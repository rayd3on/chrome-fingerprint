package main

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type recorder struct {
	outMu      sync.Mutex
	outFile    *os.File
	logger     *log.Logger
	verbose    bool
	caCert     *x509.Certificate
	caKey      *ecdsa.PrivateKey
	certMu     sync.Mutex
	certCache  map[string]*tls.Certificate
	httpClient *http.Client
	h2Pool     *h2UpstreamPool
}

func newRecorder(outputPath string, verbose bool, caCertPath, caKeyPath string) (*recorder, error) {
	if err := os.MkdirAll(filepath.Dir(outputPath), 0o755); err != nil {
		return nil, fmt.Errorf("create output dir: %w", err)
	}

	outFile, err := os.Create(outputPath)
	if err != nil {
		return nil, fmt.Errorf("create output file: %w", err)
	}

	var (
		caCert *x509.Certificate
		caKey  *ecdsa.PrivateKey
	)
	if caCertPath != "" && caKeyPath != "" {
		caCert, caKey, err = loadOrCreateCA(caCertPath, caKeyPath)
		if err != nil {
			outFile.Close()
			return nil, fmt.Errorf("load persistent CA: %w", err)
		}
	} else {
		caCert, caKey, err = generateCA()
		if err != nil {
			outFile.Close()
			return nil, fmt.Errorf("generate CA: %w", err)
		}
	}

	logger := log.New(os.Stdout, "header-recorder: ", 0)
	return &recorder{
		outFile:   outFile,
		logger:    logger,
		verbose:   verbose,
		caCert:    caCert,
		caKey:     caKey,
		certCache: map[string]*tls.Certificate{},
		httpClient: &http.Client{
			Transport: newChromeRoundTripper(),
			Timeout:   30 * time.Second,
		},
		h2Pool: newH2UpstreamPool(),
	}, nil
}

func (r *recorder) close() {
	if r.outFile != nil {
		_ = r.outFile.Close()
	}
}

func (r *recorder) serve(ctx context.Context, listenAddr string) error {
	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", listenAddr, err)
	}
	defer listener.Close()

	r.logger.Printf("listening on %s", listener.Addr().String())

	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if errors.Is(err, net.ErrClosed) {
				return err
			}
			r.logf("accept error: %v", err)
			continue
		}

		go func() {
			defer conn.Close()
			if err := r.handleProxyConn(conn); err != nil && !isExpectedClose(err) {
				r.logf("connection error: %v", err)
			}
		}()
	}
}

func (r *recorder) handleProxyConn(conn net.Conn) error {
	reader := bufio.NewReader(conn)
	for {
		rawReq, err := readRawRequest(reader)
		if err != nil {
			return err
		}

		if strings.EqualFold(rawReq.method, http.MethodConnect) {
			return r.handleConnect(conn, reader, rawReq)
		}

		if err := r.handleHTTPRequest(conn, reader, rawReq, "", ""); err != nil {
			if errors.Is(err, errCloseClientConnection) {
				return nil
			}
			return err
		}
	}
}

func (r *recorder) handleConnect(conn net.Conn, reader *bufio.Reader, connectReq *rawRequest) error {
	targetAuthority := normalizeAuthority(connectReq.target, "443")
	if _, err := io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return err
	}

	serverName := authorityHost(targetAuthority)
	cert, err := r.leafCertificate(serverName)
	if err != nil {
		return fmt.Errorf("create leaf cert for %s: %w", serverName, err)
	}

	tlsConn := tls.Server(&bufferedConn{Conn: conn, reader: reader}, &tls.Config{
		Certificates: []tls.Certificate{*cert},
		NextProtos:   []string{"h2", "http/1.1"},
		MinVersion:   tls.VersionTLS12,
	})
	defer tlsConn.Close()

	if err := tlsConn.Handshake(); err != nil {
		return err
	}

	alpn := tlsConn.ConnectionState().NegotiatedProtocol
	if alpn == "h2" {
		return r.handleH2Connection(tlsConn, targetAuthority)
	}

	tlsReader := bufio.NewReader(tlsConn)
	for {
		rawReq, err := readRawRequest(tlsReader)
		if err != nil {
			return err
		}
		if err := r.handleHTTPRequest(tlsConn, tlsReader, rawReq, "https", targetAuthority, alpn); err != nil {
			if errors.Is(err, errCloseClientConnection) {
				return nil
			}
			return err
		}
	}
}

func (r *recorder) handleHTTPRequest(writer io.Writer, reader *bufio.Reader, rawReq *rawRequest, defaultScheme, defaultAuthority string, browserALPN ...string) error {
	req, err := parseHTTPRequest(rawReq.raw, reader)
	if err != nil {
		return fmt.Errorf("parse request: %w", err)
	}
	defer req.Body.Close()

	scheme, authority, requestURL, err := normalizeUpstreamURL(req, rawReq, defaultScheme, defaultAuthority)
	if err != nil {
		return fmt.Errorf("normalize request URL: %w", err)
	}

	req.URL = requestURL
	req.RequestURI = ""
	req.Close = true
	if req.Host == "" {
		req.Host = authority
	}
	req.Header.Del("Proxy-Connection")
	req.Header.Del("Proxy-Authorization")
	req.Header.Del("Connection")

	rec := recordedRequest{
		Timestamp:   time.Now().UTC().Format(time.RFC3339Nano),
		URL:         requestURL.String(),
		Method:      rawReq.method,
		Path:        requestURL.RequestURI(),
		Host:        requestURL.Hostname(),
		Scheme:      scheme,
		HTTPVersion: rawReq.proto,
		HeaderOrder: headerOrder(rawReq.headers),
		Headers:     rawReq.headers,
	}
	if len(browserALPN) > 0 && browserALPN[0] != "" {
		rec.BrowserALPN = browserALPN[0]
	}
	if err := r.writeRecord(rec); err != nil {
		return fmt.Errorf("write record: %w", err)
	}

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return writeProxyError(writer, http.StatusBadGateway, fmt.Sprintf("upstream request failed: %v", err))
	}
	defer resp.Body.Close()

	resp.Header.Del("Proxy-Connection")
	resp.Header.Del("Keep-Alive")
	resp.Header.Set("Connection", "close")
	resp.Close = true
	if err := resp.Write(writer); err != nil {
		return err
	}
	return errCloseClientConnection
}

func (r *recorder) writeRecord(record recordedRequest) error {
	line, err := json.Marshal(record)
	if err != nil {
		return err
	}

	r.outMu.Lock()
	defer r.outMu.Unlock()
	if _, err := r.outFile.Write(append(line, '\n')); err != nil {
		return err
	}
	return r.outFile.Sync()
}

func (r *recorder) logf(format string, args ...any) {
	if r.verbose {
		r.logger.Printf(format, args...)
	}
}
