package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

type headerPair struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type recordedRequest struct {
	Timestamp         string       `json:"timestamp"`
	URL               string       `json:"url"`
	Method            string       `json:"method"`
	Path              string       `json:"path"`
	Host              string       `json:"host"`
	Scheme            string       `json:"scheme"`
	HTTPVersion       string       `json:"httpVersion"`
	BrowserALPN       string       `json:"browserALPN,omitempty"`
	PseudoHeaderOrder []string     `json:"pseudoHeaderOrder,omitempty"`
	HeaderOrder       []string     `json:"headerOrder"`
	Headers           []headerPair `json:"headers"`
}

type rawRequest struct {
	raw     []byte
	method  string
	target  string
	proto   string
	headers []headerPair
}

type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

var errCloseClientConnection = errors.New("close client connection")

// chromeRoundTripper makes outbound HTTPS connections using utls with a
// Chrome TLS fingerprint so the upstream sees the same TLS shape Chrome
// would have presented directly, instead of Go's default crypto/tls
// ClientHello, which would change the response we hand back to Chrome and
// poison the capture.
type chromeRoundTripper struct {
	mu      sync.Mutex
	h2Conns map[string]*http2.ClientConn
}

func newChromeRoundTripper() *chromeRoundTripper {
	return &chromeRoundTripper{h2Conns: make(map[string]*http2.ClientConn)}
}

func (rt *chromeRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Scheme != "https" {
		return http.DefaultTransport.RoundTrip(req)
	}

	addr := req.URL.Host
	if _, _, err := net.SplitHostPort(addr); err != nil {
		addr = net.JoinHostPort(addr, "443")
	}
	host, _, _ := net.SplitHostPort(addr)

	rt.mu.Lock()
	cc := rt.h2Conns[host]
	rt.mu.Unlock()
	if cc != nil {
		resp, err := cc.RoundTrip(req)
		if err == nil {
			return resp, nil
		}
		rt.mu.Lock()
		delete(rt.h2Conns, host)
		rt.mu.Unlock()
	}

	rawConn, err := net.DialTimeout("tcp", addr, 15*time.Second)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", addr, err)
	}

	uConn := utls.UClient(rawConn, &utls.Config{ServerName: host}, utls.HelloChrome_Auto)
	if err := uConn.Handshake(); err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("utls handshake %s: %w", addr, err)
	}

	alpn := uConn.ConnectionState().NegotiatedProtocol
	if alpn == "h2" {
		h2t := &http2.Transport{
			DisableCompression: true,
		}
		h2cc, err := h2t.NewClientConn(uConn)
		if err != nil {
			uConn.Close()
			return nil, fmt.Errorf("h2 client conn %s: %w", addr, err)
		}
		rt.mu.Lock()
		rt.h2Conns[host] = h2cc
		rt.mu.Unlock()
		return h2cc.RoundTrip(req)
	}

	if err := req.Write(uConn); err != nil {
		uConn.Close()
		return nil, fmt.Errorf("write request %s: %w", addr, err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(uConn), req)
	if err != nil {
		uConn.Close()
		return nil, fmt.Errorf("read response %s: %w", addr, err)
	}
	resp.Body = &connClosingBody{ReadCloser: resp.Body, conn: uConn}
	return resp, nil
}

type connClosingBody struct {
	io.ReadCloser
	conn net.Conn
}

func (b *connClosingBody) Close() error {
	err := b.ReadCloser.Close()
	b.conn.Close()
	return err
}

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

func main() {
	var (
		listenAddr = flag.String("listen", "127.0.0.1:8899", "proxy listen address")
		outputPath = flag.String("out", filepath.Join(os.TempDir(), fmt.Sprintf("header-recorder-%d.jsonl", time.Now().UnixNano())), "JSONL output path")
		caCertPath = flag.String("ca-cert", "", "path to a persistent root CA certificate PEM")
		caKeyPath  = flag.String("ca-key", "", "path to a persistent root CA private key PEM")
		verbose    = flag.Bool("verbose", false, "enable verbose logs")
	)
	flag.Parse()

	rec, err := newRecorder(*outputPath, *verbose, *caCertPath, *caKeyPath)
	if err != nil {
		log.Fatalf("init recorder: %v", err)
	}
	defer rec.close()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if err := rec.serve(ctx, *listenAddr); err != nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, context.Canceled) {
		log.Fatalf("serve recorder: %v", err)
	}
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

// When Chrome negotiates h2 via ALPN, we handle raw HTTP/2 frames with
// golang.org/x/net/http2.Framer + hpack.Decoder. ReadMetaHeaders auto-merges
// HEADERS + CONTINUATION frames and HPACK-decodes them, returning
// []hpack.HeaderField in exact wire emission order -that's what lets us
// record header order faithfully.

type h2StreamState struct {
	streamID    uint32
	method      string
	authority   string
	scheme      string
	path        string
	pseudoOrder []string     // e.g. [":method", ":authority", ":scheme", ":path"]
	headers     []headerPair // regular headers in wire order
	bodyBuf     bytes.Buffer
}

type h2ClientSettings struct {
	mu               sync.RWMutex
	settings         []http2.Setting
	connWindowUpdate uint32
}

func (s *h2ClientSettings) setSettings(settings []http2.Setting) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.settings = append([]http2.Setting(nil), settings...)
}

func (s *h2ClientSettings) addConnWindowUpdate(increment uint32) {
	if increment == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.connWindowUpdate += increment
}

func (s *h2ClientSettings) snapshot() ([]http2.Setting, uint32) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]http2.Setting(nil), s.settings...), s.connWindowUpdate
}

// Pools one HTTP/2 connection per upstream host so consecutive requests
// multiplex with incrementing stream IDs, like real Chrome. A background
// reader goroutine dispatches response frames to per-stream channels.

type h2FrameEvent struct {
	meta      *http2.MetaHeadersFrame
	data      []byte
	endStream bool
	resetCode http2.ErrCode
	err       error
}

type h2UpstreamConn struct {
	writeMu    sync.Mutex                   // serialises all framer writes
	streamsMu  sync.Mutex                   // protects streams map
	conn       net.Conn                     // utls connection
	framer     *http2.Framer                // shared framer
	encoder    *hpack.Encoder               // HPACK encoder (per-connection state)
	encoderBuf bytes.Buffer                 // backing buffer for encoder
	nextStream uint32                       // next client stream ID (1, 3, 5, ...)
	streams    map[uint32]chan h2FrameEvent // per-stream response channels
	dead       chan struct{}                // closed when connection dies
	deadOnce   sync.Once
	deadErr    error
}

type h2UpstreamPool struct {
	mu    sync.Mutex
	conns map[string]*h2UpstreamConn
}

func newH2UpstreamPool() *h2UpstreamPool {
	return &h2UpstreamPool{conns: make(map[string]*h2UpstreamConn)}
}

func (p *h2UpstreamPool) get(host string) *h2UpstreamConn {
	p.mu.Lock()
	defer p.mu.Unlock()
	uc := p.conns[host]
	if uc != nil {
		select {
		case <-uc.dead:
			delete(p.conns, host)
			return nil
		default:
			return uc
		}
	}
	return nil
}

func (p *h2UpstreamPool) put(host string, uc *h2UpstreamConn) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if existing := p.conns[host]; existing != nil {
		select {
		case <-existing.dead:
			p.conns[host] = uc
		default:
			uc.markDead(errors.New("superseded"))
			uc.conn.Close()
		}
		return
	}
	p.conns[host] = uc
}

func (p *h2UpstreamPool) evict(host string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if uc := p.conns[host]; uc != nil {
		uc.markDead(errors.New("evicted"))
		uc.conn.Close()
		delete(p.conns, host)
	}
}

func (uc *h2UpstreamConn) markDead(err error) {
	uc.deadOnce.Do(func() {
		uc.deadErr = err
		close(uc.dead)
		uc.streamsMu.Lock()
		for id, ch := range uc.streams {
			select {
			case ch <- h2FrameEvent{err: err}:
			default:
			}
			close(ch)
			delete(uc.streams, id)
		}
		uc.streamsMu.Unlock()
	})
}

func (uc *h2UpstreamConn) isDead() bool {
	select {
	case <-uc.dead:
		return true
	default:
		return false
	}
}

func (uc *h2UpstreamConn) readLoop() {
	defer uc.conn.Close()
	for {
		frame, err := uc.framer.ReadFrame()
		if err != nil {
			uc.markDead(err)
			return
		}

		switch f := frame.(type) {
		case *http2.MetaHeadersFrame:
			uc.dispatchToStream(f.StreamID, h2FrameEvent{
				meta:      f,
				endStream: f.StreamEnded(),
			})

		case *http2.DataFrame:
			data := make([]byte, len(f.Data()))
			copy(data, f.Data())
			n := uint32(len(f.Data()))
			if n > 0 {
				uc.writeMu.Lock()
				_ = uc.framer.WriteWindowUpdate(f.StreamID, n)
				_ = uc.framer.WriteWindowUpdate(0, n)
				uc.writeMu.Unlock()
			}
			uc.dispatchToStream(f.StreamID, h2FrameEvent{
				data:      data,
				endStream: f.StreamEnded(),
			})

		case *http2.SettingsFrame:
			if !f.IsAck() {
				uc.writeMu.Lock()
				_ = uc.framer.WriteSettingsAck()
				uc.writeMu.Unlock()
			}

		case *http2.PingFrame:
			if !f.IsAck() {
				uc.writeMu.Lock()
				_ = uc.framer.WritePing(true, f.Data)
				uc.writeMu.Unlock()
			}

		case *http2.RSTStreamFrame:
			uc.dispatchToStream(f.StreamID, h2FrameEvent{
				resetCode: f.ErrCode,
				err:       fmt.Errorf("upstream RST_STREAM: %s", f.ErrCode),
			})

		case *http2.GoAwayFrame:
			uc.markDead(fmt.Errorf("upstream GOAWAY: %s", f.ErrCode))
			return

		case *http2.WindowUpdateFrame:
		case *http2.PriorityFrame:
		}
	}
}

func (uc *h2UpstreamConn) dispatchToStream(streamID uint32, event h2FrameEvent) {
	uc.streamsMu.Lock()
	ch := uc.streams[streamID]
	uc.streamsMu.Unlock()
	if ch == nil {
		return
	}
	select {
	case ch <- event:
	case <-uc.dead:
	}
	if event.endStream || event.err != nil {
		uc.streamsMu.Lock()
		delete(uc.streams, streamID)
		uc.streamsMu.Unlock()
	}
}

func (uc *h2UpstreamConn) sendRequest(stream *h2StreamState, scheme, authority string) (uint32, chan h2FrameEvent, error) {
	if uc.isDead() {
		return 0, nil, fmt.Errorf("connection is dead: %v", uc.deadErr)
	}

	uc.writeMu.Lock()
	defer uc.writeMu.Unlock()

	streamID := uc.nextStream
	uc.nextStream += 2

	uc.encoderBuf.Reset()
	pseudoValues := map[string]string{
		":method":    stream.method,
		":authority": authority,
		":scheme":    scheme,
		":path":      stream.path,
	}
	for _, name := range stream.pseudoOrder {
		value := pseudoValues[name]
		if value == "" {
			continue
		}
		if err := uc.encoder.WriteField(hpack.HeaderField{Name: name, Value: value}); err != nil {
			uc.markDead(fmt.Errorf("encode pseudo header %s: %w", name, err))
			return 0, nil, err
		}
	}
	for _, header := range stream.headers {
		if err := uc.encoder.WriteField(hpack.HeaderField{Name: header.Name, Value: header.Value}); err != nil {
			uc.markDead(fmt.Errorf("encode header %s: %w", header.Name, err))
			return 0, nil, err
		}
	}

	// Register stream channel before sending so readLoop can dispatch to it.
	ch := make(chan h2FrameEvent, 16)
	uc.streamsMu.Lock()
	uc.streams[streamID] = ch
	uc.streamsMu.Unlock()

	endStream := stream.bodyBuf.Len() == 0
	if err := writeH2HeaderBlock(uc.framer, streamID, uc.encoderBuf.Bytes(), endStream); err != nil {
		uc.markDead(err)
		return 0, nil, err
	}

	if !endStream {
		if err := writeH2DataFrames(uc.framer, streamID, stream.bodyBuf.Bytes()); err != nil {
			uc.markDead(err)
			return 0, nil, err
		}
	}

	return streamID, ch, nil
}

// Don't be tempted to buffer the whole body here before returning. The
// upstream sees big idle gaps between frames and that shifts the pacing
// enough for timing-sensitive sensor scripts on the page to flag the
// session. The io.Pipe below streams frames out as they arrive.
func waitPooledH2Response(ch chan h2FrameEvent, method string) (*http.Response, error) {
	statusCode := 0
	header := make(http.Header)

	for {
		event, ok := <-ch
		if !ok {
			if statusCode != 0 {
				return buildH2Response(statusCode, header, nil, method), nil
			}
			return nil, errors.New("upstream connection closed without response")
		}

		if event.err != nil {
			return nil, event.err
		}
		if event.resetCode != 0 {
			return nil, fmt.Errorf("upstream reset stream: %s", event.resetCode)
		}
		if event.meta != nil {
			code := 0
			nextHeader := make(http.Header)
			for _, field := range event.meta.Fields {
				if field.IsPseudo() {
					if field.Name == ":status" {
						code, _ = strconv.Atoi(field.Value)
					}
					continue
				}
				nextHeader.Add(field.Name, field.Value)
			}
			if code >= 100 && code < 200 && code != http.StatusSwitchingProtocols {
				continue
			}
			if code != 0 {
				statusCode = code
				header = nextHeader
			}
		}

		if statusCode == 0 {
			if event.endStream {
				return nil, errors.New("upstream stream ended without :status")
			}
			continue
		}

		if event.endStream && len(event.data) == 0 {
			return buildH2Response(statusCode, header, nil, method), nil
		}

		pipeReader, pipeWriter := io.Pipe()
		go streamPooledH2Body(event, ch, pipeWriter)
		return &http.Response{
			StatusCode: statusCode,
			Status:     fmt.Sprintf("%d %s", statusCode, http.StatusText(statusCode)),
			Proto:      "HTTP/2.0",
			ProtoMajor: 2,
			ProtoMinor: 0,
			Header:     header,
			Body:       pipeReader,
			Request: &http.Request{
				Method: method,
			},
		}, nil
	}
}

func streamPooledH2Body(firstEvent h2FrameEvent, ch chan h2FrameEvent, writer *io.PipeWriter) {
	defer writer.Close()

	event := firstEvent
	for {
		if event.err != nil {
			_ = writer.CloseWithError(event.err)
			return
		}
		if event.resetCode != 0 {
			_ = writer.CloseWithError(fmt.Errorf("upstream reset stream: %s", event.resetCode))
			return
		}

		if len(event.data) > 0 {
			if _, err := writer.Write(event.data); err != nil {
				return
			}
		}

		if event.endStream {
			return
		}

		next, ok := <-ch
		if !ok {
			_ = writer.CloseWithError(io.EOF)
			return
		}
		event = next
	}
}

func (r *recorder) handleH2Connection(tlsConn *tls.Conn, targetAuthority string) error {
	preface := make([]byte, len(http2.ClientPreface))
	if _, err := io.ReadFull(tlsConn, preface); err != nil {
		return fmt.Errorf("read h2 client preface: %w", err)
	}
	if string(preface) != http2.ClientPreface {
		return fmt.Errorf("invalid h2 client preface")
	}

	framer := http2.NewFramer(tlsConn, tlsConn)
	framer.MaxHeaderListSize = 1 << 20
	framer.ReadMetaHeaders = hpack.NewDecoder(4096, nil)

	if err := framer.WriteSettings(
		http2.Setting{ID: http2.SettingEnablePush, Val: 0},
		http2.Setting{ID: http2.SettingMaxConcurrentStreams, Val: 250},
		http2.Setting{ID: http2.SettingInitialWindowSize, Val: 1 << 20},
	); err != nil {
		return fmt.Errorf("write server settings: %w", err)
	}

	// Grant an extra (1MB - 65535) bytes on top of the default H2 window so
	// Chrome can send freely without waiting for WINDOW_UPDATEs.
	const defaultH2WindowSize = 65535
	if err := framer.WriteWindowUpdate(0, (1<<20)-defaultH2WindowSize); err != nil {
		return fmt.Errorf("write conn window update: %w", err)
	}

	clientSettings := &h2ClientSettings{}
	frame, err := framer.ReadFrame()
	if err != nil {
		return fmt.Errorf("read client settings: %w", err)
	}
	if sf, ok := frame.(*http2.SettingsFrame); ok && !sf.IsAck() {
		var settings []http2.Setting
		_ = sf.ForeachSetting(func(setting http2.Setting) error {
			settings = append(settings, setting)
			return nil
		})
		clientSettings.setSettings(settings)
		if err := framer.WriteSettingsAck(); err != nil {
			return fmt.Errorf("write settings ack: %w", err)
		}
	}

	streams := map[uint32]*h2StreamState{}
	var writeMu sync.Mutex
	hpackBuf := new(bytes.Buffer)
	hpackEnc := hpack.NewEncoder(hpackBuf)

	for {
		frame, err := framer.ReadFrame()
		if err != nil {
			if err == io.EOF || isExpectedClose(err) {
				return nil
			}
			return fmt.Errorf("read h2 frame: %w", err)
		}

		switch f := frame.(type) {
		case *http2.MetaHeadersFrame:
			stream := &h2StreamState{streamID: f.StreamID}
			for _, hf := range f.Fields {
				if hf.IsPseudo() {
					stream.pseudoOrder = append(stream.pseudoOrder, hf.Name)
					switch hf.Name {
					case ":method":
						stream.method = hf.Value
					case ":authority":
						stream.authority = hf.Value
					case ":scheme":
						stream.scheme = hf.Value
					case ":path":
						stream.path = hf.Value
					}
				} else {
					stream.headers = append(stream.headers, headerPair{
						Name:  hf.Name,
						Value: hf.Value,
					})
				}
			}
			streams[f.StreamID] = stream

			if f.StreamEnded() {
				go r.dispatchH2Request(framer, &writeMu, hpackEnc, hpackBuf, stream, targetAuthority, clientSettings)
				delete(streams, f.StreamID)
			}

		case *http2.DataFrame:
			stream := streams[f.StreamID]
			if stream == nil {
				writeMu.Lock()
				_ = framer.WriteRSTStream(f.StreamID, http2.ErrCodeStreamClosed)
				writeMu.Unlock()
				continue
			}
			stream.bodyBuf.Write(f.Data())

			// Replenish the flow-control window so Chrome can keep sending.
			n := uint32(len(f.Data()))
			if n > 0 {
				writeMu.Lock()
				_ = framer.WriteWindowUpdate(f.StreamID, n)
				_ = framer.WriteWindowUpdate(0, n)
				writeMu.Unlock()
			}

			if f.StreamEnded() {
				go r.dispatchH2Request(framer, &writeMu, hpackEnc, hpackBuf, stream, targetAuthority, clientSettings)
				delete(streams, f.StreamID)
			}

		case *http2.SettingsFrame:
			if !f.IsAck() {
				writeMu.Lock()
				_ = framer.WriteSettingsAck()
				writeMu.Unlock()
			}

		case *http2.PingFrame:
			if !f.IsAck() {
				writeMu.Lock()
				_ = framer.WritePing(true, f.Data)
				writeMu.Unlock()
			}

		case *http2.WindowUpdateFrame:
			if f.StreamID == 0 {
				clientSettings.addConnWindowUpdate(f.Increment)
			}

		case *http2.GoAwayFrame:
			return nil

		case *http2.RSTStreamFrame:
			delete(streams, f.StreamID)

		case *http2.PriorityFrame:
		}
	}
}

func (r *recorder) dispatchH2Request(
	framer *http2.Framer,
	writeMu *sync.Mutex,
	hpackEnc *hpack.Encoder,
	hpackBuf *bytes.Buffer,
	stream *h2StreamState,
	targetAuthority string,
	clientSettings *h2ClientSettings,
) {
	scheme, authority, reqURL := upstreamRequestURL(stream, targetAuthority)

	rec := recordedRequest{
		Timestamp:         time.Now().UTC().Format(time.RFC3339Nano),
		URL:               reqURL,
		Method:            stream.method,
		Path:              stream.path,
		Host:              authorityHost(authority),
		Scheme:            scheme,
		HTTPVersion:       "h2",
		BrowserALPN:       "h2",
		PseudoHeaderOrder: stream.pseudoOrder,
		HeaderOrder:       headerOrder(stream.headers),
		Headers:           stream.headers,
	}
	if err := r.writeRecord(rec); err != nil {
		r.logf("write record: %v", err)
	}

	// Forward upstream preserving exact header order when the origin speaks
	// HTTP/2, so the upstream sees the same on-wire serialization Chrome
	// would have sent; fall back to Go's stdlib http.Client (which reorders)
	// only if that fails.
	resp, err := r.forwardExactH2Request(stream, targetAuthority, clientSettings)
	if err != nil {
		resp, err = r.forwardRecordedRequest(stream, targetAuthority)
	}
	if err != nil {
		r.logf("upstream request: %v", err)
		r.writeH2ResetStream(framer, writeMu, stream.streamID, http2.ErrCodeInternal)
		return
	}
	defer resp.Body.Close()

	r.writeH2Response(framer, writeMu, hpackEnc, hpackBuf, stream.streamID, resp)
}

func upstreamRequestURL(stream *h2StreamState, targetAuthority string) (scheme, authority, reqURL string) {
	scheme = stream.scheme
	if scheme == "" {
		scheme = "https"
	}
	authority = stream.authority
	if authority == "" {
		authority = targetAuthority
	}
	reqURL = fmt.Sprintf("%s://%s%s", scheme, authority, stream.path)
	return scheme, authority, reqURL
}

func (r *recorder) forwardRecordedRequest(stream *h2StreamState, targetAuthority string) (*http.Response, error) {
	_, _, reqURL := upstreamRequestURL(stream, targetAuthority)

	var body io.Reader
	if stream.bodyBuf.Len() > 0 {
		body = bytes.NewReader(stream.bodyBuf.Bytes())
	}
	httpReq, err := http.NewRequest(stream.method, reqURL, body)
	if err != nil {
		return nil, fmt.Errorf("build upstream request: %w", err)
	}
	for _, h := range stream.headers {
		httpReq.Header.Add(h.Name, h.Value)
	}
	return r.httpClient.Do(httpReq)
}

func defaultBrowserH2Settings() []http2.Setting {
	return []http2.Setting{
		{ID: http2.SettingHeaderTableSize, Val: 65536},
		{ID: http2.SettingEnablePush, Val: 0},
		{ID: http2.SettingInitialWindowSize, Val: 6291456},
		{ID: http2.SettingMaxHeaderListSize, Val: 262144},
	}
}

func (r *recorder) dialChromeTLS(authority string) (*utls.UConn, string, error) {
	addr := normalizeAuthority(authority, "443")
	host := authorityHost(addr)

	rawConn, err := net.DialTimeout("tcp", addr, 15*time.Second)
	if err != nil {
		return nil, "", fmt.Errorf("dial %s: %w", addr, err)
	}

	uConn := utls.UClient(rawConn, &utls.Config{ServerName: host}, utls.HelloChrome_Auto)
	if err := uConn.Handshake(); err != nil {
		rawConn.Close()
		return nil, "", fmt.Errorf("utls handshake %s: %w", addr, err)
	}
	return uConn, uConn.ConnectionState().NegotiatedProtocol, nil
}

func (r *recorder) forwardExactH2Request(stream *h2StreamState, targetAuthority string, clientSettings *h2ClientSettings) (*http.Response, error) {
	scheme, authority, _ := upstreamRequestURL(stream, targetAuthority)
	if scheme != "https" {
		return nil, fmt.Errorf("exact h2 forwarding only supports https, got %s", scheme)
	}
	host := authorityHost(authority)

	uc := r.h2Pool.get(host)
	if uc != nil {
		_, ch, sendErr := uc.sendRequest(stream, scheme, authority)
		if sendErr == nil {
			resp, waitErr := waitPooledH2Response(ch, stream.method)
			if waitErr == nil {
				return resp, nil
			}
			r.logf("pooled h2 response error for %s: %v", host, waitErr)
		} else {
			r.logf("pooled h2 send error for %s: %v", host, sendErr)
		}
		r.h2Pool.evict(host)
	}

	uc, dialErr := r.dialPooledH2(authority, clientSettings)
	if dialErr != nil {
		return nil, fmt.Errorf("h2 pool dial %s: %w", host, dialErr)
	}
	r.h2Pool.put(host, uc)
	_, ch, sendErr := uc.sendRequest(stream, scheme, authority)
	if sendErr != nil {
		r.h2Pool.evict(host)
		return nil, fmt.Errorf("h2 pool send %s: %w", host, sendErr)
	}
	resp, waitErr := waitPooledH2Response(ch, stream.method)
	if waitErr != nil {
		r.h2Pool.evict(host)
		return nil, fmt.Errorf("h2 pool response %s: %w", host, waitErr)
	}
	return resp, nil
}

func (r *recorder) dialPooledH2(authority string, clientSettings *h2ClientSettings) (*h2UpstreamConn, error) {
	uConn, alpn, err := r.dialChromeTLS(authority)
	if err != nil {
		return nil, err
	}
	if alpn != "h2" {
		uConn.Close()
		return nil, fmt.Errorf("origin negotiated %s instead of h2", alpn)
	}

	if _, err := io.WriteString(uConn, http2.ClientPreface); err != nil {
		uConn.Close()
		return nil, fmt.Errorf("write h2 client preface: %w", err)
	}

	framer := http2.NewFramer(uConn, uConn)
	framer.MaxHeaderListSize = 1 << 20
	framer.ReadMetaHeaders = hpack.NewDecoder(4096, nil)

	settings, connWindowUpdate := clientSettings.snapshot()
	if len(settings) == 0 {
		settings = defaultBrowserH2Settings()
	}
	if err := framer.WriteSettings(settings...); err != nil {
		uConn.Close()
		return nil, fmt.Errorf("write upstream settings: %w", err)
	}
	if connWindowUpdate > 0 {
		if err := framer.WriteWindowUpdate(0, connWindowUpdate); err != nil {
			uConn.Close()
			return nil, fmt.Errorf("write upstream conn window update: %w", err)
		}
	}

	sawServerSettings := false
	for !sawServerSettings {
		frame, err := framer.ReadFrame()
		if err != nil {
			uConn.Close()
			return nil, fmt.Errorf("read upstream preface frame: %w", err)
		}
		switch f := frame.(type) {
		case *http2.SettingsFrame:
			if !f.IsAck() {
				if err := framer.WriteSettingsAck(); err != nil {
					uConn.Close()
					return nil, fmt.Errorf("ack upstream settings: %w", err)
				}
				sawServerSettings = true
			}
		case *http2.PingFrame:
			if !f.IsAck() {
				if err := framer.WritePing(true, f.Data); err != nil {
					uConn.Close()
					return nil, fmt.Errorf("ack upstream ping: %w", err)
				}
			}
		}
	}

	uc := &h2UpstreamConn{
		conn:       uConn,
		framer:     framer,
		nextStream: 1,
		streams:    make(map[uint32]chan h2FrameEvent),
		dead:       make(chan struct{}),
	}
	uc.encoder = hpack.NewEncoder(&uc.encoderBuf)

	go uc.readLoop()
	return uc, nil
}

func writeH2HeaderBlock(framer *http2.Framer, streamID uint32, block []byte, endStream bool) error {
	const maxFramePayload = 16384
	first := true
	for {
		chunk := block
		if len(chunk) > maxFramePayload {
			chunk = block[:maxFramePayload]
		}
		block = block[len(chunk):]
		endHeaders := len(block) == 0

		if first {
			if err := framer.WriteHeaders(http2.HeadersFrameParam{
				StreamID:      streamID,
				BlockFragment: chunk,
				EndHeaders:    endHeaders,
				EndStream:     endStream && endHeaders,
			}); err != nil {
				return fmt.Errorf("write upstream headers: %w", err)
			}
			first = false
		} else {
			if err := framer.WriteContinuation(streamID, endHeaders, chunk); err != nil {
				return fmt.Errorf("write upstream continuation: %w", err)
			}
		}
		if endHeaders {
			return nil
		}
	}
}

func writeH2DataFrames(framer *http2.Framer, streamID uint32, body []byte) error {
	const maxFramePayload = 16384
	for len(body) > 0 {
		chunk := body
		if len(chunk) > maxFramePayload {
			chunk = body[:maxFramePayload]
		}
		body = body[len(chunk):]
		if err := framer.WriteData(streamID, len(body) == 0, chunk); err != nil {
			return fmt.Errorf("write upstream data: %w", err)
		}
	}
	return nil
}

func buildH2Response(statusCode int, header http.Header, body []byte, method string) *http.Response {
	if statusCode == 0 {
		statusCode = http.StatusBadGateway
	}
	if header == nil {
		header = make(http.Header)
	}
	return &http.Response{
		StatusCode:    statusCode,
		Status:        fmt.Sprintf("%d %s", statusCode, http.StatusText(statusCode)),
		Proto:         "HTTP/2.0",
		ProtoMajor:    2,
		ProtoMinor:    0,
		Header:        header,
		Body:          io.NopCloser(bytes.NewReader(body)),
		ContentLength: int64(len(body)),
		Request: &http.Request{
			Method: method,
		},
	}
}

func (r *recorder) writeH2Response(
	framer *http2.Framer,
	writeMu *sync.Mutex,
	hpackEnc *hpack.Encoder,
	hpackBuf *bytes.Buffer,
	streamID uint32,
	resp *http.Response,
) {
	const maxFramePayload = 16384

	writeMu.Lock()
	hpackBuf.Reset()
	hpackEnc.WriteField(hpack.HeaderField{Name: ":status", Value: strconv.Itoa(resp.StatusCode)})
	for key, values := range resp.Header {
		lk := strings.ToLower(key)
		if lk == "connection" || lk == "keep-alive" || lk == "transfer-encoding" || lk == "upgrade" {
			continue
		}
		for _, val := range values {
			hpackEnc.WriteField(hpack.HeaderField{Name: lk, Value: val})
		}
	}

	block := hpackBuf.Bytes()
	first := true
	for len(block) > 0 {
		chunk := block
		if len(chunk) > maxFramePayload {
			chunk = block[:maxFramePayload]
		}
		block = block[len(chunk):]
		endHeaders := len(block) == 0

		if first {
			if err := framer.WriteHeaders(http2.HeadersFrameParam{
				StreamID:      streamID,
				BlockFragment: chunk,
				EndHeaders:    endHeaders,
				EndStream:     false,
			}); err != nil {
				writeMu.Unlock()
				return
			}
			first = false
		} else {
			if err := framer.WriteContinuation(streamID, endHeaders, chunk); err != nil {
				writeMu.Unlock()
				return
			}
		}
	}
	writeMu.Unlock()

	buf := make([]byte, maxFramePayload)
	for {
		n, readErr := resp.Body.Read(buf)
		if n > 0 {
			endStream := readErr != nil
			writeMu.Lock()
			if err := framer.WriteData(streamID, endStream, buf[:n]); err != nil {
				writeMu.Unlock()
				return
			}
			writeMu.Unlock()
			if endStream {
				return
			}
		}
		if readErr != nil {
			writeMu.Lock()
			framer.WriteData(streamID, true, nil)
			writeMu.Unlock()
			return
		}
	}
}

func (r *recorder) writeH2ResetStream(framer *http2.Framer, writeMu *sync.Mutex, streamID uint32, code http2.ErrCode) {
	writeMu.Lock()
	defer writeMu.Unlock()
	_ = framer.WriteRSTStream(streamID, code)
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

func (r *recorder) leafCertificate(host string) (*tls.Certificate, error) {
	host = authorityHost(normalizeAuthority(host, "443"))

	r.certMu.Lock()
	defer r.certMu.Unlock()
	if cert := r.certCache[host]; cert != nil {
		return cert, nil
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: host,
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(30 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{host},
	}

	if ip := net.ParseIP(host); ip != nil {
		template.DNSNames = nil
		template.IPAddresses = []net.IP{ip}
	}

	der, err := x509.CreateCertificate(rand.Reader, template, r.caCert, &priv.PublicKey, r.caKey)
	if err != nil {
		return nil, err
	}

	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: r.caCert.Raw})

	pair, err := tls.X509KeyPair(append(leafPEM, caPEM...), keyPEM)
	if err != nil {
		return nil, err
	}

	r.certCache[host] = &pair
	return &pair, nil
}

func generateCA() (*x509.Certificate, *ecdsa.PrivateKey, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "chrome-fingerprint header recorder",
			Organization: []string{"chrome-fingerprint"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(3650 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLenZero:        true,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, err
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}
	return cert, priv, nil
}

func loadOrCreateCA(certPath, keyPath string) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	if fileExists(certPath) && fileExists(keyPath) {
		return loadCA(certPath, keyPath)
	}

	cert, key, err := generateCA()
	if err != nil {
		return nil, nil, err
	}
	if err := writeCA(cert, key, certPath, keyPath); err != nil {
		return nil, nil, err
	}
	return cert, key, nil
}

func writeCA(cert *x509.Certificate, key *ecdsa.PrivateKey, certPath, keyPath string) error {
	if err := os.MkdirAll(filepath.Dir(certPath), 0o755); err != nil {
		return fmt.Errorf("create cert dir: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(keyPath), 0o700); err != nil {
		return fmt.Errorf("create key dir: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	keyBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return fmt.Errorf("marshal CA key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})

	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		return fmt.Errorf("write CA cert: %w", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return fmt.Errorf("write CA key: %w", err)
	}
	return nil
}

func loadCA(certPath, keyPath string) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, nil, fmt.Errorf("read CA cert: %w", err)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("read CA key: %w", err)
	}

	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, nil, errors.New("invalid CA cert PEM")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse CA cert: %w", err)
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, nil, errors.New("invalid CA key PEM")
	}
	var key *ecdsa.PrivateKey
	switch keyBlock.Type {
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(keyBlock.Bytes)
	case "PRIVATE KEY":
		parsed, parseErr := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
		if parseErr != nil {
			err = parseErr
			break
		}
		ecdsaKey, ok := parsed.(*ecdsa.PrivateKey)
		if !ok {
			return nil, nil, errors.New("CA key is not an ECDSA private key")
		}
		key = ecdsaKey
	default:
		err = fmt.Errorf("unsupported CA key type %q", keyBlock.Type)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("parse CA key: %w", err)
	}

	return cert, key, nil
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func readRawRequest(reader *bufio.Reader) (*rawRequest, error) {
	var raw bytes.Buffer

	requestLine, err := reader.ReadString('\n')
	if err != nil {
		return nil, err
	}
	raw.WriteString(requestLine)
	requestLine = strings.TrimRight(requestLine, "\r\n")
	parts := strings.SplitN(requestLine, " ", 3)
	if len(parts) != 3 {
		return nil, fmt.Errorf("malformed request line: %q", requestLine)
	}

	headers := make([]headerPair, 0, 16)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return nil, err
		}
		raw.WriteString(line)
		if line == "\r\n" {
			break
		}

		line = strings.TrimRight(line, "\r\n")
		idx := strings.IndexByte(line, ':')
		if idx <= 0 {
			continue
		}
		headers = append(headers, headerPair{
			Name:  strings.TrimSpace(line[:idx]),
			Value: strings.TrimSpace(line[idx+1:]),
		})
	}

	return &rawRequest{
		raw:     raw.Bytes(),
		method:  parts[0],
		target:  parts[1],
		proto:   parts[2],
		headers: headers,
	}, nil
}

func parseHTTPRequest(rawHeader []byte, reader *bufio.Reader) (*http.Request, error) {
	combo := bufio.NewReader(io.MultiReader(bytes.NewReader(rawHeader), reader))
	return http.ReadRequest(combo)
}

func normalizeUpstreamURL(req *http.Request, rawReq *rawRequest, defaultScheme, defaultAuthority string) (string, string, *url.URL, error) {
	if req.URL != nil && req.URL.IsAbs() {
		return req.URL.Scheme, req.URL.Host, req.URL, nil
	}

	scheme := defaultScheme
	if scheme == "" {
		scheme = "http"
	}

	authority := defaultAuthority
	if authority == "" {
		authority = req.Host
	}
	if authority == "" {
		for _, header := range rawReq.headers {
			if strings.EqualFold(header.Name, "Host") {
				authority = header.Value
				break
			}
		}
	}
	if authority == "" {
		return "", "", nil, errors.New("missing authority")
	}

	target := rawReq.target
	if target == "" {
		target = "/"
	}
	requestURL, err := url.Parse(fmt.Sprintf("%s://%s%s", scheme, authority, target))
	if err != nil {
		return "", "", nil, err
	}
	return scheme, authority, requestURL, nil
}

func normalizeAuthority(authority, defaultPort string) string {
	authority = strings.TrimSpace(authority)
	if authority == "" {
		return authority
	}

	if _, _, err := net.SplitHostPort(authority); err == nil {
		return authority
	}
	if strings.HasPrefix(authority, "[") && strings.Contains(authority, "]") {
		return authority
	}
	return net.JoinHostPort(authorityHost(authority), defaultPort)
}

func authorityHost(authority string) string {
	if authority == "" {
		return authority
	}
	host, _, err := net.SplitHostPort(authority)
	if err == nil {
		return host
	}
	return strings.Trim(authority, "[]")
}

func headerOrder(headers []headerPair) []string {
	names := make([]string, 0, len(headers))
	for _, header := range headers {
		names = append(names, strings.ToLower(header.Name))
	}
	return names
}

func writeProxyError(writer io.Writer, status int, message string) error {
	resp := &http.Response{
		StatusCode:    status,
		Status:        fmt.Sprintf("%d %s", status, http.StatusText(status)),
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		ContentLength: int64(len(message)),
		Header:        make(http.Header),
		Body:          io.NopCloser(strings.NewReader(message)),
	}
	resp.Header.Set("Content-Type", "text/plain; charset=utf-8")
	return resp.Write(writer)
}

func isExpectedClose(err error) bool {
	return errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed)
}

func (c *bufferedConn) Read(p []byte) (int, error) {
	return c.reader.Read(p)
}
