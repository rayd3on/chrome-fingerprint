package main

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
)

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
