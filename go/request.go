package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
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

func (c *bufferedConn) Read(p []byte) (int, error) {
	return c.reader.Read(p)
}

var errCloseClientConnection = errors.New("close client connection")

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

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}
