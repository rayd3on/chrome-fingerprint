# chrome-fingerprint

Records what a real Chrome session actually puts on the wire - TLS ClientHello, HTTP/2 SETTINGS, and the order of every header - and dumps it to a JSON file you can diff or feed into other tools.

It does this in two passes:

1. `tshark` sniffs `tcp port 443` and decrypts TLS using `SSLKEYLOGFILE`. That's where TLS / JA3 / HTTP/2 SETTINGS come from.
2. A small Go MITM proxy sits in front of Chrome and reads HPACK frames directly, so it sees every request header in the exact order Chrome sent it.

Output goes to `profiles/chrome-{version}-{timestamp}.json`.

## What ends up in the profile

- TLS cipher suites, extensions, supported groups, signature algorithms, ALPN - all in order
- JA3 string and JA3 hash
- HTTP/2 SETTINGS, the order they were sent in, and the connection-level `WINDOW_UPDATE`
- Pseudo-header order (`:method`, `:authority`, `:scheme`, `:path`)
- Per-request-type header order (document, script, xhr-get, xhr-post, image, etc.)
- The `User-Agent` and the client-hint headers Chrome currently emits

## Why bother

Servers can tell which client is talking to them long before they get to the `User-Agent`. Two layers leak it:

**TLS.** The first thing your client sends is a ClientHello. It lists the cipher suites it supports, then the TLS extensions, then supported groups, signature algorithms, ALPN - and the order matters. Each TLS stack picks a different order. Python `requests` (OpenSSL) looks one way, Node `axios` another, Go's `crypto/tls` another, and Chrome (BoringSSL) something else again. JA3 / JA4 just hashes those fields. If you're trying to make a Go or Python script "look like Chrome 147", you need to know what Chrome 147 actually sends. That changes between major versions.

**Header order.** HTTP/1.1 and HTTP/2 both keep the order of headers as they go on the wire, and HTTP/2 has the four pseudo-headers on top of that. Chrome, Firefox, and Safari all pick different orders. Most HTTP libraries don't even let you control this - `requests` and `axios` send headers in whatever order you added them, the H2 layer underneath shuffles pseudo-headers around, and stuff like `priority` lands wherever the library felt like putting it. Get every header value right but the order wrong and it still doesn't match.

This tool just records the ground truth so you have something to compare against. It doesn't replay anything - the output is JSON, not a runtime.

## Why the recorder is in Go

This was the annoying part. Most tools you'd reach for to capture headers reorder them somewhere in the stack:

- **Node's `http` / `http2`** hands you `req.headers` as an object and rebuilds outgoing requests from a header map. By the time you can read it, the wire order is gone.
- **Python `mitmproxy`** keeps the original list internally, but the upstream H2 path runs through `hyperframe` / `hpack` helpers that re-sort pseudo-headers and strip hop-by-hop ones. The UI shows you the right thing; the bytes it forwards aren't the same.
- **Charles / Fiddler / etc.** display the original order in the UI, then forward through their own HTTP stack.

Go is the one place where you can sit at the right level without doing anything clever:

- `golang.org/x/net/http2.Framer` with `ReadMetaHeaders: hpack.NewDecoder(...)` reads raw `HEADERS` + `CONTINUATION` frames, glues them together, HPACK-decodes them, and gives you back a `[]hpack.HeaderField` in exact wire order. No header map in between.
- For HTTP/1.1 we read the request line and headers ourselves out of a `bufio.Reader` and write down the order before handing the buffered bytes to `http.ReadRequest` for the body.
- The outbound side uses `refraction-networking/utls` with a Chrome ClientHello. If we used Go's default `crypto/tls`, the upstream server would see a Go-shaped TLS handshake, possibly serve a different response, and we'd be recording garbage.

The proxy writes one JSON line per request to a JSONL file. The Node side reads that back and merges it into the profile.

## Requirements

- Node.js 18+
- Wireshark / tshark - https://www.wireshark.org/download.html
- Chrome or Chromium (the script will download a specific major if you don't have it)
- Go 1.25+ (for building the recorder on first run)

A few platform notes:

- **macOS / Linux** need elevated privileges for tshark capture. `sudo` works, or on Linux you can `setcap cap_net_raw,cap_net_admin+eip $(which dumpcap)` once and skip sudo afterwards.
- **Windows** doesn't need sudo because Npcap handles capture rights at install time. You do need [Npcap](https://npcap.com/) - Wireshark's installer bundles it, just tick "WinPcap API-compatible mode" during setup.
- **Linux shared libraries.** If the tool downloads Chrome for you on a minimal Linux (Docker, fresh Debian Slim, CI runner), Chrome will exit silently on launch because the required shared libs aren't present. On Debian / Ubuntu: `sudo apt install libnss3 libatk-bridge2.0-0 libatk1.0-0 libdrm2 libxcomposite1 libxdamage1 libxrandr2 libgbm1 libxkbcommon0 libasound2 libpango-1.0-0 libcairo2`. If tshark captures zero frames and the recorder saw no requests, this is usually why.
- The Go recorder generates a local root CA at `~/.chrome-fingerprint/ca/` the first time it runs. macOS and Windows trust it automatically. On Linux you have to do it yourself (`sudo cp ~/.chrome-fingerprint/ca/rootCA.pem /usr/local/share/ca-certificates/chrome-fingerprint.crt && sudo update-ca-certificates`, plus NSS via `certutil` for Chrome). Linux mostly works but I haven't tested it end-to-end - if something is off there, file an issue.

## Install

```bash
# macOS
brew install wireshark

# Ubuntu / Debian
sudo apt install tshark

# Windows
winget install WiresharkFoundation.Wireshark --source winget
```

## Usage

```bash
# Interactive (prompts for Chrome version, URL, interface)
node capture.js

# Scripted
node capture.js --version 147 --url https://example.com

# Force the recorder (fail if it can't start)
node capture.js --version 147 --url https://example.com --header-source recorder

# TLS only - no recorder, no proxy, no manual browsing window
sudo node capture.js --version 147 --url https://example.com --interface en0 --skip-headers

# Recorder only - useful if you've already got a TLS profile
node capture.js --version 147 --url https://example.com --skip-tls
```

## Options

| Flag | What it does |
| --- | --- |
| `--version`, `-v` | Chrome major version, e.g. `147` |
| `--url`, `-u` | Target URL |
| `--interface`, `-i` | tshark capture interface |
| `--chrome-path` | Use a specific Chrome / Chromium binary |
| `--header-source` | `auto` (default) or `recorder` |
| `--skip-headers` | Skip the recorder phase (TLS only) |
| `--skip-tls` | Skip the tshark phase (recorder only) |
| `--timeout`, `-t` | Seconds to wait per phase (default 15) |
| `--help`, `-h` | Show usage |

A few details that aren't obvious from the table:

- `--header-source auto` runs the recorder when `go` is on PATH and silently skips it when it isn't. `recorder` is the strict version: it errors out if the recorder can't start.
- tshark always owns the TLS fingerprint and HTTP/2 SETTINGS. The recorder only contributes header order and pseudo-header order. Both sources are tagged in `captureSources` so you can see where each field came from.
- `--interface` takes a name on macOS / Linux (`en0`, `eth0`, `any`) and a numeric index on Windows (the number from `tshark -D`).

## Output

Looks roughly like this:

```json
{
  "chromeVersion": "147",
  "chromeFullVersion": "147.0.7727.56",
  "platform": "Windows",
  "capturedAt": "2026-04-09T12:34:56.000Z",
  "targetUrl": "https://example.com/",
  "userAgent": "Mozilla/5.0 ...",
  "secCHUA": "\"Google Chrome\";v=\"147\", ...",
  "tls": {
    "cipherSuites": ["GREASE(0x0a0a)", "TLS_AES_128_GCM_SHA256"],
    "extensions": ["server_name", "supported_groups"],
    "supportedGroups": ["x25519", "secp256r1"],
    "signatureAlgorithms": ["ecdsa_secp256r1_sha256"],
    "alpn": ["h2", "http/1.1"],
    "supportedVersions": ["0x0304"],
    "ja3": "771,...",
    "ja3Hash": "abc123..."
  },
  "http2": {
    "settings": { "HEADER_TABLE_SIZE": 65536 },
    "settingsOrder": ["HEADER_TABLE_SIZE"],
    "windowUpdate": 15663105,
    "pseudoHeaderOrder": [":method", ":authority", ":scheme", ":path"]
  },
  "captureSources": {
    "tls": "tshark",
    "http2": "tshark",
    "headerOrders": "recorder"
  },
  "headerOrders": {
    "document": ["sec-ch-ua", "sec-ch-ua-mobile", "user-agent"],
    "script": ["sec-ch-ua", "user-agent", "accept"],
    "xhr-post": ["content-length", "sec-ch-ua", "user-agent"]
  }
}
```

## Known issues

- **Chrome for Testing isn't quite the same as Chrome.** Different `sec-ch-ua` branding, slightly different header order. The downloader prefers real branded Chrome via Google's Omaha service, then `ulixee/chrome-versions`, and only falls back to CfT as a last resort. If your profile says `chrome-for-testing` in `captureSources` you're not capturing the real thing.
- **Mismatch refusal.** If the resolved Chrome binary doesn't match the major version you asked for, the tool refuses to save the profile. Better to error than to label a Chrome 145 capture as Chrome 147.

## Roadmap

- **QUIC / HTTP/3.** Not supported yet. Chrome is launched with `--disable-quic` so everything falls back to TCP + TLS - both tshark's H2 dissector and the recorder only know how to deal with TLS-over-TCP. Decrypting QUIC via the keylog, recording HTTP/3 SETTINGS, and capturing QUIC transport parameters is on the list. If `Pcap stats` reports any QUIC frames, Chrome cached an alt-svc from a previous session - delete `.chrome-versions/` and retry.
- **Linux CA trust automation.** Right now you have to run `update-ca-certificates` and `certutil` yourself.
- **Bigger cipher / extension / group name tables in `src/tls.js`.** The current ones cover what Chrome actually uses, but anything obscure shows up as `unknown(0x...)`.

## Contributing

PRs welcome, especially for the roadmap stuff above and for any time a new Chrome release breaks detection. Before opening one:

```bash
npm test            # JS unit tests
go build ./go       # recorder still compiles
node capture.js --help
```

Keep PRs focused - don't bundle a refactor with a feature.

## License

MIT
