package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"
)

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
