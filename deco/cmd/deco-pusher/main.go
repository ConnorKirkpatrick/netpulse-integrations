// Command deco-pusher polls a TP-Link Deco mesh over its web-portal API and
// pushes the resulting probe payload to a NetPulse server. It is the
// standalone variant of the deco integration: run one instance per Deco
// appliance, from a host that can reach the Deco's LAN.
package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/gnacho/netpulse-integrations/deco"
	"github.com/gnacho/netpulse-integrations/internal/pusher"
)

var Version = "0.1.0"

func run(ctx context.Context) error {
	cfg, err := pusher.ConfigFromEnv("deco-pusher", Version)
	if err != nil {
		return err
	}
	host, err := pusher.RequiredEnv("DECO_HOST")
	if err != nil {
		return err
	}
	password, err := pusher.RequiredEnv("DECO_PASSWORD")
	if err != nil {
		return err
	}
	poller := deco.New(deco.Config{
		Host:     host,
		Password: password,
		// The Deco ships a self-signed certificate, so verification is
		// off by default; set DECO_INSECURE=0 to keep it on behind a
		// trusted CA.
		Insecure: os.Getenv("DECO_INSECURE") != "0",
	})
	return pusher.Run(ctx, cfg, pusher.FromData(poller.Poll))
}

func main() {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, nil)))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx); err != nil {
		slog.Error("deco-pusher: stopped", "err", err)
		os.Exit(1)
	}
}
