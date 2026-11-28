// Package deco exposes the TP-Link Deco mesh poller to the shared
// integrations supervisor while keeping its protocol implementation private.
package deco

import (
	"log/slog"

	internal "github.com/gnacho/netpulse-integrations/deco/internal/deco"
)

type Config = internal.Config
type Poller = internal.Poller
type AuthenticationError = internal.AuthenticationError

// New builds a poller. An optional logger receives login diagnostics and
// defaults to slog.Default when omitted.
func New(cfg Config, logger ...*slog.Logger) *Poller {
	return internal.New(cfg, logger...)
}
