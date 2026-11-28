// Package deco polls a TP-Link Deco mesh from an external pusher.
//
// Deco is a closed appliance: the native NetPulse agent cannot run on it, so
// this package speaks the Deco web-portal API over the LAN and returns the
// same probe.PayloadData used by every external integration. The client is
// strictly read-only: it logs in and issues "operation":"read" calls, never
// writing to any endpoint.
//
// The portal API is unusual. Every request is a POST whose body is a
// form-encoded "sign=<hex>&data=<base64>" pair. The sign is the device
// RSA-public-key encryption of a key/iv/seq string; the data is the JSON
// payload encrypted with AES-128-CBC under a 16-character key and IV that
// the client generated and exchanged during login. Login itself is a
// six-step handshake driven by the firmware's own tpencrypt.js, and the
// per-boot XOR key and alphabet are delivered inside the HTTP 401 challenge
// body. None of this is documented by TP-Link; it is reconstructed from the
// portal's own JavaScript.
package deco

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/gnacho/netpulse/agent/probe"
)

// Config is the Deco endpoint and credentials for one pusher.
type Config struct {
	// Host is the Deco's LAN address, e.g. "192.168.1.15" or "deco.lan".
	// The portal listens on 443 by default; append a port (e.g.
	// "192.168.1.15:8443") only if the appliance was set to a non-default one.
	Host string
	// Password is the Deco local admin password. It is sent once per login,
	// RSA-encrypted, and never logged.
	Password string
	// Insecure disables TLS certificate verification. The Deco ships a
	// self-signed certificate, so this is required in the common case; it
	// exists so a caller with a trusted CA can keep verification on.
	Insecure bool
	// Timeout bounds every HTTP request. The zero value becomes ten seconds.
	Timeout time.Duration
}

// Poller holds the resolved configuration and logs fallback diagnostics.
type Poller struct {
	cfg    Config
	logger *slog.Logger
}

// New builds a poller. A zero timeout becomes ten seconds. The optional
// logger receives diagnostics and defaults to slog.Default.
func New(cfg Config, loggers ...*slog.Logger) *Poller {
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}
	logger := slog.Default()
	if len(loggers) > 0 && loggers[0] != nil {
		logger = loggers[0]
	}
	return &Poller{cfg: cfg, logger: logger}
}

// Poll performs one read-only cycle: a fresh login, then the sections the
// payload needs, and returns the assembled probe payload. A rejected
// password is returned as *AuthenticationError so the caller can stop
// instead of re-triggering the device's login lockout.
func (p *Poller) Poll(ctx context.Context) (*probe.PayloadData, error) {
	base, err := p.baseURL()
	if err != nil {
		return nil, err
	}
	hc := newHTTPClient(p.cfg.Timeout, p.cfg.Insecure)

	c, err := login(ctx, hc, base, p.cfg.Password)
	if err != nil {
		var authErr *AuthenticationError
		if errors.As(err, &authErr) {
			p.logger.Error("deco login rejected; stopping to avoid lockout", "host", base)
			return nil, err
		}
		p.logger.Warn("deco login failed", "host", base, "error", err)
		return nil, err
	}

	// device_list is the mesh identity and is required. The rest are
	// optional: a build that rejects a form returns its raw error blob,
	// which we log and skip rather than failing the whole cycle on.
	var dl deviceListResp
	if err := c.api(ctx, "device", "device_list", readOp(), &dl); err != nil {
		return nil, err
	}
	if dl.ErrorCode != 0 {
		return nil, fmt.Errorf("deco: device_list refused (error_code %d)", dl.ErrorCode)
	}
	units := dl.Result.DeviceList
	if len(units) == 0 {
		return nil, errors.New("deco: empty device_list; is this a Deco mesh?")
	}

	var clients []meshClient
	var wl *wlan
	var wan *wanV4

	var cl clientListResp
	if err := c.api(ctx, "client", "client_list", readOp(), &cl); err != nil {
		p.logger.Warn("deco client_list unavailable", "error", err)
	} else if cl.ErrorCode != 0 {
		p.logger.Warn("deco client_list refused", "error_code", cl.ErrorCode)
	} else {
		clients = cl.Result.ClientList
	}

	var wlr wlanResp
	if err := c.api(ctx, "wireless", "wlan", readOp(), &wlr); err != nil {
		p.logger.Warn("deco wlan unavailable", "error", err)
	} else if wlr.ErrorCode != 0 {
		p.logger.Warn("deco wlan refused", "error_code", wlr.ErrorCode)
	} else {
		wl = &wlr.Result
	}

	var wvr wanV4Resp
	if err := c.api(ctx, "network", "wan_ipv4", readOp(), &wvr); err != nil {
		p.logger.Warn("deco wan_ipv4 unavailable", "error", err)
	} else if wvr.ErrorCode != 0 {
		p.logger.Warn("deco wan_ipv4 refused", "error_code", wvr.ErrorCode)
	} else {
		wan = &wvr.Result
	}

	return buildPayload(units, clients, wl, wan), nil
}

// baseURL resolves the configured host into the https base URL. The Deco
// portal is HTTPS on 443 by default; an explicit port in the host overrides
// it. When no port is given we leave it off so the client uses the standard
// HTTPS port.
func (p *Poller) baseURL() (string, error) {
	host := strings.TrimSpace(p.cfg.Host)
	if host == "" {
		return "", errors.New("deco: Host is required")
	}
	host = strings.TrimPrefix(host, "http://")
	host = strings.TrimPrefix(host, "https://")
	host = strings.TrimSuffix(host, "/")
	return "https://" + host, nil
}

// readOp is the standard read payload the Deco portal expects for these
// endpoints. device_mac selects the unit in a multi-pack mesh; "default"
// resolves to the master, which is the one that answers for the whole mesh.
func readOp() map[string]string { return map[string]string{"device_mac": "default"} }
