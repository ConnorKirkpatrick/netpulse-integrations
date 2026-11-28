# TP-Link Deco integration

Pushes the state of a TP-Link Deco mesh (any model that exposes the built-in
web-portal API) to NetPulse. The poller talks to the router's local HTTPS
management interface — the same one the web UI uses — and is **read-only**:
it only performs the login handshake and a handful of read calls, and never
issues a configuration change.

## How it works

Each poll logs in fresh (the device drops idle sessions, so holding a cookie
across cycles is more fragile than a six-request handshake) and then reads four
sections:

| Deco endpoint         | Area / form          | Feeds the payload                          | Required |
|-----------------------|----------------------|--------------------------------------------|----------|
| Mesh inventory        | `device/device_list` | system identity, backhaul, own-BSSID set   | yes      |
| Connected LAN clients | `client/client_list` | ARP, DHCP leases, per-client signal/band   | no       |
| Wi-Fi SSID profiles   | `wireless/wlan`      | radio names, channels, client counts       | no       |
| Uplink                | `network/wan_ipv4`   | WAN proto / IP / gateway / DNS             | no       |

Only the mesh inventory is required: without it there is nothing to identify
the router. The other three degrade gracefully — if the firmware rejects one
(the `performance` and `firmware_status` calls, for instance, are refused by
some builds) that section simply is not populated and the rest of the poll
still succeeds.

### Login handshake

Deco does not use cookies or a bearer token. It is a small custom protocol
built on top of three crypto primitives the web UI ships in its JavaScript:

1. `POST /?code=7&asyn=1` returns HTTP 401 with a CRLF body whose line 4 is a
   per-session key and line 5 a 344-character substitution alphabet.
2. `POST /?code=16&asyn=0` with body `enable` turns on the "GDPR" encryption
   layer.
3. `POST /?code=16&asyn=0` with body `get` returns the router's RSA-1024
   public key (exponent, modulus) and an anti-replay counter.
4. The login id is computed as a substitution cipher
   `su_encrypt(key, MD5(password), alphabet)` — the same `$.su.encrypt` the
   browser runs.
5. `POST /?code=7&asyn=0&id=<id>` with the RSA-encrypted password performs the
   credential check. A wrong password is rejected here and reported as a
   terminal `AuthenticationError` so the supervisor stops instead of feeding
   the device's failed-login counter.
6. `POST /?code=16&asyn=0&id=<id>` with `set <RSA("k=<16>&i=<16>")>` installs
   a session AES-128 key/iv the poller generated.

From then on every `/admin/<area>?form=<form>` call is
`sign=<RSA chunks of k/i/seq> & data=<AES-CBC(JSON)>`, and the reply body is
`base64(AES(JSON))` under the same key. The `sign` field is the RSA
encryption of `k=<key>&i=<iv>&s=<seq+len(data)>` split into 53-character
chunks, which is the anti-replay mechanism the firmware enforces.

### Signal levels

Deco only exposes a four-bar signal level (`0`–`3`) per band, not a true RSSI.
The integration maps those bars to representative dBm midpoints
(3 → -50, 2 → -60, 1 → -70, 0 → -80) so NetPulse can order and display them.
Treat the numbers as "strong / fair / weak", not as a measurement.

### What is deliberately not sent

- The Wi-Fi passphrase. The `wlan` sections return the base64-encoded
  password, but no Go struct declares that field, so it can never reach the
  payload, the logs or the server.
- Per-unit per-second throughput and the firmware-upgrade state. Some Deco
  builds reject those endpoints outright, and neither maps cleanly onto the
  neutral payload, so the poller does not request them.

## Building

```sh
go build ./deco/...
```

Two binaries are produced:

- `deco/cmd/deco-pusher` — a standalone pusher for running outside the
  supervisor (Docker, a systemd unit, a Raspberry Pi, …).
- `cmd/integrations-supervisor` — the supervisor with Deco wired in as
  `type: "deco"`. This is the binary the `deco/v*` release tags publish.

## Configuration (standalone pusher)

All settings come from the environment; see `config.example.json` for the
full set. The Deco-specific variables are:

| Variable        | Meaning                                            | Default  |
|-----------------|----------------------------------------------------|----------|
| `DECO_HOST`     | Hostname or IP of the Deco (e.g. `deco.lan`)       | required |
| `DECO_PASSWORD` | Password of the Deco web UI (the admin password)   | required |
| `DECO_INSECURE` | `0` to keep TLS verification on behind a trusted CA | `true`   |

The shared pusher variables (`NETPULSE_SERVER`, `NETPULSE_TOKEN`,
`NETPULSE_SLUG`, `NETPULSE_INTERVAL`, `NETPULSE_SERVER_FP` or
`NETPULSE_CA_FILE`) are read by the common `pusher` package.

## Running under the supervisor

```json
{
  "type": "deco",
  "host": "deco.lan",
  "password": "change-me",
  "insecure": true
}
```

The supervisor reads the router's state on the configured interval and pushes
it to NetPulse. `host` and `password` are required. Set `insecure: true`
unless you have installed the Deco's self-signed certificate into your trust
store: the Deco connection itself does not accept a custom CA file, so
skipping verification is the usual way to use a stock Deco.
