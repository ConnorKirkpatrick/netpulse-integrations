package deco

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// --- pure crypto / payload helpers -----------------------------------------

func TestSUEncryptMatchesReference(t *testing.T) {
	// Vector computed from the device's own tpencrypt.js (the source of
	// truth), so a regression in the XOR/pad logic is caught in CI.
	const (
		key      = "a3F9k2Lm8Qw1Zx4V"
		value    = "e10adc3949ba59abbe56e057f20f883e" // md5("123456")
		alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
		want     = "EC4aPTDWMqVSxDX0fkSRkPSQjNPjHHMk"
	)
	if got := suEncrypt(key, value, alphabet); got != want {
		t.Fatalf("suEncrypt = %q, want %q", got, want)
	}
	// The shorter side is padded with 0xBB up to the longer length, so a
	// 16-char key against a 32-char value must not panic and must still
	// produce 32 characters.
	if got := suEncrypt("k3y3vAlUeFOrTeSt", value, alphabet); len(got) != len(value) {
		t.Fatalf("suEncrypt length = %d, want %d", len(got), len(value))
	}
	// Deterministic: same inputs, same output.
	if a, b := suEncrypt(key, value, alphabet), suEncrypt(key, value, alphabet); a != b {
		t.Fatalf("suEncrypt not deterministic: %q vs %q", a, b)
	}
}

func TestAesRoundtrip(t *testing.T) {
	const (
		key   = "0123456789abcdef"
		iv    = "fedcba9876543210"
		plain = `{"error_code":0,"result":{"device_list":[]}}`
	)
	enc, err := aesEncryptB64(key, iv, plain)
	if err != nil {
		t.Fatalf("aesEncryptB64: %v", err)
	}
	if _, err := base64.StdEncoding.DecodeString(enc); err != nil {
		t.Fatalf("ciphertext is not valid base64: %v", err)
	}
	got, err := aesDecryptB64(key, iv, enc)
	if err != nil {
		t.Fatalf("aesDecryptB64: %v", err)
	}
	if got != plain {
		t.Fatalf("roundtrip = %q, want %q", got, plain)
	}
}

func TestAesDecryptRejectsBadPadding(t *testing.T) {
	// A well-formed AES block that does not carry valid PKCS#7 padding must
	// be rejected rather than silently returning garbage.
	const key = "0123456789abcdef"
	const iv = "fedcba9876543210"
	enc, _ := aesEncryptB64(key, iv, "ok")
	raw, _ := base64.StdEncoding.DecodeString(enc)
	// Corrupt the final byte so the padding check fails.
	raw[len(raw)-1] ^= 0xFF
	if _, err := aesDecryptB64(key, iv, base64.StdEncoding.EncodeToString(raw)); err == nil {
		t.Fatal("aesDecryptB64 accepted corrupt padding, want error")
	}
}

func TestMacNorm(t *testing.T) {
	for in, want := range map[string]string{
		"B0-19-21-88-4E-D4":    "B01921884ED4",
		"  ab-cd-ef-00-11-22 ": "ABCDEF001122",
		"":                     "",
	} {
		if got := macNorm(in); got != want {
			t.Errorf("macNorm(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestBandName(t *testing.T) {
	for in, want := range map[string]string{
		"band2_4": "2.4 GHz",
		"band5":   "5 GHz",
		"wired":   "",
		"":        "",
	} {
		if got := bandName(in); got != want {
			t.Errorf("bandName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSignalDbm(t *testing.T) {
	for level, want := range map[int]int{
		0:  -80,
		1:  -70,
		2:  -60,
		3:  -50,
		-1: -80, // out of range clamps to the weakest bar
		9:  -80,
	} {
		if got := signalDbm(level); got != want {
			t.Errorf("signalDbm(%d) = %d, want %d", level, got, want)
		}
	}
}

func TestProtoName(t *testing.T) {
	for in, want := range map[string]string{
		"dynamic_ip": "dhcp",
		"static_ip":  "static",
		"pppoe":      "pppoe",
		"custom":     "custom", // unknown values pass through
	} {
		if got := protoName(in); got != want {
			t.Errorf("protoName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestB64(t *testing.T) {
	for in, want := range map[string]string{
		base64.StdEncoding.EncodeToString([]byte("Dans")): "Dans",
		"":             "",
		"not-base64!!": "", // invalid degrades to ""
	} {
		if got := b64(in); got != want {
			t.Errorf("b64(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestBuildPayload(t *testing.T) {
	master := unit{
		DeviceID: "abc123", MAC: "b0-19-21-88-4e-d4", Role: "master",
		DeviceModel: "S7", SoftwareVer: "1.6.3 Build 20260327",
		IP: "192.168.1.15", BSSID2G: "b0-19-21-88-4e-78", BSSID5G: "b0-19-21-88-8e-74",
		CustomNick: base64.StdEncoding.EncodeToString([]byte("Dans")),
	}
	slave := unit{
		DeviceID: "def456", MAC: "b0-19-21-88-99-99", Role: "slave",
		Connection: []string{"wired"},
	}
	client := meshClient{
		MAC: "aa-bb-cc-dd-ee-ff", IP: "192.168.1.50",
		Name: base64.StdEncoding.EncodeToString([]byte("phone")), Online: true,
		Linked: struct {
			SignalLevel struct {
				Band24 int `json:"band2_4"`
				Band5  int `json:"band5"`
			} `json:"signal_level"`
			Connection []string `json:"connection_type"`
			DeviceID   string   `json:"device_id"`
		}{
			SignalLevel: struct {
				Band24 int `json:"band2_4"`
				Band5  int `json:"band5"`
			}{Band24: 3},
			Connection: []string{"band2_4"},
			DeviceID:   "abc123", // associated with the master unit
		},
	}
	wl := &wlan{}
	wl.Band24.Host.Enable = true
	wl.Band24.Backhaul.Channel = 6
	wl.Band24.Host.SSID = base64.StdEncoding.EncodeToString([]byte("SKY67NSU"))
	wl.Band51.Host.Enable = true
	wl.Band51.Backhaul.Channel = 48
	wl.Band51.Host.SSID = base64.StdEncoding.EncodeToString([]byte("SKY67NSU"))
	wan := &wanV4{}
	wan.Wan.DialType = "dynamic_ip"
	wan.Wan.IPInfo = ipInfo{IP: "203.0.113.10", Gateway: "198.51.100.1", DNS1: "1.1.1.1", DNS2: "8.8.8.8"}

	data := buildPayload([]unit{master, slave}, []meshClient{client}, wl, wan)

	if data.System == nil || data.System.Board == nil {
		t.Fatal("missing system/board")
	}
	if got := data.System.Board.Model; got != "Deco S7" {
		t.Errorf("model = %q, want %q", got, "Deco S7")
	}
	if got := data.System.Board.Hostname; got != "Dans" {
		t.Errorf("hostname = %q, want %q", got, "Dans")
	}
	if got := data.System.Backhaul; got != "cable" {
		t.Errorf("backhaul = %q, want %q", got, "cable")
	}
	if len(data.Wireless.Radios) != 2 {
		t.Fatalf("radios = %d, want 2", len(data.Wireless.Radios))
	}
	if wc, ok := data.Wireless.Clients["AABBCCDDEEFF"]; !ok {
		t.Fatal("wireless client missing")
	} else {
		if wc.Band != "2.4 GHz" || wc.SignalDbm != -50 {
			t.Errorf("client band/signal = %q/%d, want 2.4 GHz/-50", wc.Band, wc.SignalDbm)
		}
		// Per-router association: Iface must be the MAC of the unit the client
		// is linked to (the master), and SSID the band's SSID.
		if wc.Iface != "B01921884ED4" {
			t.Errorf("client Iface = %q, want B01921884ED4 (master)", wc.Iface)
		}
		if wc.SSID != "SKY67NSU" {
			t.Errorf("client SSID = %q, want SKY67NSU", wc.SSID)
		}
	}
	if data.Arp["AABBCCDDEEFF"] != "192.168.1.50" {
		t.Errorf("arp = %v, want 192.168.1.50", data.Arp["AABBCCDDEEFF"])
	}
	if data.DHCP == nil || data.DHCP.Leases[0].Hostname != "phone" {
		t.Errorf("dhcp lease wrong: %+v", data.DHCP)
	}
	if data.Wan == nil || data.Wan.Proto != "dhcp" || data.Wan.IP != "203.0.113.10" {
		t.Errorf("wan wrong: %+v", data.Wan)
	}
	if len(data.Wan.DNS) != 2 {
		t.Errorf("wan dns = %v, want 2 entries", data.Wan.DNS)
	}
}

// --- full login + poll against a mocked device -----------------------------

// mockDeco plays the role of a Deco mesh for the login handshake and the four
// read endpoints. It derives the client's AES key/IV from the RSA key-exchange
// step and answers /admin calls with base64(AES(JSON)) exactly like firmware,
// so the whole crypto path is exercised in CI.
type mockDeco struct {
	priv     *rsa.PrivateKey
	key3     string
	alphabet string
	password string

	mu     sync.Mutex
	aesKey string
	aesIV  string
	// apiResults maps "area/form" to the JSON object the device returns for
	// that call (the inner "result" value is wrapped automatically).
	apiResults map[string]any
}

func newMockDeco(password string, results map[string]any) (*mockDeco, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	return &mockDeco{
		priv:       priv,
		key3:       "k3y3vAlUeFOrTeStInG0123456",
		alphabet:   "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
		password:   password,
		apiResults: results,
	}, nil
}

func (m *mockDeco) decryptRSA(t *testing.T, hexCipher string) string {
	t.Helper()
	raw, err := hex.DecodeString(hexCipher)
	if err != nil {
		t.Fatalf("device: ciphertext not hex: %v", err)
	}
	plain, err := rsa.DecryptPKCS1v15(rand.Reader, m.priv, raw)
	if err != nil {
		t.Fatalf("device: RSA decrypt: %v", err)
	}
	return string(plain)
}

func (m *mockDeco) handler(t *testing.T) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		b := string(body)
		q := r.URL.Query()

		// ---- /admin/<area> API calls --------------------------------------
		if strings.HasPrefix(r.URL.Path, "/admin/") {
			area := strings.TrimPrefix(r.URL.Path, "/admin/")
			form := q.Get("form")
			key, iv := m.sessionKey(t)
			// The client's request body is "sign=<hex>&data=<b64>"; decrypt
			// the data to confirm the client and device agree on the key.
			data := b
			if i := strings.Index(b, "data="); i >= 0 {
				data = b[i+len("data="):]
			}
			if _, err := aesDecryptB64(key, iv, data); err != nil {
				t.Errorf("device could not decrypt client payload for %s/%s: %v", area, form, err)
			}
			resp := map[string]any{"error_code": 0, "result": m.apiResults[area+"/"+form]}
			out, _ := json.Marshal(resp)
			enc, err := aesEncryptB64(key, iv, string(out))
			if err != nil {
				t.Fatalf("device encrypt: %v", err)
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(enc))
			return
		}

		// ---- login handshake ---------------------------------------------
		code, asyn := q.Get("code"), q.Get("asyn")
		switch {
		case code == "7" && asyn == "1":
			// 401 challenge: line 4 is the key, line 5 the alphabet.
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte("err\r\n\r\n\r\n" + m.key3 + "\r\n" + m.alphabet))
		case code == "16" && asyn == "0" && b == "enable":
			_, _ = w.Write([]byte("00000\r\n"))
		case code == "16" && asyn == "0" && b == "get":
			nn := m.priv.N.Text(16)
			ee := strconv.FormatInt(int64(m.priv.E), 16)
			_, _ = w.Write([]byte("00000\r\n" + ee + "\r\n" + nn + "\r\n0"))
		case code == "7" && asyn == "0" && q.Get("id") != "":
			// Password check: the body is RSA(password). Decrypt it to prove
			// the client's rsaEncrypt is correct, then accept or reject
			// exactly as firmware would.
			got := m.decryptRSA(t, b)
			if got == m.password {
				_, _ = w.Write([]byte("00000\r\n"))
			} else {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("90001\r\n")) // firmware-style rejection
			}
		case code == "16" && asyn == "0" && q.Get("id") != "" && strings.HasPrefix(b, "set "):
			// AES key exchange: body is "set " + RSA("k=<key>&i=<iv>").
			kv := m.decryptRSA(t, b[len("set "):])
			k, i := "", ""
			for _, part := range strings.Split(kv, "&") {
				if strings.HasPrefix(part, "k=") {
					k = strings.TrimPrefix(part, "k=")
				} else if strings.HasPrefix(part, "i=") {
					i = strings.TrimPrefix(part, "i=")
				}
			}
			m.mu.Lock()
			m.aesKey, m.aesIV = k, i
			m.mu.Unlock()
			_, _ = w.Write([]byte("00000\r\n"))
		default:
			t.Errorf("device: unexpected login request code=%q asyn=%q body=%q", code, asyn, b)
			w.WriteHeader(http.StatusBadRequest)
		}
	}
}

func (m *mockDeco) sessionKey(t *testing.T) (string, string) {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.aesKey == "" || m.aesIV == "" {
		t.Fatal("device: AES key/IV not exchanged yet")
	}
	return m.aesKey, m.aesIV
}

func TestPollAgainstMockDeco(t *testing.T) {
	const password = "s3cr3t-deco-pass"
	results := map[string]any{
		"device/device_list": map[string]any{
			"device_list": []map[string]any{
				{
					"device_id": "abc", "mac": "b0-19-21-88-4e-d4", "role": "master",
					"device_model": "S7", "software_ver": "1.6.3", "ip": "192.168.1.15",
					"bssid_2g": "b0-19-21-88-4e-78", "bssid_5g": "b0-19-21-88-8e-74",
					"custom_nickname": base64.StdEncoding.EncodeToString([]byte("Dans")),
				},
			},
		},
		"client/client_list": map[string]any{
			"client_list": []map[string]any{
				{
					"mac": "aa-bb-cc-dd-ee-ff", "ip": "192.168.1.50",
					"name": base64.StdEncoding.EncodeToString([]byte("phone")), "online": true,
					"linked_device_info": map[string]any{
						"signal_level":    map[string]any{"band2_4": 2, "band5": 0},
						"connection_type": []string{"band2_4"},
					},
				},
			},
		},
		"wireless/wlan": map[string]any{
			"band2_4": map[string]any{
				"host":     map[string]any{"ssid": base64.StdEncoding.EncodeToString([]byte("home")), "enable": true},
				"backhaul": map[string]any{"channel": 6},
			},
			"band5_1": map[string]any{
				"host":     map[string]any{"ssid": base64.StdEncoding.EncodeToString([]byte("home-5")), "enable": true},
				"backhaul": map[string]any{"channel": 48},
			},
		},
		"network/wan_ipv4": map[string]any{
			"wan": map[string]any{
				"dial_type": "dynamic_ip",
				"ip_info":   map[string]any{"ip": "203.0.113.10", "gateway": "198.51.100.1", "dns1": "1.1.1.1", "dns2": "8.8.8.8"},
			},
			"lan": map[string]any{"ip_info": map[string]any{"ip": "192.168.1.1"}},
		},
	}

	mock, err := newMockDeco(password, results)
	if err != nil {
		t.Fatalf("newMockDeco: %v", err)
	}
	ts := httptest.NewTLSServer(http.HandlerFunc(mock.handler(t)))
	defer ts.Close()

	host := strings.TrimPrefix(ts.URL, "https://")
	p := New(Config{Host: host, Password: password, Insecure: true})
	data, err := p.Poll(t.Context())
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if data == nil {
		t.Fatal("Poll returned nil payload")
	}

	// Sanity: every section the mock served must have made it into the
	// neutral payload, proving login + crypto + decode all worked.
	if data.System == nil || data.System.Board == nil || data.System.Board.Model != "Deco S7" {
		t.Errorf("system/board wrong: %+v", data.System)
	}
	if len(data.Wireless.Radios) != 2 {
		t.Errorf("radios = %d, want 2", len(data.Wireless.Radios))
	}
	if _, ok := data.Wireless.Clients["AABBCCDDEEFF"]; !ok {
		t.Error("wireless client AABBCCDDEEFF missing")
	}
	if data.Wan == nil || data.Wan.IP != "203.0.113.10" {
		t.Errorf("wan wrong: %+v", data.Wan)
	}
}

func TestPollWrongPassword(t *testing.T) {
	mock, err := newMockDeco("correct-password", map[string]any{"device/device_list": []any{}})
	if err != nil {
		t.Fatalf("newMockDeco: %v", err)
	}
	ts := httptest.NewTLSServer(http.HandlerFunc(mock.handler(t)))
	defer ts.Close()

	host := strings.TrimPrefix(ts.URL, "https://")
	p := New(Config{Host: host, Password: "wrong-password", Insecure: true})
	_, err = p.Poll(t.Context())
	if err == nil {
		t.Fatal("Poll succeeded with wrong password, want error")
	}
}
