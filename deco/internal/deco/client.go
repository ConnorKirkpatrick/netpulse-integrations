package deco

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// AuthenticationError marks rejected credentials as terminal for this
// poller. Retrying bad credentials feeds the device's failed-login
// counter and can lock the local admin out, so the supervisor and the
// standalone pusher stop instead of hammering the login again.
type AuthenticationError struct{ message string }

func (e *AuthenticationError) Error() string  { return e.message }
func (e *AuthenticationError) Terminal() bool { return true }

// client is one logged-in Deco session. It is built per Poll, like the
// UniFi pusher: the device drops idle sessions and the login handshake is
// six small requests, so keeping no state across cycles is simpler than
// detecting expiry mid-poll.
type client struct {
	hc   *http.Client
	base string
	id   string
	seq  int
	key  string
	iv   string
	ee   string // RSA exponent, hex
	nn   string // RSA modulus, hex
}

func newHTTPClient(timeout time.Duration, insecure bool) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if insecure {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // device self-signed certificate, same as the unifi pusher
	}
	return &http.Client{Timeout: timeout, Transport: transport}
}

// login performs the Deco web-UI handshake and returns a ready session.
// The sequence is fixed by the firmware, not by HTTP semantics:
//
//  1. POST /?code=7&asyn=1          -> 401 body carries the su_encrypt
//     key (line 4) and alphabet (line 5)
//  2. POST /?code=16&asyn=0 "enable"
//  3. POST /?code=16&asyn=0 "get"   -> RSA public key (ee, nn) + seq counter
//  4. id = su_encrypt(key, md5(password), alphabet)
//  5. POST /?code=7&asyn=0&id=      body RSA(password)     <- credential check
//  6. POST /?code=16&asyn=0 "set RSA(k=..&i=..)"           <- AES key exchange
//
// A wrong password surfaces at step 5 as a non-"00000" status or a 401,
// and is reported as AuthenticationError.
func login(ctx context.Context, hc *http.Client, base, password string) (*client, error) {
	// Step 1: the 401 challenge.
	body, status, err := rawPost(ctx, hc, base, base+"/?code=7&asyn=1", "")
	if err != nil {
		return nil, err
	}
	if status != http.StatusUnauthorized {
		return nil, fmt.Errorf("deco: expected 401 challenge, got HTTP %d", status)
	}
	lines := strings.Split(strings.TrimSpace(body), "\r\n")
	if len(lines) < 5 {
		return nil, fmt.Errorf("deco: 401 challenge body has %d lines, wanted at least 5", len(lines))
	}
	key3 := strings.TrimSpace(lines[3])
	alphabet := strings.TrimSpace(lines[4])
	if key3 == "" || alphabet == "" {
		return nil, errors.New("deco: 401 challenge carries no key or alphabet")
	}

	// Step 2: enable the GDPR layer.
	body, _, err = rawPost(ctx, hc, base, base+"/?code=16&asyn=0", "enable")
	if err != nil {
		return nil, err
	}
	if !okStatus(body) {
		return nil, fmt.Errorf("deco: GDPR enable rejected: %q", truncate(body))
	}

	// Step 3: fetch the RSA public key and the anti-replay counter.
	body, _, err = rawPost(ctx, hc, base, base+"/?code=16&asyn=0", "get")
	if err != nil {
		return nil, err
	}
	ee, nn, seq, err := parseRSA(body)
	if err != nil {
		return nil, err
	}

	// Steps 4-5: login id and password check.
	id := suEncrypt(key3, md5hex(password), alphabet)
	encPass, err := rsaEncrypt(password, nn, ee)
	if err != nil {
		return nil, err
	}
	body, status, err = rawPost(ctx, hc, base, base+"/?code=7&asyn=0&id="+id, encPass)
	if err != nil {
		return nil, err
	}
	if status == http.StatusUnauthorized || !okStatus(body) {
		return nil, &AuthenticationError{"deco: password rejected by " + base}
	}

	// Step 6: AES key exchange. The key and IV are random 16-character
	// strings; the device echoes neither back.
	key, err := randomDigits(16)
	if err != nil {
		return nil, err
	}
	iv, err := randomDigits(16)
	if err != nil {
		return nil, err
	}
	sig, err := rsaEncrypt("k="+key+"&i="+iv, nn, ee)
	if err != nil {
		return nil, err
	}
	body, _, err = rawPost(ctx, hc, base, base+"/?code=16&asyn=0&id="+id, "set "+sig)
	if err != nil {
		return nil, err
	}
	if !okStatus(body) {
		return nil, fmt.Errorf("deco: AES key exchange rejected: %q", truncate(body))
	}
	return &client{hc: hc, base: base, id: id, seq: seq, key: key, iv: iv, ee: ee, nn: nn}, nil
}

// parseRSA extracts ee, nn and seq from the code=16 "get" reply:
// "00000\r\nee\r\nnn\r\nseq".
func parseRSA(body string) (ee, nn string, seq int, err error) {
	if !okStatus(body) {
		return "", "", 0, fmt.Errorf("deco: bad RSA reply: %q", truncate(body))
	}
	lines := strings.Split(strings.TrimSpace(body), "\r\n")
	if len(lines) < 4 {
		return "", "", 0, fmt.Errorf("deco: RSA reply has %d lines, wanted 4", len(lines))
	}
	ee = strings.TrimSpace(lines[1])
	nn = strings.TrimSpace(lines[2])
	seq, err = strconv.Atoi(strings.TrimSpace(lines[3]))
	if err != nil {
		return "", "", 0, fmt.Errorf("deco: bad seq counter %q", lines[3])
	}
	if ee == "" || nn == "" {
		return "", "", 0, errors.New("deco: RSA key missing from reply")
	}
	return ee, nn, seq, nil
}

// okStatus reports whether a device body starts with the "00000" success
// marker.
func okStatus(body string) bool {
	lines := strings.Split(body, "\r\n")
	return len(lines) > 0 && strings.TrimSpace(lines[0]) == "00000"
}

// rawPost performs one POST and returns the body and the HTTP status. The
// device answers every request in the same custom CRLF text format; a
// malformed answer (the firmware's way of rejecting an unsupported endpoint)
// surfaces as the http client's read error.
//
// The firmware's web server is fussy about the browser headers the portal
// sends: without X-Requested-With and the Origin/Referer pair it answers
// 408 instead of the expected challenge or status line. base is the https
// origin (e.g. "https://deco.lan") used for those two.
func rawPost(ctx context.Context, hc *http.Client, base, url, body string) (string, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(body))
	if err != nil {
		return "", 0, fmt.Errorf("deco: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/131.0.0.0")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	req.Header.Set("Origin", base)
	req.Header.Set("Referer", base+"/")
	resp, err := hc.Do(req)
	if err != nil {
		return "", 0, fmt.Errorf("deco: %w", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 8*1024*1024))
	if err != nil {
		return "", resp.StatusCode, fmt.Errorf("deco: read response: %w", err)
	}
	return string(data), resp.StatusCode, nil
}

// api issues one encrypted /admin/<area> call and unmarshals the decrypted
// JSON into target. The seq counter advances by the ciphertext length,
// matching the anti-replay accounting of the firmware.
func (c *client) api(ctx context.Context, area, form string, reqPayload, target any) error {
	reqJSON, err := json.Marshal(reqPayload)
	if err != nil {
		return fmt.Errorf("deco: marshal %s.%s: %w", area, form, err)
	}
	data, err := aesEncryptB64(c.key, c.iv, string(reqJSON))
	if err != nil {
		return err
	}
	sig := "k=" + c.key + "&i=" + c.iv + "&s=" + strconv.Itoa(c.seq+len(data))
	var signParts []string
	for i := 0; i < len(sig); i += 53 {
		end := i + 53
		if end > len(sig) {
			end = len(sig)
		}
		part, err := rsaEncrypt(sig[i:end], c.nn, c.ee)
		if err != nil {
			return err
		}
		signParts = append(signParts, part)
	}
	url := fmt.Sprintf("%s/admin/%s?form=%s&id=%s", c.base, area, form, c.id)
	body, status, err := rawPost(ctx, c.hc, c.base, url, "sign="+strings.Join(signParts, "")+"&data="+data)
	if err != nil {
		return err
	}
	if status == http.StatusUnauthorized {
		return &AuthenticationError{"deco: session rejected by " + c.base}
	}
	// The /admin endpoints answer with the whole body base64(AES(JSON))
	// under the session key/iv. There is no "00000" status prefix here (that
	// is the login handshake's format). A body that is neither AES base64
	// nor JSON is the firmware's way of rejecting an unsupported form, and
	// we surface it as an error.
	plain, err := decryptBody(c.key, c.iv, body)
	if err != nil {
		return fmt.Errorf("deco: %s.%s: %v (device reply: %q)", area, form, err, truncate(body))
	}
	if target == nil {
		return nil
	}
	if err := json.Unmarshal([]byte(plain), target); err != nil {
		return fmt.Errorf("deco: %s.%s: bad JSON: %w", area, form, err)
	}
	return nil
}

// decryptBody turns a device reply into plaintext. The GDPR layer answers
// base64(AES-CBC(JSON)); a build that skips it answers plain JSON. Both are
// accepted. Anything else is an error carrying the device's raw text.
func decryptBody(key, iv, body string) (string, error) {
	encoded := strings.TrimSpace(body)
	if plain, err := aesDecryptB64(key, iv, encoded); err == nil {
		return plain, nil
	} else if strings.HasPrefix(encoded, "{") || strings.HasPrefix(encoded, "[") {
		return encoded, nil // unencrypted JSON answer
	} else {
		return "", err
	}
}

// truncate keeps error messages short without leaking the payload.
func truncate(s string) string {
	s = strings.ReplaceAll(s, "\r\n", " | ")
	if len(s) > 120 {
		return s[:120] + "..."
	}
	return s
}
