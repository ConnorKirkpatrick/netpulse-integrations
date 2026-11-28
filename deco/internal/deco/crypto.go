package deco

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/big"
)

// The Deco web UI protects its admin API with a three-step scheme the
// firmware itself never documents: a per-boot XOR cipher (su_encrypt) for
// the login id, PKCS#1 v1.5 RSA for the password and for the AES key
// exchange, and AES-128-CBC for the API bodies. These helpers reproduce
// that scheme; none of it changes device state.

// suEncrypt XORs key and value byte-by-byte, padding whichever is shorter
// with the constant 0xBB (187) up to the length of the longer, then maps
// each result through the alphabet. This is the per-boot cipher the UI uses
// to derive the login id; reproducing it exactly (including the padding)
// keeps us compatible with every firmware build.
func suEncrypt(key, value, alphabet string) string {
	if alphabet == "" {
		return ""
	}
	n := len(key)
	if len(value) > n {
		n = len(value)
	}
	out := make([]byte, n)
	for i := 0; i < n; i++ {
		s := byte(0xBB)
		if i < len(key) {
			s = key[i]
		}
		t := byte(0xBB)
		if i < len(value) {
			t = value[i]
		}
		out[i] = alphabet[(s^t)%byte(len(alphabet))]
	}
	return string(out)
}

// md5hex is the lowercase hex MD5 of s, the form the login id expects.
func md5hex(s string) string {
	sum := md5.Sum([]byte(s))
	return hex.EncodeToString(sum[:])
}

// rsaEncrypt applies PKCS#1 v1.5 padding to msg under the (n, e) key and
// returns the ciphertext as lowercase hex zero-padded to an even length,
// exactly the representation the firmware's JS parser feeds back into its
// BigInteger math. nn and ee are the hex modulus and exponent from the
// device's RSA public key.
func rsaEncrypt(msg, nn, ee string) (string, error) {
	n, ok := new(big.Int).SetString(nn, 16)
	if !ok {
		return "", fmt.Errorf("deco: invalid RSA modulus from device")
	}
	e, ok := new(big.Int).SetString(ee, 16)
	if !ok {
		return "", fmt.Errorf("deco: invalid RSA exponent from device")
	}
	km := n.BitLen() / 8
	if len(msg) > km-11 {
		return "", fmt.Errorf("deco: message of %d bytes does not fit a %d-bit RSA key", len(msg), n.BitLen())
	}
	// PKCS#1 v1.5 type-2 padding: 0x00 0x02 PS 0x00 M with random
	// non-zero PS.
	ps := make([]byte, km-3-len(msg))
	for {
		if _, err := rand.Read(ps); err != nil {
			return "", err
		}
		nonZero := true
		for _, b := range ps {
			if b == 0 {
				nonZero = false
				break
			}
		}
		if nonZero {
			break
		}
	}
	m := make([]byte, 0, km)
	m = append(m, 0x00, 0x02)
	m = append(m, ps...)
	m = append(m, 0x00)
	m = append(m, msg...)
	c := new(big.Int).Exp(new(big.Int).SetBytes(m), e, n)
	hexStr := c.Text(16)
	if len(hexStr)%2 != 0 {
		hexStr = "0" + hexStr
	}
	return hexStr, nil
}

// randomDigits returns n cryptographically random decimal digits. The
// firmware treats the AES key and IV as arbitrary 16-character strings;
// digits keep them JSON-safe in logs.
func randomDigits(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	out := make([]byte, n)
	for i, b := range buf {
		out[i] = '0' + b%10
	}
	return string(out), nil
}

// aesEncryptB64 encrypts plaintext with AES-128-CBC and PKCS#7 padding
// under the 16-character key and IV and returns base64.
func aesEncryptB64(key, iv, plaintext string) (string, error) {
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", fmt.Errorf("deco: aes cipher: %w", err)
	}
	data := []byte(plaintext)
	pad := block.BlockSize() - len(data)%block.BlockSize()
	data = append(data, bytes.Repeat([]byte{byte(pad)}, pad)...)
	enc := make([]byte, len(data))
	cipher.NewCBCEncrypter(block, []byte(iv)).CryptBlocks(enc, data)
	return base64.StdEncoding.EncodeToString(enc), nil
}

// aesDecryptB64 reverses aesEncryptB64.
func aesDecryptB64(key, iv, encoded string) (string, error) {
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", fmt.Errorf("deco: aes cipher: %w", err)
	}
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", fmt.Errorf("deco: bad base64 in device response: %w", err)
	}
	if len(data) == 0 || len(data)%block.BlockSize() != 0 {
		return "", fmt.Errorf("deco: device response is not an AES block multiple (%d bytes)", len(data))
	}
	dec := make([]byte, len(data))
	cipher.NewCBCDecrypter(block, []byte(iv)).CryptBlocks(dec, data)
	pad := int(dec[len(dec)-1])
	if pad == 0 || pad > block.BlockSize() || !bytes.Equal(dec[len(dec)-pad:], bytes.Repeat([]byte{byte(pad)}, pad)) {
		return "", fmt.Errorf("deco: bad PKCS#7 padding in device response")
	}
	return string(dec[:len(dec)-pad]), nil
}
