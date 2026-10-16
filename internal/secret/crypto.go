package secret

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

// Secrets at rest are AES-256-GCM encrypted with a key derived from a
// passphrase by PBKDF2-SHA256. The passphrase lives in its own 0600 file
// next to the secrets. This guards against a casual read of the secret
// files (a backup, a copied home directory, a `cat` over the shoulder); it
// does not guard against root on the same host, who can read the passphrase
// file too. The host is trusted; the files are not.
//
// File format: "ais-enc-v1:" + base64(salt[16] || nonce[12] || ciphertext).

const (
	encPrefix  = "ais-enc-v1:"
	saltLen    = 16
	nonceLen   = 12
	keyLen     = 32
	pbkdfIters = 600_000
)

// IsEncrypted reports whether data is in the encrypted file format.
func IsEncrypted(data []byte) bool {
	return strings.HasPrefix(strings.TrimSpace(string(data)), encPrefix)
}

// ErrNoPassphrase means an encrypted secret cannot be read.
var ErrNoPassphrase = errors.New("no passphrase file; run 'ais secret passphrase set' (or generate)")

// ErrBadPassphrase means decryption failed.
var ErrBadPassphrase = errors.New("cannot decrypt: wrong passphrase or corrupt file")

func deriveKey(passphrase string, salt []byte) ([]byte, error) {
	return pbkdf2.Key(sha256.New, passphrase, salt, pbkdfIters, keyLen)
}

// Encrypt seals value under passphrase.
func Encrypt(passphrase, value string) ([]byte, error) {
	if passphrase == "" {
		return nil, errors.New("empty passphrase")
	}
	salt := make([]byte, saltLen)
	nonce := make([]byte, nonceLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	key, err := deriveKey(passphrase, salt)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	ct := gcm.Seal(nil, nonce, []byte(value), []byte(encPrefix))
	blob := append(append(append([]byte{}, salt...), nonce...), ct...)
	return []byte(encPrefix + base64.StdEncoding.EncodeToString(blob) + "\n"), nil
}

// Decrypt opens data produced by Encrypt.
func Decrypt(passphrase string, data []byte) (string, error) {
	s := strings.TrimSpace(string(data))
	if !strings.HasPrefix(s, encPrefix) {
		return "", errors.New("not an encrypted secret")
	}
	blob, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(s, encPrefix))
	if err != nil || len(blob) < saltLen+nonceLen+1 {
		return "", ErrBadPassphrase
	}
	salt, nonce, ct := blob[:saltLen], blob[saltLen:saltLen+nonceLen], blob[saltLen+nonceLen:]
	key, err := deriveKey(passphrase, salt)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	pt, err := gcm.Open(nil, nonce, ct, []byte(encPrefix))
	if err != nil {
		return "", ErrBadPassphrase
	}
	return string(pt), nil
}

// NewPassphrase returns a random 32-byte passphrase, base64 encoded.
func NewPassphrase() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// PassphraseFileName is the passphrase file inside the secrets directory.
const PassphraseFileName = ".passphrase"

func fmtErr(name string, err error) error { return fmt.Errorf("secret %s: %w", name, err) }
