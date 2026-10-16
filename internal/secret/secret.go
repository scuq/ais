// Package secret stores the few credentials ais needs on the host: the
// Claude OAuth token and sink tokens. Values are files with mode 0600 in a
// 0700 directory, encrypted at rest with a passphrase kept in a 0600 file
// of its own (see crypto.go for what that does and does not protect). A
// systemd credential directory ($CREDENTIALS_DIRECTORY, LoadCredential=)
// is consulted first so a unit can supply secrets without files in $HOME;
// those are read as they are, encrypted or plain.
package secret

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// ErrNotFound means the named secret does not exist.
var ErrNotFound = errors.New("secret not found")

// Store is the secret surface the rest of ais uses.
type Store interface {
	Get(name string) (string, error)
	Set(name, value string) error
	Delete(name string) error
	List() ([]string, error)
}

// NormalizeToken removes every whitespace character from a token. Tokens
// pasted from a terminal or saved with a wrapped line arrive broken into
// lines; the API then rejects the header. A token never contains
// whitespace, so stripping it is always right.
func NormalizeToken(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == ' ' || r == '\t' {
			return -1
		}
		return r
	}, s)
}

// CheckToken reports why a stored token cannot work, or nil.
func CheckToken(s string) error {
	if strings.TrimSpace(s) == "" {
		return errors.New("token is empty")
	}
	if strings.ContainsAny(s, " \t\r\n") {
		return errors.New("token contains whitespace or a line break; store it again (ais secret set normalises it)")
	}
	return nil
}

// Dated is implemented by stores that know when a secret was stored. The
// OAuth token is opaque, so its age is the only expiry signal ais has.
type Dated interface {
	StoredAt(name string) (time.Time, error)
}

// Status of a token relative to its lifetime.
const (
	StatusOK       = "ok"
	StatusExpiring = "expiring"
	StatusExpired  = "expired"
)

// TokenStatus classifies a token by age: expired once older than lifetime,
// expiring once within warnBefore of that, ok otherwise. It returns the
// status, the remaining time (negative when past) and a human line.
func TokenStatus(storedAt, now time.Time, lifetime, warnBefore time.Duration) (string, time.Duration, string) {
	remaining := storedAt.Add(lifetime).Sub(now)
	days := func(d time.Duration) int { return int(d.Hours() / 24) }
	switch {
	case remaining <= 0:
		return StatusExpired, remaining, fmt.Sprintf("stored %s, lifetime %dd exceeded by %dd; rotate it with 'claude setup-token' and 'ais secret set'", storedAt.Format("2006-01-02"), days(lifetime), -days(remaining))
	case remaining <= warnBefore:
		return StatusExpiring, remaining, fmt.Sprintf("stored %s, expires in about %dd; rotate it soon with 'claude setup-token' and 'ais secret set'", storedAt.Format("2006-01-02"), days(remaining))
	}
	return StatusOK, remaining, fmt.Sprintf("stored %s, about %dd left", storedAt.Format("2006-01-02"), days(remaining))
}

var nameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

// ValidName reports whether name is safe to use as a file name.
func ValidName(name string) bool { return nameRE.MatchString(name) }

// FileStore keeps one file per secret.
type FileStore struct {
	Dir string
	// CredentialsDir is checked before Dir; empty disables the lookup.
	CredentialsDir string
	// PassphraseFile overrides <Dir>/.passphrase.
	PassphraseFile string
}

func (s *FileStore) passphrasePath() string {
	if s.PassphraseFile != "" {
		return s.PassphraseFile
	}
	return filepath.Join(s.Dir, PassphraseFileName)
}

// Passphrase returns the passphrase, from $CREDENTIALS_DIRECTORY/ais-passphrase
// first, then the passphrase file. ErrNoPassphrase when neither exists.
func (s *FileStore) Passphrase() (string, error) {
	if s.CredentialsDir != "" {
		if data, err := os.ReadFile(filepath.Join(s.CredentialsDir, "ais-passphrase")); err == nil {
			return strings.TrimRight(string(data), "\r\n"), nil
		}
	}
	data, err := os.ReadFile(s.passphrasePath())
	if errors.Is(err, fs.ErrNotExist) {
		return "", ErrNoPassphrase
	}
	if err != nil {
		return "", err
	}
	p := strings.TrimRight(string(data), "\r\n")
	if p == "" {
		return "", ErrNoPassphrase
	}
	return p, nil
}

// HasPassphrase reports whether a passphrase is configured.
func (s *FileStore) HasPassphrase() bool {
	_, err := s.Passphrase()
	return err == nil
}

// SetPassphrase writes a new passphrase and re-encrypts every secret that
// was readable under the old one (or stored in plaintext). Returns how
// many secrets were re-encrypted.
func (s *FileStore) SetPassphrase(passphrase string) (int, error) {
	if strings.TrimSpace(passphrase) == "" {
		return 0, errors.New("empty passphrase")
	}
	names, err := s.List()
	if err != nil {
		return 0, err
	}
	values := map[string]string{}
	for _, n := range names {
		v, err := s.Get(n)
		if err != nil {
			return 0, fmt.Errorf("cannot re-encrypt %s under the new passphrase: %w", n, err)
		}
		values[n] = v
	}
	if err := s.writePassphrase(passphrase); err != nil {
		return 0, err
	}
	for n, v := range values {
		if err := s.Set(n, v); err != nil {
			return 0, err
		}
	}
	return len(values), nil
}

// EnsurePassphrase generates a random passphrase when none exists. Returns
// true when it created one.
func (s *FileStore) EnsurePassphrase() (bool, error) {
	if s.HasPassphrase() {
		return false, nil
	}
	p, err := NewPassphrase()
	if err != nil {
		return false, err
	}
	return true, s.writePassphrase(p)
}

func (s *FileStore) writePassphrase(p string) error {
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return err
	}
	path := s.passphrasePath()
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(p+"\n"), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Encrypted reports whether the stored file of name is encrypted; false
// for a plaintext file written by hand, or for a systemd credential.
func (s *FileStore) Encrypted(name string) bool {
	data, err := os.ReadFile(filepath.Join(s.Dir, name))
	return err == nil && IsEncrypted(data)
}

// NewFileStore returns a store rooted at dir, honouring
// $CREDENTIALS_DIRECTORY when set.
func NewFileStore(dir string) *FileStore {
	return &FileStore{Dir: dir, CredentialsDir: os.Getenv("CREDENTIALS_DIRECTORY")}
}

func (s *FileStore) Get(name string) (string, error) {
	if !ValidName(name) {
		return "", fmt.Errorf("invalid secret name %q", name)
	}
	if s.CredentialsDir != "" {
		if data, err := os.ReadFile(filepath.Join(s.CredentialsDir, name)); err == nil {
			return strings.TrimRight(string(data), "\r\n"), nil
		}
	}
	data, err := os.ReadFile(filepath.Join(s.Dir, name))
	if errors.Is(err, fs.ErrNotExist) {
		return "", fmt.Errorf("%w: %s (set it with: ais secret set %s)", ErrNotFound, name, name)
	}
	if err != nil {
		return "", err
	}
	if !IsEncrypted(data) {
		// A file written by hand. Readable, but doctor flags it.
		return strings.TrimRight(string(data), "\r\n"), nil
	}
	p, err := s.Passphrase()
	if err != nil {
		return "", fmtErr(name, err)
	}
	v, err := Decrypt(p, data)
	if err != nil {
		return "", fmtErr(name, err)
	}
	return v, nil
}

// StoredAt returns the modification time of the secret file, which Set
// and `ais secret set` refresh on every rotation.
func (s *FileStore) StoredAt(name string) (time.Time, error) {
	if !ValidName(name) {
		return time.Time{}, fmt.Errorf("invalid secret name %q", name)
	}
	if s.CredentialsDir != "" {
		if st, err := os.Stat(filepath.Join(s.CredentialsDir, name)); err == nil {
			return st.ModTime(), nil
		}
	}
	st, err := os.Stat(filepath.Join(s.Dir, name))
	if errors.Is(err, fs.ErrNotExist) {
		return time.Time{}, fmt.Errorf("%w: %s", ErrNotFound, name)
	}
	if err != nil {
		return time.Time{}, err
	}
	return st.ModTime(), nil
}

func (s *FileStore) Set(name, value string) error {
	if !ValidName(name) {
		return fmt.Errorf("invalid secret name %q", name)
	}
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(s.Dir, 0o700); err != nil {
		return err
	}
	// Trailing newlines come from piped input, never from the value.
	value = strings.TrimRight(value, "\r\n")
	if _, err := s.EnsurePassphrase(); err != nil {
		return err
	}
	p, err := s.Passphrase()
	if err != nil {
		return err
	}
	enc, err := Encrypt(p, value)
	if err != nil {
		return err
	}
	tmp := filepath.Join(s.Dir, "."+name+".tmp")
	if err := os.WriteFile(tmp, enc, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(s.Dir, name))
}

func (s *FileStore) Delete(name string) error {
	if !ValidName(name) {
		return fmt.Errorf("invalid secret name %q", name)
	}
	err := os.Remove(filepath.Join(s.Dir, name))
	if errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("%w: %s", ErrNotFound, name)
	}
	return err
}

func (s *FileStore) List() ([]string, error) {
	entries, err := os.ReadDir(s.Dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if !e.IsDir() && ValidName(e.Name()) && !strings.HasSuffix(e.Name(), ".tmp") {
			out = append(out, e.Name())
		}
	}
	sort.Strings(out)
	return out, nil
}

var refRE = regexp.MustCompile(`\$\{secret:([A-Za-z0-9._-]+)\}`)

// Expand replaces every ${secret:name} in s with the secret's value.
func Expand(s string, st Store) (string, error) {
	var firstErr error
	out := refRE.ReplaceAllStringFunc(s, func(m string) string {
		name := refRE.FindStringSubmatch(m)[1]
		v, err := st.Get(name)
		if err != nil && firstErr == nil {
			firstErr = err
		}
		return v
	})
	return out, firstErr
}

// Memory is an in-memory store for tests.
type Memory map[string]string

func (m Memory) Get(name string) (string, error) {
	v, ok := m[name]
	if !ok {
		return "", fmt.Errorf("%w: %s", ErrNotFound, name)
	}
	return v, nil
}
func (m Memory) Set(name, value string) error { m[name] = value; return nil }
func (m Memory) Delete(name string) error     { delete(m, name); return nil }
func (m Memory) List() ([]string, error) {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out, nil
}
