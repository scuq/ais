package secret

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestFileStore(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "secrets")
	s := &FileStore{Dir: dir}
	if err := s.Set("claude-oauth-token", "tok\n"); err != nil {
		t.Fatal(err)
	}
	st, _ := os.Stat(dir)
	if st.Mode().Perm() != 0o700 {
		t.Errorf("dir mode %o", st.Mode().Perm())
	}
	fi, _ := os.Stat(filepath.Join(dir, "claude-oauth-token"))
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("file mode %o", fi.Mode().Perm())
	}
	v, err := s.Get("claude-oauth-token")
	if err != nil || v != "tok" {
		t.Errorf("get %q %v", v, err)
	}
	names, _ := s.List()
	if len(names) != 1 {
		t.Errorf("list %v", names)
	}
	if _, err := s.Get("missing"); err == nil {
		t.Error("expected not found")
	}
	if err := s.Set("../evil", "x"); err == nil {
		t.Error("path traversal name accepted")
	}
	if err := s.Delete("claude-oauth-token"); err != nil {
		t.Error(err)
	}
}

func TestCredentialsDirWins(t *testing.T) {
	cred := t.TempDir()
	_ = os.WriteFile(filepath.Join(cred, "x"), []byte("from-systemd\n"), 0o600)
	s := &FileStore{Dir: t.TempDir(), CredentialsDir: cred}
	_ = s.Set("x", "from-file")
	if v, _ := s.Get("x"); v != "from-systemd" {
		t.Errorf("got %q", v)
	}
}

func TestExpand(t *testing.T) {
	m := Memory{"a": "1", "b": "2"}
	out, err := Expand("Splunk ${secret:a}-${secret:b}", m)
	if err != nil || out != "Splunk 1-2" {
		t.Errorf("%q %v", out, err)
	}
	if _, err := Expand("${secret:nope}", m); err == nil {
		t.Error("expected error")
	}
}

func TestTokenStatus(t *testing.T) {
	year, month := 365*24*time.Hour, 30*24*time.Hour
	stored := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	cases := []struct {
		now  time.Time
		want string
	}{
		{stored.AddDate(0, 6, 0), StatusOK},
		{stored.Add(year - 10*24*time.Hour), StatusExpiring},
		{stored.Add(year + time.Hour), StatusExpired},
	}
	for _, c := range cases {
		got, _, detail := TokenStatus(stored, c.now, year, month)
		if got != c.want {
			t.Errorf("at %s: got %s want %s (%s)", c.now.Format("2006-01-02"), got, c.want, detail)
		}
	}
	s := &FileStore{Dir: t.TempDir()}
	_ = s.Set("claude-oauth-token", "x")
	at, err := s.StoredAt("claude-oauth-token")
	if err != nil || time.Since(at) > time.Minute {
		t.Errorf("StoredAt: %v %v", at, err)
	}
	if _, err := s.StoredAt("missing"); err == nil {
		t.Error("expected not found")
	}
}

func TestEncryptedAtRest(t *testing.T) {
	s := &FileStore{Dir: filepath.Join(t.TempDir(), "secrets")}
	if err := s.Set("tok", "sk-ant-oat01-value"); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(filepath.Join(s.Dir, "tok"))
	if !IsEncrypted(raw) || strings.Contains(string(raw), "sk-ant") {
		t.Fatalf("not encrypted at rest: %s", raw)
	}
	if fi, _ := os.Stat(filepath.Join(s.Dir, PassphraseFileName)); fi == nil || fi.Mode().Perm() != 0o600 {
		t.Error("passphrase file missing or wrong mode")
	}
	if v, err := s.Get("tok"); err != nil || v != "sk-ant-oat01-value" {
		t.Errorf("round trip: %q %v", v, err)
	}
	if !s.Encrypted("tok") {
		t.Error("Encrypted() false")
	}
	// Plaintext file written by hand still reads, and is reported as such.
	_ = os.WriteFile(filepath.Join(s.Dir, "plain"), []byte("hello\n"), 0o600)
	if v, err := s.Get("plain"); err != nil || v != "hello" {
		t.Errorf("plaintext: %q %v", v, err)
	}
	if s.Encrypted("plain") {
		t.Error("plaintext reported as encrypted")
	}
	// Wrong passphrase fails closed.
	_ = os.WriteFile(filepath.Join(s.Dir, PassphraseFileName), []byte("wrong\n"), 0o600)
	if _, err := s.Get("tok"); err == nil {
		t.Error("decrypt with wrong passphrase succeeded")
	}
	// Missing passphrase is a clear error.
	_ = os.Remove(filepath.Join(s.Dir, PassphraseFileName))
	if _, err := s.Get("tok"); err == nil || !strings.Contains(err.Error(), "passphrase") {
		t.Errorf("missing passphrase: %v", err)
	}
}

func TestSetPassphraseReencrypts(t *testing.T) {
	s := &FileStore{Dir: filepath.Join(t.TempDir(), "secrets")}
	_ = s.Set("a", "1")
	_ = os.WriteFile(filepath.Join(s.Dir, "b"), []byte("2"), 0o600) // plaintext gets encrypted too
	before, _ := os.ReadFile(filepath.Join(s.Dir, "a"))
	n, err := s.SetPassphrase("my phrase")
	if err != nil || n != 2 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	after, _ := os.ReadFile(filepath.Join(s.Dir, "a"))
	if string(before) == string(after) || !s.Encrypted("b") {
		t.Error("secrets not re-encrypted")
	}
	if p, _ := s.Passphrase(); p != "my phrase" {
		t.Errorf("passphrase %q", p)
	}
	if v, _ := s.Get("b"); v != "2" {
		t.Errorf("b=%q", v)
	}
	if _, err := s.SetPassphrase("  "); err == nil {
		t.Error("empty passphrase accepted")
	}
}

func TestNormalizeAndCheckToken(t *testing.T) {
	if got := NormalizeToken("sk-ant-oat01-abc\ndef \r\n"); got != "sk-ant-oat01-abcdef" {
		t.Errorf("got %q", got)
	}
	if err := CheckToken("sk-ant\nx"); err == nil {
		t.Error("line break accepted")
	}
	if err := CheckToken("sk-ant-x"); err != nil {
		t.Error(err)
	}
}
