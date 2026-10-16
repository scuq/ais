// Package store is the host-side record of everything ais does: runs and
// their states, per-task salts and token maps, results in both views,
// leaks, run tokens for the backend and sink deliveries. One SQLite file in
// WAL mode; the daemon is the single writer in normal operation and a
// manual `ais run` serialises on the per-task lock.
package store

import (
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"

	"github.com/scuq/ais/internal/pseudo"
)

// Store wraps the database.
type Store struct {
	db   *sql.DB
	path string
}

// Open opens or creates the database at path and applies the schema.
func Open(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	dsn := fmt.Sprintf("file:%s?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(ON)", path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	s := &Store{db: db, path: path}
	if err := s.migrate(context.Background()); err != nil {
		db.Close()
		return nil, err
	}
	_ = os.Chmod(path, 0o600)
	return s, nil
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

// Path returns the database file.
func (s *Store) Path() string { return s.path }

const schema = `
CREATE TABLE IF NOT EXISTS runs (
  id TEXT PRIMARY KEY,
  task TEXT NOT NULL,
  task_hash TEXT NOT NULL DEFAULT '',
  state TEXT NOT NULL,
  trigger TEXT NOT NULL DEFAULT 'manual',
  engine TEXT NOT NULL DEFAULT '',
  dir TEXT NOT NULL DEFAULT '',
  started_at TEXT NOT NULL,
  finished_at TEXT,
  exit_code INTEGER NOT NULL DEFAULT 0,
  subtype TEXT NOT NULL DEFAULT '',
  model TEXT NOT NULL DEFAULT '',
  cost_usd REAL NOT NULL DEFAULT 0,
  num_turns INTEGER NOT NULL DEFAULT 0,
  duration_ms INTEGER NOT NULL DEFAULT 0,
  input_tokens INTEGER NOT NULL DEFAULT 0,
  output_tokens INTEGER NOT NULL DEFAULT 0,
  cache_read_tokens INTEGER NOT NULL DEFAULT 0,
  cache_creation_tokens INTEGER NOT NULL DEFAULT 0,
  models TEXT NOT NULL DEFAULT '',
  reason TEXT NOT NULL DEFAULT '',
  error TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS runs_task_started ON runs(task, started_at DESC);
CREATE INDEX IF NOT EXISTS runs_state ON runs(state);

CREATE TABLE IF NOT EXISTS task_salts (
  id TEXT PRIMARY KEY,
  task TEXT NOT NULL,
  salt TEXT NOT NULL,
  created_at TEXT NOT NULL,
  active INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS task_salts_task ON task_salts(task, active);

CREATE TABLE IF NOT EXISTS pseudonyms (
  task TEXT NOT NULL,
  salt_id TEXT NOT NULL,
  token TEXT NOT NULL,
  field TEXT NOT NULL,
  value TEXT NOT NULL,
  PRIMARY KEY (task, token)
);

CREATE TABLE IF NOT EXISTS results (
  run_id TEXT PRIMARY KEY REFERENCES runs(id) ON DELETE CASCADE,
  task TEXT NOT NULL,
  finished_at TEXT NOT NULL,
  pseudo_json TEXT NOT NULL,
  clear_json TEXT
);
CREATE INDEX IF NOT EXISTS results_task_finished ON results(task, finished_at DESC);

CREATE TABLE IF NOT EXISTS leaks (
  run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
  value TEXT NOT NULL,
  field TEXT NOT NULL,
  snippet TEXT NOT NULL,
  offset INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS run_tokens (
  hash TEXT PRIMARY KEY,
  run_id TEXT NOT NULL,
  task TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  revoked INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS prompts (
  run_id TEXT PRIMARY KEY REFERENCES runs(id) ON DELETE CASCADE,
  task TEXT NOT NULL,
  created_at TEXT NOT NULL,
  sha256 TEXT NOT NULL,
  bytes INTEGER NOT NULL,
  system TEXT NOT NULL,
  prompt TEXT NOT NULL,
  argv_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS prompts_task_created ON prompts(task, created_at DESC);

CREATE TABLE IF NOT EXISTS deliveries (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
  sink TEXT NOT NULL,
  kind TEXT NOT NULL DEFAULT 'result',
  state TEXT NOT NULL,
  attempt INTEGER NOT NULL DEFAULT 0,
  next_at TEXT NOT NULL,
  last_error TEXT NOT NULL DEFAULT '',
  updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS deliveries_due ON deliveries(state, next_at);
`

// runColumnsAdded lists the columns that were added to runs after the first
// release. CREATE TABLE IF NOT EXISTS does not add them to an existing
// database. Because of this, migrate adds each column that is missing.
var runColumnsAdded = []struct{ name, def string }{
	{"input_tokens", "INTEGER NOT NULL DEFAULT 0"},
	{"output_tokens", "INTEGER NOT NULL DEFAULT 0"},
	{"cache_read_tokens", "INTEGER NOT NULL DEFAULT 0"},
	{"cache_creation_tokens", "INTEGER NOT NULL DEFAULT 0"},
	{"models", "TEXT NOT NULL DEFAULT ''"},
}

func (s *Store) migrate(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, schema); err != nil {
		return err
	}
	have, err := s.columns(ctx, "runs")
	if err != nil {
		return err
	}
	for _, c := range runColumnsAdded {
		if have[c.name] {
			continue
		}
		if _, err := s.db.ExecContext(ctx, `ALTER TABLE runs ADD COLUMN `+c.name+` `+c.def); err != nil {
			return fmt.Errorf("store: add column runs.%s: %w", c.name, err)
		}
	}
	return nil
}

// columns returns the set of column names of table.
func (s *Store) columns(ctx context.Context, table string) (map[string]bool, error) {
	rows, err := s.db.QueryContext(ctx, `PRAGMA table_info(`+table+`)`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var cid int
		var name, typ string
		var notnull, pk int
		var dflt any
		if err := rows.Scan(&cid, &name, &typ, &notnull, &dflt, &pk); err != nil {
			return nil, err
		}
		out[name] = true
	}
	return out, rows.Err()
}

const tsLayout = time.RFC3339Nano

func ts(t time.Time) string { return t.UTC().Format(tsLayout) }

func parseTS(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	t, _ := time.Parse(tsLayout, s)
	return t
}

// Run states.
const (
	StateQueued    = "queued"
	StateRunning   = "running"
	StateSucceeded = "succeeded"
	StateFailed    = "failed"
	StateLeaked    = "leaked"
	StateTimeout   = "timeout"
	StateSkipped   = "skipped"
	StateCancelled = "cancelled"
)

// Run is one row of runs.
type Run struct {
	ID         string    `json:"id"`
	Task       string    `json:"task"`
	TaskHash   string    `json:"taskHash"`
	State      string    `json:"state"`
	Trigger    string    `json:"trigger"`
	Engine     string    `json:"engine"`
	Dir        string    `json:"dir"`
	StartedAt  time.Time `json:"startedAt"`
	FinishedAt time.Time `json:"finishedAt,omitempty"`
	ExitCode   int       `json:"exitCode"`
	Subtype    string    `json:"subtype"`
	// Model is the configured model of the task until the run finishes.
	// After that, it is the model that did most of the work.
	// Models lists each model that the run used, separated by commas,
	// with the highest cost first.
	Model      string  `json:"model"`
	Models     string  `json:"models,omitempty"`
	CostUSD    float64 `json:"costUsd"`
	NumTurns   int     `json:"numTurns"`
	DurationMS int64   `json:"durationMs"`
	// The token counts are the sums over all models of the run.
	InputTokens         int64 `json:"inputTokens"`
	OutputTokens        int64 `json:"outputTokens"`
	CacheReadTokens     int64 `json:"cacheReadTokens"`
	CacheCreationTokens int64 `json:"cacheCreationTokens"`
	// Reason is a short machine-readable cause for failed/skipped/leaked:
	// auth, schema, budget, turns, overlap, exit, engine, timeout.
	Reason string `json:"reason"`
	Error  string `json:"error"`
}

// Terminal reports whether the state is final.
func Terminal(state string) bool {
	switch state {
	case StateSucceeded, StateFailed, StateLeaked, StateTimeout, StateSkipped, StateCancelled:
		return true
	}
	return false
}

// InsertRun records a new run.
func (s *Store) InsertRun(ctx context.Context, r Run) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO runs (id, task, task_hash, state, trigger, engine, dir, started_at, model, reason)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		r.ID, r.Task, r.TaskHash, r.State, r.Trigger, r.Engine, r.Dir, ts(r.StartedAt), r.Model, r.Reason)
	return err
}

// FinishRun writes the terminal fields of a run.
func (s *Store) FinishRun(ctx context.Context, r Run) error {
	if !Terminal(r.State) {
		return fmt.Errorf("store: %q is not a terminal state", r.State)
	}
	res, err := s.db.ExecContext(ctx, `UPDATE runs SET state=?, finished_at=?, exit_code=?, subtype=?, cost_usd=?, num_turns=?, duration_ms=?, reason=?, error=?, model=?,
		input_tokens=?, output_tokens=?, cache_read_tokens=?, cache_creation_tokens=?, models=?
		WHERE id=? AND state IN (?, ?)`,
		r.State, ts(r.FinishedAt), r.ExitCode, r.Subtype, r.CostUSD, r.NumTurns, r.DurationMS, r.Reason, r.Error, r.Model,
		r.InputTokens, r.OutputTokens, r.CacheReadTokens, r.CacheCreationTokens, r.Models,
		r.ID, StateQueued, StateRunning)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("store: run %s is not in a non-terminal state", r.ID)
	}
	return nil
}

// SetRunState moves a non-terminal run to another non-terminal state.
func (s *Store) SetRunState(ctx context.Context, id, state string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE runs SET state=? WHERE id=?`, state, id)
	return err
}

const runCols = `id, task, task_hash, state, trigger, engine, dir, started_at, COALESCE(finished_at,''), exit_code, subtype, model, cost_usd, num_turns, duration_ms, reason, error, input_tokens, output_tokens, cache_read_tokens, cache_creation_tokens, models`

func scanRun(sc interface{ Scan(...any) error }) (Run, error) {
	var r Run
	var started, finished string
	err := sc.Scan(&r.ID, &r.Task, &r.TaskHash, &r.State, &r.Trigger, &r.Engine, &r.Dir, &started, &finished, &r.ExitCode, &r.Subtype, &r.Model, &r.CostUSD, &r.NumTurns, &r.DurationMS, &r.Reason, &r.Error,
		&r.InputTokens, &r.OutputTokens, &r.CacheReadTokens, &r.CacheCreationTokens, &r.Models)
	r.StartedAt = parseTS(started)
	r.FinishedAt = parseTS(finished)
	return r, err
}

// ErrNotFound means no such row.
var ErrNotFound = errors.New("store: not found")

// GetRun returns one run.
func (s *Store) GetRun(ctx context.Context, id string) (Run, error) {
	r, err := scanRun(s.db.QueryRowContext(ctx, `SELECT `+runCols+` FROM runs WHERE id=?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return r, ErrNotFound
	}
	return r, err
}

// ListRuns returns the newest runs, optionally filtered by task and state.
func (s *Store) ListRuns(ctx context.Context, task, state string, limit int) ([]Run, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.db.QueryContext(ctx, `SELECT `+runCols+` FROM runs WHERE (?='' OR task=?) AND (?='' OR state=?) ORDER BY started_at DESC LIMIT ?`,
		task, task, state, state, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Run
	for rows.Next() {
		r, err := scanRun(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ActiveRun returns the queued or running run of a task, if any.
func (s *Store) ActiveRun(ctx context.Context, task string) (Run, bool, error) {
	r, err := scanRun(s.db.QueryRowContext(ctx, `SELECT `+runCols+` FROM runs WHERE task=? AND state IN (?, ?) ORDER BY started_at DESC LIMIT 1`, task, StateQueued, StateRunning))
	if errors.Is(err, sql.ErrNoRows) {
		return Run{}, false, nil
	}
	return r, err == nil, err
}

// CostSince sums the cost of a task's runs started after t.
func (s *Store) CostSince(ctx context.Context, task string, t time.Time) (float64, error) {
	var c float64
	err := s.db.QueryRowContext(ctx, `SELECT COALESCE(SUM(cost_usd),0) FROM runs WHERE (?='' OR task=?) AND started_at>=?`, task, task, ts(t)).Scan(&c)
	return c, err
}

// ConsecutiveFailures counts the latest runs of a task that ended with the
// given reason, stopping at the first that did not.
func (s *Store) ConsecutiveFailures(ctx context.Context, task, reason string) (int, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT state, reason FROM runs WHERE task=? AND state NOT IN (?, ?, ?) ORDER BY started_at DESC LIMIT 50`, task, StateQueued, StateRunning, StateSkipped)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		var state, r string
		if err := rows.Scan(&state, &r); err != nil {
			return 0, err
		}
		if state == StateFailed && r == reason {
			n++
			continue
		}
		break
	}
	return n, rows.Err()
}

// TaskSalt returns the active salt of a task, creating one on first use.
// It implements runner.SaltSource.
func (s *Store) TaskSalt(ctx context.Context, task string) (string, []byte, error) {
	var id, saltHex string
	err := s.db.QueryRowContext(ctx, `SELECT id, salt FROM task_salts WHERE task=? AND active=1 ORDER BY created_at DESC LIMIT 1`, task).Scan(&id, &saltHex)
	if err == nil {
		salt, err := hex.DecodeString(saltHex)
		return id, salt, err
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return "", nil, err
	}
	return s.RotateSalt(ctx, task)
}

// RotateSalt deactivates the current salt and creates a new one. Old
// pseudonym rows stay, so earlier results remain resolvable.
func (s *Store) RotateSalt(ctx context.Context, task string) (string, []byte, error) {
	salt, err := pseudo.NewSalt()
	if err != nil {
		return "", nil, err
	}
	now := time.Now()
	id := now.UTC().Format("20060102T150405Z")
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", nil, err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `UPDATE task_salts SET active=0 WHERE task=?`, task); err != nil {
		return "", nil, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO task_salts (id, task, salt, created_at, active) VALUES (?, ?, ?, ?, 1)`, task+"/"+id, task, hex.EncodeToString(salt), ts(now)); err != nil {
		return "", nil, err
	}
	return task + "/" + id, salt, tx.Commit()
}

// SavePseudonyms upserts the tokens a run minted.
func (s *Store) SavePseudonyms(ctx context.Context, m *pseudo.Map) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	stmt, err := tx.PrepareContext(ctx, `INSERT OR REPLACE INTO pseudonyms (task, salt_id, token, field, value) VALUES (?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for tok, val := range m.Tokens {
		if _, err := stmt.ExecContext(ctx, m.Task, m.SaltID, tok, m.Field(tok), val); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// LoadPseudonyms returns every token ever minted for a task, across salts,
// so any stored result can be resolved.
func (s *Store) LoadPseudonyms(ctx context.Context, task string) (*pseudo.Map, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT token, field, value FROM pseudonyms WHERE task=?`, task)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	m := pseudo.NewMap(task, "")
	for rows.Next() {
		var tok, field, val string
		if err := rows.Scan(&tok, &field, &val); err != nil {
			return nil, err
		}
		m.Add(tok, field, val)
	}
	return m, rows.Err()
}

// SaveResult stores both views of a result; clearJSON may be nil (leaked).
func (s *Store) SaveResult(ctx context.Context, runID, task string, finishedAt time.Time, pseudoJSON, clearJSON []byte) error {
	var clear any
	if clearJSON != nil {
		clear = string(clearJSON)
	}
	_, err := s.db.ExecContext(ctx, `INSERT OR REPLACE INTO results (run_id, task, finished_at, pseudo_json, clear_json) VALUES (?, ?, ?, ?, ?)`,
		runID, task, ts(finishedAt), string(pseudoJSON), clear)
	return err
}

// Result is a stored result.
type Result struct {
	RunID      string    `json:"runId"`
	Task       string    `json:"task"`
	FinishedAt time.Time `json:"finishedAt"`
	PseudoJSON []byte    `json:"-"`
	ClearJSON  []byte    `json:"-"`
}

// GetResult returns one result.
func (s *Store) GetResult(ctx context.Context, runID string) (Result, error) {
	var r Result
	var finished string
	var clear sql.NullString
	var pseudoJSON string
	err := s.db.QueryRowContext(ctx, `SELECT run_id, task, finished_at, pseudo_json, clear_json FROM results WHERE run_id=?`, runID).Scan(&r.RunID, &r.Task, &finished, &pseudoJSON, &clear)
	if errors.Is(err, sql.ErrNoRows) {
		return r, ErrNotFound
	}
	if err != nil {
		return r, err
	}
	r.FinishedAt = parseTS(finished)
	r.PseudoJSON = []byte(pseudoJSON)
	if clear.Valid {
		r.ClearJSON = []byte(clear.String)
	}
	return r, nil
}

// RecentResults returns a task's results finished after since, newest first.
func (s *Store) RecentResults(ctx context.Context, task string, since time.Time, limit int) ([]Result, error) {
	if limit <= 0 || limit > 200 {
		limit = 20
	}
	rows, err := s.db.QueryContext(ctx, `SELECT run_id, task, finished_at, pseudo_json, clear_json FROM results WHERE task=? AND finished_at>=? ORDER BY finished_at DESC LIMIT ?`, task, ts(since), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Result
	for rows.Next() {
		var r Result
		var finished, pj string
		var clear sql.NullString
		if err := rows.Scan(&r.RunID, &r.Task, &finished, &pj, &clear); err != nil {
			return nil, err
		}
		r.FinishedAt = parseTS(finished)
		r.PseudoJSON = []byte(pj)
		if clear.Valid {
			r.ClearJSON = []byte(clear.String)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// SaveLeaks records leak findings for a run.
func (s *Store) SaveLeaks(ctx context.Context, runID string, findings []pseudo.Finding) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, f := range findings {
		if _, err := tx.ExecContext(ctx, `INSERT INTO leaks (run_id, value, field, snippet, offset) VALUES (?, ?, ?, ?, ?)`, runID, f.Value, f.Field, f.Snippet, f.Offset); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// Leaks returns the findings of a run.
func (s *Store) Leaks(ctx context.Context, runID string) ([]pseudo.Finding, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT value, field, snippet, offset FROM leaks WHERE run_id=? ORDER BY offset`, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []pseudo.Finding
	for rows.Next() {
		var f pseudo.Finding
		if err := rows.Scan(&f.Value, &f.Field, &f.Snippet, &f.Offset); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// RunToken is a bearer token scope.
type RunToken struct {
	RunID     string
	Task      string
	ExpiresAt time.Time
}

// InsertRunToken stores a token hash.
func (s *Store) InsertRunToken(ctx context.Context, hash string, t RunToken) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO run_tokens (hash, run_id, task, expires_at) VALUES (?, ?, ?, ?)`, hash, t.RunID, t.Task, ts(t.ExpiresAt))
	return err
}

// LookupRunToken resolves a token hash to its scope if valid.
func (s *Store) LookupRunToken(ctx context.Context, hash string, now time.Time) (RunToken, bool, error) {
	var t RunToken
	var exp string
	err := s.db.QueryRowContext(ctx, `SELECT run_id, task, expires_at FROM run_tokens WHERE hash=? AND revoked=0`, hash).Scan(&t.RunID, &t.Task, &exp)
	if errors.Is(err, sql.ErrNoRows) {
		return t, false, nil
	}
	if err != nil {
		return t, false, err
	}
	t.ExpiresAt = parseTS(exp)
	if now.After(t.ExpiresAt) {
		return t, false, nil
	}
	return t, true, nil
}

// RevokeRunTokens revokes every token of a run.
func (s *Store) RevokeRunTokens(ctx context.Context, runID string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE run_tokens SET revoked=1 WHERE run_id=?`, runID)
	return err
}

// Prompt is what was sent to the model for a run.
type Prompt struct {
	RunID     string    `json:"runId"`
	Task      string    `json:"task"`
	CreatedAt time.Time `json:"createdAt"`
	SHA256    string    `json:"sha256"`
	Bytes     int       `json:"bytes"`
	System    string    `json:"system"`
	Prompt    string    `json:"prompt"`
	ArgvJSON  string    `json:"argvJson"`
}

// SavePrompt records the prompt of a run (one per run).
func (s *Store) SavePrompt(ctx context.Context, p Prompt) error {
	_, err := s.db.ExecContext(ctx, `INSERT OR REPLACE INTO prompts (run_id, task, created_at, sha256, bytes, system, prompt, argv_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		p.RunID, p.Task, ts(p.CreatedAt), p.SHA256, p.Bytes, p.System, p.Prompt, p.ArgvJSON)
	return err
}

// GetPrompt returns the prompt of a run.
func (s *Store) GetPrompt(ctx context.Context, runID string) (Prompt, error) {
	var p Prompt
	var created string
	err := s.db.QueryRowContext(ctx, `SELECT run_id, task, created_at, sha256, bytes, system, prompt, argv_json FROM prompts WHERE run_id=?`, runID).
		Scan(&p.RunID, &p.Task, &created, &p.SHA256, &p.Bytes, &p.System, &p.Prompt, &p.ArgvJSON)
	if errors.Is(err, sql.ErrNoRows) {
		return p, ErrNotFound
	}
	p.CreatedAt = parseTS(created)
	return p, err
}

// ListPrompts returns prompt headers (no bodies), newest first.
func (s *Store) ListPrompts(ctx context.Context, task string, limit int) ([]Prompt, error) {
	if limit <= 0 {
		limit = 30
	}
	rows, err := s.db.QueryContext(ctx, `SELECT run_id, task, created_at, sha256, bytes FROM prompts WHERE (?='' OR task=?) ORDER BY created_at DESC LIMIT ?`, task, task, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Prompt
	for rows.Next() {
		var p Prompt
		var created string
		if err := rows.Scan(&p.RunID, &p.Task, &created, &p.SHA256, &p.Bytes); err != nil {
			return nil, err
		}
		p.CreatedAt = parseTS(created)
		out = append(out, p)
	}
	return out, rows.Err()
}

// Delivery states.
const (
	DeliveryPending   = "pending"
	DeliveryDelivered = "delivered"
	DeliveryDead      = "dead"
	// DeliverySkipped means the sink declined the event by policy
	// (skipEmpty). LastError holds the reason.
	DeliverySkipped = "skipped"
)

// Delivery is one sink delivery attempt record.
type Delivery struct {
	ID        int64     `json:"id"`
	RunID     string    `json:"runId"`
	Sink      string    `json:"sink"`
	Kind      string    `json:"kind"`
	State     string    `json:"state"`
	Attempt   int       `json:"attempt"`
	NextAt    time.Time `json:"nextAt"`
	LastError string    `json:"lastError"`
	UpdatedAt time.Time `json:"updatedAt"`
}

// EnqueueDelivery adds a pending delivery.
func (s *Store) EnqueueDelivery(ctx context.Context, runID, sink, kind string, now time.Time) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO deliveries (run_id, sink, kind, state, attempt, next_at, updated_at) VALUES (?, ?, ?, ?, 0, ?, ?)`,
		runID, sink, kind, DeliveryPending, ts(now), ts(now))
	return err
}

// DueDeliveries returns pending deliveries whose next_at has passed.
func (s *Store) DueDeliveries(ctx context.Context, now time.Time, limit int) ([]Delivery, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, run_id, sink, kind, state, attempt, next_at, last_error, updated_at FROM deliveries WHERE state=? AND next_at<=? ORDER BY next_at LIMIT ?`, DeliveryPending, ts(now), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanDeliveries(rows)
}

// DeliveriesOf returns the deliveries of a run.
func (s *Store) DeliveriesOf(ctx context.Context, runID string) ([]Delivery, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, run_id, sink, kind, state, attempt, next_at, last_error, updated_at FROM deliveries WHERE run_id=? ORDER BY id`, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanDeliveries(rows)
}

func scanDeliveries(rows *sql.Rows) ([]Delivery, error) {
	var out []Delivery
	for rows.Next() {
		var d Delivery
		var next, upd string
		if err := rows.Scan(&d.ID, &d.RunID, &d.Sink, &d.Kind, &d.State, &d.Attempt, &next, &d.LastError, &upd); err != nil {
			return nil, err
		}
		d.NextAt = parseTS(next)
		d.UpdatedAt = parseTS(upd)
		out = append(out, d)
	}
	return out, rows.Err()
}

// UpdateDelivery writes the outcome of an attempt.
func (s *Store) UpdateDelivery(ctx context.Context, id int64, state string, attempt int, nextAt time.Time, lastErr string, now time.Time) error {
	_, err := s.db.ExecContext(ctx, `UPDATE deliveries SET state=?, attempt=?, next_at=?, last_error=?, updated_at=? WHERE id=?`, state, attempt, ts(nextAt), lastErr, ts(now), id)
	return err
}

// ResetDeliveries re-queues deliveries of a run (optionally one sink).
func (s *Store) ResetDeliveries(ctx context.Context, runID, sink string, now time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx, `UPDATE deliveries SET state=?, attempt=0, next_at=?, last_error='', updated_at=? WHERE run_id=? AND (?='' OR sink=?)`, DeliveryPending, ts(now), ts(now), runID, sink, sink)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// PruneRuns deletes terminal runs beyond keep per task or older than
// before, returning the ids removed so run directories can follow.
func (s *Store) PruneRuns(ctx context.Context, task string, keep int, before time.Time) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id FROM runs WHERE task=? AND state NOT IN (?, ?) ORDER BY started_at DESC`, task, StateQueued, StateRunning)
	if err != nil {
		return nil, err
	}
	var ids []string
	var starts []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		ids = append(ids, id)
	}
	rows.Close()
	_ = starts
	var doomed []string
	for i, id := range ids {
		r, err := s.GetRun(ctx, id)
		if err != nil {
			continue
		}
		if i >= keep || (!before.IsZero() && r.StartedAt.Before(before)) {
			doomed = append(doomed, id)
		}
	}
	for _, id := range doomed {
		if _, err := s.db.ExecContext(ctx, `DELETE FROM runs WHERE id=?`, id); err != nil {
			return doomed, err
		}
	}
	return doomed, nil
}
