package sink

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"text/template"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/scuq/ais/internal/config"
	"github.com/scuq/ais/internal/secret"
)

type natsSink struct {
	name    string
	url     string
	opts    []nats.Option
	subject *template.Template
	stream  config.NatsStreamSpec

	mu   sync.Mutex
	nc   *nats.Conn
	js   jetstream.JetStream
	init bool
}

func newNATS(name string, cfg config.SinkConfig, secrets secret.Store) (Sink, error) {
	url, err := secret.Expand(cfg.URL, secrets)
	if err != nil {
		return nil, fmt.Errorf("sink %q: %w", name, err)
	}
	var opts []nats.Option
	opts = append(opts, nats.Name("ais"), nats.MaxReconnects(-1))
	if cfg.CredsSecret != "" {
		creds, err := secrets.Get(cfg.CredsSecret)
		if err != nil {
			return nil, fmt.Errorf("sink %q: %w", name, err)
		}
		// nats.go wants a file; write the creds 0600 into a private dir.
		dir, err := os.MkdirTemp("", "ais-nats-")
		if err != nil {
			return nil, err
		}
		path := filepath.Join(dir, "user.creds")
		if err := os.WriteFile(path, []byte(creds+"\n"), 0o600); err != nil {
			return nil, err
		}
		opts = append(opts, nats.UserCredentials(path))
	}
	if cfg.TokenSecret != "" {
		tok, err := secrets.Get(cfg.TokenSecret)
		if err != nil {
			return nil, fmt.Errorf("sink %q: %w", name, err)
		}
		opts = append(opts, nats.Token(tok))
	}
	subj, err := template.New("subject").Funcs(tmplFuncs).Parse(orDefault(cfg.Subject, "ais.results.{{ .Task }}"))
	if err != nil {
		return nil, fmt.Errorf("sink %q: subject: %w", name, err)
	}
	return &natsSink{name: name, url: url, opts: opts, subject: subj, stream: cfg.Stream}, nil
}

func (n *natsSink) Name() string { return n.name }
func (n *natsSink) Type() string { return "nats" }

func (n *natsSink) connect(ctx context.Context) (jetstream.JetStream, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.js != nil && n.nc != nil && !n.nc.IsClosed() {
		return n.js, nil
	}
	nc, err := nats.Connect(n.url, n.opts...)
	if err != nil {
		return nil, err
	}
	js, err := jetstream.New(nc)
	if err != nil {
		nc.Close()
		return nil, err
	}
	if n.stream.Name != "" && !n.init {
		if _, err := js.CreateOrUpdateStream(ctx, jetstream.StreamConfig{Name: n.stream.Name, Subjects: n.stream.Subjects}); err != nil {
			nc.Close()
			return nil, fmt.Errorf("stream %s: %w", n.stream.Name, err)
		}
		n.init = true
	}
	n.nc, n.js = nc, js
	return js, nil
}

func (n *natsSink) Deliver(ctx context.Context, ev Event) error {
	subject, err := render(n.subject, ev)
	if err != nil {
		return Permanent{err}
	}
	subject = strings.TrimSpace(subject)
	body, err := json.Marshal(ev)
	if err != nil {
		return Permanent{err}
	}
	js, err := n.connect(ctx)
	if err != nil {
		return err
	}
	// The message id makes a retried publish idempotent on the server.
	_, err = js.Publish(ctx, subject, body, jetstream.WithMsgID(ev.RunID+"/"+ev.Kind+"/"+n.name))
	return err
}
