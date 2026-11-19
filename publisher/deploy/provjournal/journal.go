// Package provjournal is the on-disk provision journal: one JSON object
// per line, fsynced line by line, under an exclusive advisory lock held
// for the life of the provisioning process.
//
// The wizard passes `provision --journal <path>`. The file outlives the
// process — that is the point: when the app (and the provisioning child
// with it) is killed after a server was created, the next launch reads
// this file to learn which server exists, on which port it was going to
// be managed, and whether the run finished. The lock tells the next
// launch whether a run is still going (desktop, where the child can
// outlive the app); the kernel drops it when the process dies, however
// it dies.
//
// Format v1, common fields v, ev, seq (1-based per process run), ts
// (RFC3339 UTC). Events: begin, intent, created, deleted, phase, done,
// failed. See the publisher-alone wave contract, section D1-GO.
//
// Nothing secret is ever written here: the API token, the provisioning
// health token and every private key stay out. The only key that
// appears is the PUBLIC publisher key, base64.
package provjournal

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"daal/publisher/deploy/provider"
)

// ErrBusy is returned by Open when another live process holds the lock.
var ErrBusy = errors.New("provjournal: another setup is still writing this journal")

// Static is what the CLI knows before the adapter runs; it goes on the
// begin line next to what the adapter resolves.
type Static struct {
	Provider         string
	Region           string
	ServerType       string
	ToolboxProfile   string
	PublisherPubKey  []byte
	ExistingServerID string
}

// Journal is an open, locked journal file. It implements
// provider.ProvisionJournal and adds the CLI-level Done/Failed events.
type Journal struct {
	mu     sync.Mutex
	f      *os.File
	seq    int
	static Static
	now    func() time.Time
	// warn is told when a non-fatal line (created/deleted/phase) could
	// not be written; the CLI turns it into a journal_warning progress
	// line.
	warn func(ev string, err error)

	createdServers map[string]bool
	rolledBack     bool
}

// Open opens (creating with mode 0600) and exclusively locks path. A
// held lock is ErrBusy; anything else that stops the file being opened,
// locked or written is returned as-is. On first creation the parent
// directory is fsynced so the file's existence survives a power cut.
func Open(path string, st Static, warn func(ev string, err error)) (*Journal, error) {
	if path == "" {
		return nil, errors.New("provjournal: empty path")
	}
	_, statErr := os.Stat(path)
	fresh := errors.Is(statErr, os.ErrNotExist)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("provjournal: open %s: %w", path, err)
	}
	if err := lockExclusive(f); err != nil {
		f.Close()
		return nil, err
	}
	if fresh {
		if d, err := os.Open(filepath.Dir(path)); err == nil {
			_ = d.Sync()
			d.Close()
		}
	}
	if warn == nil {
		warn = func(string, error) {}
	}
	return &Journal{f: f, static: st, now: time.Now, warn: warn, createdServers: map[string]bool{}}, nil
}

// SetClock is a test seam.
func (j *Journal) SetClock(now func() time.Time) { j.now = now }

// Close releases the lock and the file. Safe on nil.
func (j *Journal) Close() error {
	if j == nil || j.f == nil {
		return nil
	}
	err := j.f.Close()
	j.f = nil
	return err
}

func (j *Journal) write(ev string, fields map[string]any) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.f == nil {
		return errors.New("provjournal: closed")
	}
	j.seq++
	line := map[string]any{
		"v":   1,
		"ev":  ev,
		"seq": j.seq,
		"ts":  j.now().UTC().Format(time.RFC3339),
	}
	for k, v := range fields {
		line[k] = v
	}
	body, err := json.Marshal(line)
	if err != nil {
		return fmt.Errorf("provjournal: encode %s: %w", ev, err)
	}
	body = append(body, '\n')
	if _, err := j.f.Write(body); err != nil {
		return fmt.Errorf("provjournal: write %s: %w", ev, err)
	}
	if err := j.f.Sync(); err != nil {
		return fmt.Errorf("provjournal: sync %s: %w", ev, err)
	}
	return nil
}

// Begin implements provider.ProvisionJournal.
func (j *Journal) Begin(mode, relayName string, mgmtPort int, coverSNI string) error {
	return j.write("begin", map[string]any{
		"pid":                os.Getpid(),
		"provider":           j.static.Provider,
		"region":             j.static.Region,
		"server_type":        j.static.ServerType,
		"toolbox_profile":    j.static.ToolboxProfile,
		"relay_name":         relayName,
		"publisher_pub_key":  base64.StdEncoding.EncodeToString(j.static.PublisherPubKey),
		"mgmt_port":          mgmtPort,
		"cover_sni":          coverSNI,
		"existing_server_id": j.static.ExistingServerID,
		"mode":               mode,
	})
}

// Intent implements provider.ProvisionJournal.
func (j *Journal) Intent(kind, name, id string) error {
	fields := map[string]any{"kind": kind, "name": name}
	if id != "" {
		fields["id"] = id
	}
	return j.write("intent", fields)
}

// Created implements provider.ProvisionJournal.
func (j *Journal) Created(kind, id, name string, publicIP net.IP) {
	fields := map[string]any{"kind": kind, "id": id, "name": name}
	if kind == provider.KindServer || kind == provider.JournalKindRebuild {
		ip := ""
		if len(publicIP) > 0 {
			ip = publicIP.String()
		}
		fields["public_ip"] = ip
	}
	if kind == provider.KindServer {
		j.mu.Lock()
		j.createdServers[id] = true
		j.mu.Unlock()
	}
	if err := j.write("created", fields); err != nil {
		j.warn("created", err)
	}
}

// Deleted implements provider.ProvisionJournal.
func (j *Journal) Deleted(kind, id string) {
	if kind == provider.KindServer {
		j.mu.Lock()
		if j.createdServers[id] {
			j.rolledBack = true
		}
		j.mu.Unlock()
	}
	if err := j.write("deleted", map[string]any{"kind": kind, "id": id}); err != nil {
		j.warn("deleted", err)
	}
}

// Phase implements provider.ProvisionJournal.
func (j *Journal) Phase(step string) {
	if err := j.write("phase", map[string]any{"step": step}); err != nil {
		j.warn("phase", err)
	}
}

// Done records the finished OperatorRecord. The caller writes it BEFORE
// anything reaches stdout: a run killed between the two must still leave
// the record behind, so the app can save it without renting anything.
func (j *Journal) Done(rec *provider.OperatorRecord) error {
	raw, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("provjournal: encode record: %w", err)
	}
	return j.write("done", map[string]any{"record": json.RawMessage(raw)})
}

// Failed records a non-zero exit. rolled_back is true when this run
// created a server and then deleted it again.
func (j *Journal) Failed(code string) error {
	j.mu.Lock()
	rb := j.rolledBack
	j.mu.Unlock()
	return j.write("failed", map[string]any{"code": code, "rolled_back": rb})
}

var _ provider.ProvisionJournal = (*Journal)(nil)
