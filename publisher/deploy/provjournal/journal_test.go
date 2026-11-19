package provjournal

import (
	"bufio"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"daal/publisher/deploy/provider"
)

func lines(t *testing.T, path string) []map[string]any {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out []map[string]any
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var m map[string]any
		if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
			t.Fatalf("line is not one JSON object: %q", sc.Text())
		}
		out = append(out, m)
	}
	return out
}

func TestJournal_LinesSeqModeAndRolledBack(t *testing.T) {
	path := filepath.Join(t.TempDir(), "op.jsonl")
	j, err := Open(path, Static{Provider: "hetzner", Region: "fsn1", PublisherPubKey: []byte{1, 2, 3}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := j.Begin(provider.ModeCreate, "daal-fsn1-00", 23456, "www.example.org"); err != nil {
		t.Fatal(err)
	}
	if err := j.Intent(provider.KindServer, "daal-fsn1-00", ""); err != nil {
		t.Fatal(err)
	}
	j.Created(provider.KindServer, "123", "daal-fsn1-00", net.ParseIP("203.0.113.7"))
	j.Deleted(provider.KindServer, "123")
	if err := j.Failed(provider.CodeHealthTimeout); err != nil {
		t.Fatal(err)
	}
	j.Close()

	ls := lines(t, path)
	evs := []string{}
	for i, l := range ls {
		evs = append(evs, l["ev"].(string))
		if l["seq"] != float64(i+1) || l["v"] != float64(1) || l["ts"] == "" {
			t.Errorf("line %d header: %v", i, l)
		}
	}
	if strings.Join(evs, ",") != "begin,intent,created,deleted,failed" {
		t.Fatalf("events = %v", evs)
	}
	if ls[0]["publisher_pub_key"] != "AQID" || ls[0]["mgmt_port"] != float64(23456) || ls[0]["mode"] != "create" {
		t.Errorf("begin = %v", ls[0])
	}
	if ls[2]["public_ip"] != "203.0.113.7" {
		t.Errorf("created = %v", ls[2])
	}
	if ls[4]["rolled_back"] != true || ls[4]["code"] != "health_timeout" {
		t.Errorf("failed = %v", ls[4])
	}
	if runtime.GOOS != "windows" {
		st, _ := os.Stat(path)
		if st.Mode().Perm() != 0o600 {
			t.Errorf("journal mode = %v, want 0600", st.Mode().Perm())
		}
	}
}

func TestJournal_ASecondWriterIsBusyUntilTheFirstCloses(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no flock")
	}
	path := filepath.Join(t.TempDir(), "op.jsonl")
	j, err := Open(path, Static{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path, Static{}, nil); !errors.Is(err, ErrBusy) {
		t.Fatalf("second open: %v, want ErrBusy", err)
	}
	j.Close()
	j2, err := Open(path, Static{}, nil)
	if err != nil {
		t.Fatalf("lock not released on close: %v", err)
	}
	j2.Close()
}

func TestJournal_ANewRunAppendsAndRestartsSeq(t *testing.T) {
	path := filepath.Join(t.TempDir(), "op.jsonl")
	for i := 0; i < 2; i++ {
		j, err := Open(path, Static{}, nil)
		if err != nil {
			t.Fatal(err)
		}
		_ = j.Begin(provider.ModeCreate, "r", 1, "")
		j.Close()
	}
	ls := lines(t, path)
	if len(ls) != 2 || ls[0]["seq"] != float64(1) || ls[1]["seq"] != float64(1) {
		t.Fatalf("lines = %v", ls)
	}
}
