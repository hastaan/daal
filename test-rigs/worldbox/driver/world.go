package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// The address plan. Documentation/benchmark ranges on purpose: nothing
// here can collide with a real network, and none of it is RFC 1918 (so a
// "refuse private relay address" check anywhere in the product still
// sees a public-looking address).
//
//	[client] eth0 198.51.100.2 ── 198.51.100.1 [censor] 203.0.113.1 ── eth0 203.0.113.10 [relay1]
//	                                                                  eth1 192.0.2.2 ── 192.0.2.1 [internet]
//	                                               [publisher] eth0 198.18.0.2 ── 198.18.0.1 [internet]
//
// The relay is a HOST, not a router (ip_forward=0), so the only way from
// the client to anything in 192.0.2.0/24 is inside a tunnel the relay
// terminates. That is the structural negative control.
const (
	NSClient    = "client"
	NSCensor    = "censor"
	NSRelay1    = "relay1"
	NSInternet  = "internet"
	NSPublisher = "publisher"

	ClientIP       = "198.51.100.2"
	CensorClientIP = "198.51.100.1"
	CensorRelayIP  = "203.0.113.1"
	Relay1IP       = "203.0.113.10" // the relay's "public" address: what the cloud API reports and packs carry
	Relay1EgressIP = "192.0.2.2"    // what the target sees when traffic left through the relay
	InternetIP     = "192.0.2.1"
	TargetIP       = "192.0.2.80" // the blocked site
	CloudIP        = "192.0.2.20" // api.hetzner.cloud
	MirrorIP       = "192.0.2.30" // github.com (release artefact mirror)
	CoverIP        = "192.0.2.44" // every other website (what a REALITY cover host resolves to)
	DNSIP          = "192.0.2.53" // the resolver the box uses
	PublisherIP    = "198.18.0.2" // the outsider's laptop: the "helper IP"
	InternetPubIP  = "198.18.0.1"

	CensorDevClient = "to-client"
	CensorDevRelay  = "to-relay"
)

// Paths is every location the driver needs, resolved once.
type Paths struct {
	Repo string // repository root
	Rig  string // test-rigs/worldbox
	Bin  string // built binaries
	Run  string // this run's scratch + evidence directory
}

func (p Paths) Shims() string        { return filepath.Join(p.Rig, "box", "shims") }
func (p Paths) BoxInit() string      { return filepath.Join(p.Rig, "box", "init.py") }
func (p Paths) Logs() string         { return filepath.Join(p.Run, "logs") }
func (p Paths) Box(id string) string { return filepath.Join(p.Run, "boxes", id) }
func (p Paths) CA() string           { return filepath.Join(p.Run, "lab-ca.pem") }
func (p Paths) Hosts() string        { return filepath.Join(p.Run, "hosts") }

// sh runs a command in the world's root namespaces and returns combined
// output. Every namespace-plumbing step goes through here so a failure
// names the exact command.
func sh(ctx context.Context, argv ...string) (string, error) {
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	var buf bytes.Buffer
	cmd.Stdout, cmd.Stderr = &buf, &buf
	err := cmd.Run()
	if err != nil {
		return buf.String(), fmt.Errorf("%s: %w: %s", strings.Join(argv, " "), err, strings.TrimSpace(buf.String()))
	}
	return buf.String(), nil
}

// inNS prefixes argv so it runs inside a named network namespace.
func inNS(ns string, argv ...string) []string {
	return append([]string{"ip", "netns", "exec", ns}, argv...)
}

// BringUp builds the namespaces, links, addresses and routes. It assumes
// it is running as "root" of a private user+net+mount namespace.
func BringUp(ctx context.Context, p Paths) error {
	if os.Getpid() != 1 {
		return fmt.Errorf("wb run must be PID 1 of its own pid namespace (use run.sh); refusing to build a world that would not be torn down with me")
	}
	steps := [][]string{
		// `ip netns` wants a writable /run/netns; ours is private to this mount namespace.
		{"mount", "-t", "tmpfs", "tmpfs", "/run"},
		{"mkdir", "-p", "/run/netns"},
	}
	for _, ns := range []string{NSClient, NSCensor, NSRelay1, NSInternet, NSPublisher} {
		steps = append(steps, []string{"ip", "netns", "add", ns})
		steps = append(steps, inNS(ns, "ip", "link", "set", "lo", "up"))
	}
	link := func(nsA, devA, nsB, devB string) {
		steps = append(steps, []string{"ip", "link", "add", devA, "netns", nsA, "type", "veth", "peer", "name", devB, "netns", nsB})
	}
	addr := func(ns, dev string, cidrs ...string) {
		for _, c := range cidrs {
			steps = append(steps, inNS(ns, "ip", "addr", "add", c, "dev", dev))
		}
		steps = append(steps, inNS(ns, "ip", "link", "set", dev, "up"))
	}
	link(NSClient, "eth0", NSCensor, CensorDevClient)
	link(NSCensor, CensorDevRelay, NSRelay1, "eth0")
	link(NSRelay1, "eth1", NSInternet, "r1")
	link(NSPublisher, "eth0", NSInternet, "pub")

	addr(NSClient, "eth0", ClientIP+"/24")
	addr(NSCensor, CensorDevClient, CensorClientIP+"/24")
	addr(NSCensor, CensorDevRelay, CensorRelayIP+"/24")
	addr(NSRelay1, "eth0", Relay1IP+"/24")
	addr(NSRelay1, "eth1", Relay1EgressIP+"/24")
	addr(NSInternet, "r1", InternetIP+"/24", TargetIP+"/24", CloudIP+"/24", MirrorIP+"/24", CoverIP+"/24", DNSIP+"/24")
	// The two public resolvers the phone's VpnService configures (resolver.go).
	addr(NSInternet, "lo", PublicDNS1+"/32", PublicDNS2+"/32")
	addr(NSInternet, "pub", InternetPubIP+"/24")
	addr(NSPublisher, "eth0", PublisherIP+"/24")

	steps = append(steps,
		inNS(NSClient, "ip", "route", "add", "default", "via", CensorClientIP),
		// The censor is the client's ISP: it routes between the client and
		// the relay's network and NOWHERE else.
		inNS(NSCensor, "sysctl", "-qw", "net.ipv4.ip_forward=1"),
		// Everything that is not the relay's network goes nowhere, and
		// says so at once: an explicit reject (wb_isp, below) instead of
		// the kernel's "no route" error, which is rate-limited to one a
		// second and would make every negative control cost a timeout.
		inNS(NSCensor, "sysctl", "-qw", "net.ipv4.icmp_ratelimit=0"),
		inNS(NSCensor, "ip", "link", "add", "nowhere", "type", "dummy"),
		inNS(NSCensor, "ip", "link", "set", "nowhere", "up"),
		inNS(NSCensor, "ip", "route", "add", "default", "dev", "nowhere"),
		inNS(NSCensor, "nft", "add table inet wb_isp; add chain inet wb_isp forward { type filter hook forward priority 10; }; "+
			"add rule inet wb_isp forward oifname nowhere reject with icmpx type no-route"),
		inNS(NSRelay1, "ip", "route", "add", "default", "via", InternetIP),
		inNS(NSRelay1, "ip", "route", "add", "198.51.100.0/24", "via", CensorRelayIP),
		inNS(NSRelay1, "sysctl", "-qw", "net.ipv4.ip_forward=0"),
		inNS(NSInternet, "sysctl", "-qw", "net.ipv4.ip_forward=1"),
		inNS(NSInternet, "ip", "route", "add", "203.0.113.0/24", "via", Relay1EgressIP),
		inNS(NSPublisher, "ip", "route", "add", "default", "via", InternetPubIP),
	)
	for _, s := range steps {
		if _, err := sh(ctx, s...); err != nil {
			return err
		}
	}
	// Name resolution for the two outside services the unmodified
	// binaries insist on by name.
	base, _ := os.ReadFile("/etc/hosts")
	hosts := strings.TrimRight(string(base), "\n") + "\n" + strings.Join(LabHosts(), "\n") + "\n"
	return os.WriteFile(p.Hosts(), []byte(hosts), 0o644)
}

// LabHosts are the /etc/hosts lines that point real hostnames at the lab.
func LabHosts() []string {
	return []string{
		CloudIP + " api.hetzner.cloud",
		MirrorIP + " github.com",
	}
}

// Proc is a long-lived role process started by the driver.
type Proc struct {
	Name string
	Cmd  *exec.Cmd
	Log  string
}

// Spawn starts argv with stdout+stderr appended to logs/<name>.log.
func Spawn(p Paths, name string, env []string, argv ...string) (*Proc, error) {
	logPath := filepath.Join(p.Logs(), name+".log")
	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, err
	}
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Stdout, cmd.Stderr = f, f
	cmd.Env = append(os.Environ(), env...)
	if err := cmd.Start(); err != nil {
		f.Close()
		return nil, fmt.Errorf("spawn %s: %w", name, err)
	}
	f.Close()
	return &Proc{Name: name, Cmd: cmd, Log: logPath}, nil
}

// waitFor polls cond until it is true or the deadline passes.
func waitFor(ctx context.Context, d time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(50 * time.Millisecond):
		}
	}
	return cond()
}

// CollectEvidence trims each box directory down to what is worth
// keeping after the run: the box's /etc as the product left it
// (etc-upper), its logs (rootfs/var/log) and the rig's state markers stay;
// the ~100 MB of downloaded binaries and scratch do not (their hashes are
// in results.jsonl).
func CollectEvidence(p Paths) {
	boxes, _ := filepath.Glob(filepath.Join(p.Run, "boxes", "*"))
	for _, b := range boxes {
		for _, sub := range []string{"rootfs/usr/local/bin", "rootfs/tmp", "state/overrides", "etc-work"} {
			_ = os.RemoveAll(filepath.Join(b, sub))
		}
	}
}
