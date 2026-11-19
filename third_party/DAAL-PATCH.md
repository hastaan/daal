# third_party/sing-tun

An unmodified copy of `github.com/sagernet/sing-tun` v0.8.9 (the version
sing-box 1.13.12 requires; GPL-3.0, see `sing-tun/LICENSE`) with ONE
change, in `sing-tun/stack_gvisor_filter.go`:

`LinkEndpointFilter.Attach(nil)` now passes the `nil` on to the endpoint
it wraps. Upstream wrapped it in a non-nil filter, so `GVisor.Close()`'s
"detach" never reached the fd endpoint and the packet reader of a closed
sing-box instance was never stopped. On a TUN kept across a route switch
that reader took about half of the new instance's packets
(end-to-end rig finding SW-2); on a replaced TUN it held the old
interface open for ever.

Every Go module that links the engine's sing-box points here:

    replace github.com/sagernet/sing-tun => <relative path>/third_party/sing-tun

(`core`, `cmd/daal-core`, `cmd/daal-soak-engine`,
`test-rigs/worldbox/labclient`). A `replace` only applies in the module
being built, so a new module that builds the engine needs the line too;
`core/engine/singtun_detach_singbox_test.go` fails where it is missing.

To drop the copy: move to a sing-tun release that carries the fix,
delete the `replace` lines and this directory, and keep the test.

Check the copy against upstream:

    diff -r "$(go env GOMODCACHE)/github.com/sagernet/sing-tun@v0.8.9" third_party/sing-tun
