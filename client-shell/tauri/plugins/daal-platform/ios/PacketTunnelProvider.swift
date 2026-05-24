// Phase 2E. The Network-Extension entry point. iOS hands packets
// in on `packetFlow.readPackets` and accepts return packets via
// `packetFlow.writePackets`. The bridge forwards both directions
// to Libbox.
//
// Lifecycle: `startTunnel` calls `engine_init` against the App
// Group state directory, applies the active route, and starts the
// memory sampler that drives the WireGuard sub-engine handoff.
// `stopTunnel` does the reverse.

import Foundation
import NetworkExtension

public final class PacketTunnelProvider: NEPacketTunnelProvider {
    private let bridge: EngineBridge = LibboxImpl()
    private let memorySampler = MemorySampler()
    private var wgSubEngine: WireguardSubEngine?

    /// The App Group container holds `state/` (engine SQLite +
    /// secrets KV). Both targets resolve to the same directory.
    private var appGroupStateDir: String {
        guard let url = FileManager.default
            .containerURL(forSecurityApplicationGroupIdentifier:
                "group.org.daal-project.shared")
        else {
            // Fallback to the extension's own container — degraded
            // mode, will not share state with the host app. The
            // PIN unlock UX in the host app will not have effect
            // on this run; we still ship and let the user know via
            // diagnostics that the App Group is misconfigured.
            return NSTemporaryDirectory() + "daal-fallback"
        }
        return url.appendingPathComponent("state").path
    }

    public override func startTunnel(
        options: [String: NSObject]?,
        completionHandler: @escaping (Error?) -> Void
    ) {
        do {
            try bridge.initialize(stateDir: appGroupStateDir, logLevel: "warn")
        } catch {
            completionHandler(error)
            return
        }

        // Tell the engine the network kind. iOS deliberately passes
        // empty carrier+SSID — see specs/ios-build-v1.md.
        try? bridge.networkChanged(kind: "wifi", carrier: "", ssid: "")

        // Start the 1 Hz memory sampler. On the 38 MiB watermark
        // crossing it asks the active WG sub-engine to hand off.
        memorySampler.onWatermark = { [weak self] in
            guard let self = self, let sub = self.wgSubEngine else { return }
            // Fire the lifecycle event for diagnostics, then ask
            // the sub-engine to hand off. The handoff is one-way
            // per session — sub-engine impls track this themselves.
            try? self.bridge.lifecycleEvent("memory_pressure_warning")
            sub.requestHandoff()
        }
        memorySampler.start()

        // Default sub-engine is the in-Libbox WG. The boringtun
        // impl is constructed lazily on the first handoff request
        // so its FFI archive is not paged in for non-WG sessions.
        wgSubEngine = WireguardLibboxImpl(bridge: bridge)

        // Engine is up; let the OS know we are ready to accept
        // packets. Real tunnel-network-settings application is
        // owned by Libbox via the gomobile facade once we expose
        // an iOS-side packet-flow shim; at scaffold stage we
        // accept the call with default settings.
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "127.0.0.1")
        setTunnelNetworkSettings(settings) { error in
            completionHandler(error)
        }
    }

    public override func stopTunnel(
        with reason: NEProviderStopReason,
        completionHandler: @escaping () -> Void
    ) {
        memorySampler.stop()
        wgSubEngine = nil
        try? bridge.shutdown()
        completionHandler()
    }

    public override func sleep(completionHandler: @escaping () -> Void) {
        try? bridge.lifecycleEvent("will_sleep")
        completionHandler()
    }

    public override func wake() {
        try? bridge.lifecycleEvent("did_wake")
    }

    public override func handleAppMessage(
        _ messageData: Data,
        completionHandler: ((Data?) -> Void)?
    ) {
        // Diagnostics fetch is the v1 message kind. Host app sends
        // an empty `Data()`, gets diagnostics JSON back.
        let diag = bridge.exportDiagnostics()
        completionHandler?(diag.data(using: .utf8))
    }
}
