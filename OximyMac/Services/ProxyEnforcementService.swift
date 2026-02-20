import Foundation

/// Detects and recovers from proxy tamper events.
/// When enforcement is active, polls system proxy settings every 5 seconds
/// and re-enables the proxy if it was disabled externally.
@MainActor
class ProxyEnforcementService: ObservableObject {
    static let shared = ProxyEnforcementService()

    @Published var isEnforcing = false
    @Published var tamperCount = 0

    private var timer: Timer?
    private var expectedPort: Int?
    private static let pollInterval: TimeInterval = 5.0

    private init() {}

    /// Start enforcing proxy settings
    func startEnforcement(port: Int) {
        guard !isEnforcing else { return }
        expectedPort = port
        isEnforcing = true
        tamperCount = 0

        NSLog("[ProxyEnforcementService] Starting enforcement on port %d", port)

        timer = Timer.scheduledTimer(withTimeInterval: Self.pollInterval, repeats: true) { [weak self] _ in
            Task { @MainActor [weak self] in
                await self?.checkAndEnforce()
            }
        }
    }

    /// Stop enforcing proxy settings
    func stopEnforcement() {
        timer?.invalidate()
        timer = nil
        expectedPort = nil
        isEnforcing = false
        NSLog("[ProxyEnforcementService] Stopped enforcement")
    }

    /// Check current proxy state and re-enable if tampered
    private func checkAndEnforce() async {
        guard let expectedPort = expectedPort else { return }

        // Use ProxyService to check current state
        let proxyService = ProxyService.shared
        proxyService.checkStatus()

        // If proxy is disabled or on wrong port, it was tampered
        if !proxyService.isProxyEnabled || proxyService.configuredPort != expectedPort {
            tamperCount += 1
            NSLog("[ProxyEnforcementService] Tamper detected (count: %d) - re-enabling proxy on port %d", tamperCount, expectedPort)

            do {
                try await proxyService.enableProxy(port: expectedPort)
                try await proxyService.setBypassList(ProxyService.defaultBypassList)

                // Also re-apply browser policies if they were tampered with
                if !BrowserPolicyService.shared.arePoliciesInstalled(forPort: expectedPort) {
                    try await BrowserPolicyService.shared.enablePolicies(port: expectedPort)
                    NSLog("[ProxyEnforcementService] Browser policies re-applied after tamper detection")
                }

                NSLog("[ProxyEnforcementService] Proxy re-enabled successfully")

                OximyLogger.shared.log(.PROXY_ENFORCE_001, "Proxy tamper detected and recovered", data: [
                    "tamper_count": tamperCount,
                    "port": expectedPort
                ])
            } catch {
                NSLog("[ProxyEnforcementService] Failed to re-enable proxy: %@", error.localizedDescription)
            }
        }
    }
}
