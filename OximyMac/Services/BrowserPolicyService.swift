import Foundation

/// Manages browser proxy policies for Chrome and Edge on macOS.
/// Writes managed preferences to enforce proxy settings at the browser level,
/// preventing VPN extensions from overriding the system proxy.
class BrowserPolicyService {
    static let shared = BrowserPolicyService()

    private static let chromeBundleId = "com.google.Chrome"
    private static let edgeBundleId = "com.microsoft.Edge"
    private static let managedPrefsDir = "/Library/Managed Preferences"

    private init() {}

    /// Enable browser proxy policies for the given port.
    /// Checks if policies already exist with correct port to minimize admin prompts.
    func enablePolicies(port: Int) async throws {
        // Skip if policies already installed with correct port
        guard !arePoliciesInstalled(forPort: port) else {
            NSLog("[BrowserPolicyService] Policies already installed for port %d, skipping", port)
            return
        }

        NSLog("[BrowserPolicyService] Installing browser policies for port %d", port)

        let proxyServer = "127.0.0.1:\(port)"
        let bypassList = "localhost,127.0.0.1,*.local,169.254/16"

        // Build plist content for both browsers
        let plistContent = buildPlistContent(proxyServer: proxyServer, bypassList: bypassList)

        // Write policies for Chrome and Edge
        try await writeManagedPreferences(bundleId: Self.chromeBundleId, content: plistContent)
        try await writeManagedPreferences(bundleId: Self.edgeBundleId, content: plistContent)

        NSLog("[BrowserPolicyService] Browser policies installed successfully")
    }

    /// Remove browser proxy policies
    func disablePolicies() async throws {
        NSLog("[BrowserPolicyService] Removing browser policies")

        try await removeManagedPreferences(bundleId: Self.chromeBundleId)
        try await removeManagedPreferences(bundleId: Self.edgeBundleId)

        NSLog("[BrowserPolicyService] Browser policies removed")
    }

    /// Check if policies are installed with the correct port
    func arePoliciesInstalled(forPort port: Int) -> Bool {
        let expectedServer = "127.0.0.1:\(port)"

        for bundleId in [Self.chromeBundleId, Self.edgeBundleId] {
            let plistPath = "\(Self.managedPrefsDir)/\(bundleId).plist"

            guard FileManager.default.fileExists(atPath: plistPath),
                  let dict = NSDictionary(contentsOfFile: plistPath),
                  let proxyMode = dict["ProxyMode"] as? String,
                  proxyMode == "fixed_servers",
                  let proxyServer = dict["ProxyServer"] as? String,
                  proxyServer == expectedServer else {
                return false
            }
        }

        return true
    }

    /// Clean up orphaned policies on app startup.
    /// If policies exist but our proxy port is dead, remove them to prevent broken browsing.
    func cleanupOrphanedPolicies() {
        for bundleId in [Self.chromeBundleId, Self.edgeBundleId] {
            let plistPath = "\(Self.managedPrefsDir)/\(bundleId).plist"

            guard FileManager.default.fileExists(atPath: plistPath),
                  let dict = NSDictionary(contentsOfFile: plistPath),
                  let proxyMode = dict["ProxyMode"] as? String,
                  proxyMode == "fixed_servers",
                  let proxyServer = dict["ProxyServer"] as? String else {
                continue
            }

            // Extract port from "127.0.0.1:PORT"
            let components = proxyServer.components(separatedBy: ":")
            guard components.count == 2, let port = Int(components[1]) else { continue }

            // Check if port is alive
            if !isPortListening(port) {
                NSLog("[BrowserPolicyService] FAIL-OPEN: Found orphaned browser policy for %@ pointing to dead port %d - cleaning up", bundleId, port)

                // Try to remove without admin first
                if removeWithoutAdmin(bundleId: bundleId) {
                    NSLog("[BrowserPolicyService] Orphaned policy removed without admin prompt")
                } else {
                    // Need admin - attempt async removal
                    Task {
                        do {
                            try await self.removeManagedPreferences(bundleId: bundleId)
                            NSLog("[BrowserPolicyService] Orphaned policy removed with admin prompt")
                        } catch {
                            NSLog("[BrowserPolicyService] Failed to remove orphaned policy: %@", error.localizedDescription)
                        }
                    }
                }
            }
        }
    }

    // MARK: - Private Helpers

    private func buildPlistContent(proxyServer: String, bypassList: String) -> [String: Any] {
        return [
            "ProxyMode": "fixed_servers",
            "ProxyServer": proxyServer,
            "ProxyBypassList": bypassList
        ]
    }

    /// Write managed preferences using osascript with admin privileges
    private func writeManagedPreferences(bundleId: String, content: [String: Any]) async throws {
        let plistPath = "\(Self.managedPrefsDir)/\(bundleId).plist"

        // Create a temporary plist file
        let tempDir = FileManager.default.temporaryDirectory
        let tempPlist = tempDir.appendingPathComponent("\(bundleId).plist")

        let dict = NSDictionary(dictionary: content)
        guard dict.write(toFile: tempPlist.path, atomically: true) else {
            throw BrowserPolicyError.writeFailed("Failed to create temporary plist")
        }

        // Use osascript to copy with admin privileges
        let script = """
        do shell script "mkdir -p '\(Self.managedPrefsDir)' && cp '\(tempPlist.path)' '\(plistPath)' && chmod 644 '\(plistPath)'" with administrator privileges
        """

        try await runOsascript(script)

        // Clean up temp file
        try? FileManager.default.removeItem(at: tempPlist)
    }

    /// Remove managed preferences using osascript with admin privileges
    private func removeManagedPreferences(bundleId: String) async throws {
        let plistPath = "\(Self.managedPrefsDir)/\(bundleId).plist"

        guard FileManager.default.fileExists(atPath: plistPath) else { return }

        let script = """
        do shell script "rm -f '\(plistPath)'" with administrator privileges
        """

        try await runOsascript(script)
    }

    /// Try to remove without admin (will fail if permissions don't allow)
    private func removeWithoutAdmin(bundleId: String) -> Bool {
        let plistPath = "\(Self.managedPrefsDir)/\(bundleId).plist"
        do {
            try FileManager.default.removeItem(atPath: plistPath)
            return true
        } catch {
            return false
        }
    }

    /// Run an AppleScript command asynchronously (does not block cooperative thread)
    private func runOsascript(_ script: String) async throws {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
        process.arguments = ["-e", script]

        let errorPipe = Pipe()
        process.standardOutput = FileHandle.nullDevice
        process.standardError = errorPipe

        return try await withCheckedThrowingContinuation { continuation in
            process.terminationHandler = { _ in
                if process.terminationStatus != 0 {
                    let errorData = errorPipe.fileHandleForReading.readDataToEndOfFile()
                    let errorMsg = String(data: errorData, encoding: .utf8) ?? "Unknown error"

                    if errorMsg.contains("User canceled") || errorMsg.contains("-128") {
                        continuation.resume(throwing: BrowserPolicyError.userCancelled)
                    } else {
                        continuation.resume(throwing: BrowserPolicyError.adminRequired(errorMsg))
                    }
                } else {
                    continuation.resume()
                }
            }

            do {
                try process.run()
            } catch {
                continuation.resume(throwing: BrowserPolicyError.writeFailed(error.localizedDescription))
            }
        }
    }

    /// Run an osascript command synchronously (for use during app termination)
    private func runOsascriptSync(_ script: String) throws {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
        process.arguments = ["-e", script]
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice

        try process.run()
        process.waitUntilExit()
    }

    /// Best-effort synchronous removal of browser policies (for use during app termination).
    /// Does not require admin — if removal fails, startup cleanup will handle it.
    func disablePoliciesSync() {
        for bundleId in [Self.chromeBundleId, Self.edgeBundleId] {
            let plistPath = "\(Self.managedPrefsDir)/\(bundleId).plist"
            guard FileManager.default.fileExists(atPath: plistPath) else { continue }

            // Try without admin first (will likely fail for /Library/Managed Preferences)
            if removeWithoutAdmin(bundleId: bundleId) {
                NSLog("[BrowserPolicyService] Removed %@ policy during shutdown (no admin)", bundleId)
                continue
            }

            // Try with osascript sync — best effort, may not complete in time
            let script = "do shell script \"rm -f '\(plistPath)'\" with administrator privileges"
            do {
                try runOsascriptSync(script)
                NSLog("[BrowserPolicyService] Removed %@ policy during shutdown (admin)", bundleId)
            } catch {
                NSLog("[BrowserPolicyService] Could not remove %@ policy during shutdown — startup cleanup will handle it", bundleId)
            }
        }
    }

    /// Check if a port is listening
    private func isPortListening(_ port: Int) -> Bool {
        let socketFD = socket(AF_INET, SOCK_STREAM, 0)
        guard socketFD >= 0 else { return false }
        defer { close(socketFD) }

        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = in_port_t(port).bigEndian
        addr.sin_addr.s_addr = inet_addr("127.0.0.1")

        let connectResult = withUnsafePointer(to: &addr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockaddrPtr in
                connect(socketFD, sockaddrPtr, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }

        return connectResult == 0
    }
}

// MARK: - Errors

enum BrowserPolicyError: LocalizedError {
    case writeFailed(String)
    case adminRequired(String)
    case userCancelled

    var errorDescription: String? {
        switch self {
        case .writeFailed(let reason):
            return "Failed to write browser policy: \(reason)"
        case .adminRequired(let reason):
            return "Admin privileges required: \(reason)"
        case .userCancelled:
            return "User cancelled admin authorization"
        }
    }
}
