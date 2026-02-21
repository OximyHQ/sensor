import SwiftUI

struct SettingsTab: View {
    @EnvironmentObject var appState: AppState
    @StateObject private var certService = CertificateService.shared
    @StateObject private var proxyService = ProxyService.shared

    var body: some View {
        ScrollView {
            VStack(spacing: 12) {
                // Certificate Section
                SettingsSection(title: "Certificate", icon: "lock.shield.fill") {
                    HStack {
                        VStack(alignment: .leading, spacing: 2) {
                            Text("Oximy CA")
                                .font(.subheadline)
                                .fontWeight(.medium)
                            Text(certService.isCAInstalled ? "Installed & Trusted" : "Not installed")
                                .font(.caption)
                                .foregroundColor(certService.isCAInstalled ? .secondary : .orange)
                        }

                        Spacer()

                        Image(systemName: certService.isCAInstalled ? "checkmark.circle.fill" : "exclamationmark.triangle.fill")
                            .foregroundColor(certService.isCAInstalled ? .green : .orange)
                    }
                }

                // Account Section
                SettingsSection(title: "Account", icon: "person.circle.fill") {
                    if appState.isLoggedIn {
                        HStack {
                            VStack(alignment: .leading, spacing: 2) {
                                Text(appState.workspaceName.isEmpty ? "Connected" : appState.workspaceName)
                                    .font(.subheadline)
                                    .fontWeight(.medium)

                                if MDMConfigService.shared.isManagedDevice {
                                    Text("Managed by your organization")
                                        .font(.caption)
                                        .foregroundColor(.secondary)
                                } else {
                                    Text("Logged in")
                                        .font(.caption)
                                        .foregroundColor(.green)
                                }
                            }

                            Spacer()

                            // Logout button - hidden when disableUserLogout is true
                            if appState.canLogout {
                                Button("Sign Out") {
                                    appState.logout()
                                }
                                .buttonStyle(.bordered)
                                .controlSize(.small)
                            }
                        }
                    } else {
                        HStack {
                            VStack(alignment: .leading, spacing: 2) {
                                Text("Not connected")
                                    .font(.subheadline)
                                    .fontWeight(.medium)
                                Text("Link to your workspace")
                                    .font(.caption)
                                    .foregroundColor(.secondary)
                            }

                            Spacer()

                            Button("Connect") {
                                NSWorkspace.shared.open(Constants.signUpURL)
                            }
                            .buttonStyle(.borderedProminent)
                            .controlSize(.small)
                        }
                    }
                }

                // Advanced Section
                SettingsSection(title: "Advanced", icon: "wrench.and.screwdriver.fill") {
                    VStack(alignment: .leading, spacing: 8) {
                        HStack {
                            Text("Version")
                                .font(.caption)
                                .foregroundColor(.secondary)
                            Spacer()
                            Text(Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "Unknown")
                                .font(.caption)
                                .fontWeight(.medium)
                        }

                        HStack {
                            Text("Port")
                                .font(.caption)
                                .foregroundColor(.secondary)
                            Spacer()
                            Text("\(proxyService.configuredPort ?? Constants.preferredPort)")
                                .font(.caption)
                                .fontWeight(.medium)
                        }

                        HStack {
                            Text("Config Directory")
                                .font(.caption)
                                .foregroundColor(.secondary)
                            Spacer()
                            Text("~/.oximy")
                                .font(.caption)
                                .fontWeight(.medium)
                        }

                        // Show managed device indicator
                        if MDMConfigService.shared.isManagedDevice {
                            HStack {
                                Text("Management")
                                    .font(.caption)
                                    .foregroundColor(.secondary)
                                Spacer()
                                Text("MDM Managed")
                                    .font(.caption)
                                    .fontWeight(.medium)
                                    .foregroundColor(.blue)
                            }
                        }

                    }
                }
            }
            .padding(16)
        }
        .onAppear {
            // Only check cert status on appear - it rarely changes
            // DO NOT call proxyService.checkStatus() here - it overwrites the known state
            // and can cause flickering when moving screens
            certService.checkStatus()
        }
    }

}

struct SettingsSection<Content: View>: View {
    let title: String
    let icon: String
    @ViewBuilder let content: Content

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 6) {
                Image(systemName: icon)
                    .font(.caption)
                    .foregroundColor(.secondary)
                Text(title.uppercased())
                    .font(.caption)
                    .fontWeight(.medium)
                    .foregroundColor(.secondary)
            }

            content
                .padding(12)
                .background(Color(nsColor: .controlBackgroundColor))
                .cornerRadius(8)
        }
    }
}

#Preview {
    SettingsTab()
        .environmentObject(AppState())
        .frame(width: 340, height: 400)
}
