import Foundation

/// A single enforcement violation detected by the sensor
struct ViolationEntry: Codable {
    let id: String
    let timestamp: String
    let action: String  // "warn" or "block"
    let policyName: String
    let ruleName: String
    let severity: String
    let detectedType: String
    let host: String
    let bundleId: String?
    let retryAllowed: Bool
    let message: String

    enum CodingKeys: String, CodingKey {
        case id
        case timestamp
        case action
        case policyName = "policy_name"
        case ruleName = "rule_name"
        case severity
        case detectedType = "detected_type"
        case host
        case bundleId = "bundle_id"
        case retryAllowed = "retry_allowed"
        case message
    }
}

// MARK: - Display helpers

extension ViolationEntry {
    /// Built-in Oximy/Presidio PII type keys — everything else is a custom rule name.
    private static let knownOximyTypes: Set<String> = [
        "email", "phone", "ssn", "credit_card", "api_key",
        "aws_key", "github_token", "ip_address", "private_key",
        "person_name", "location",
    ]

    /// Individual type strings parsed from the comma-separated `detectedType`.
    var detectedTypes: [String] {
        detectedType.components(separatedBy: ",")
            .map { $0.trimmingCharacters(in: .whitespaces).lowercased() }
            .filter { !$0.isEmpty }
    }

    /// True when detectedType is a custom regex/keyword rule name rather than a known Oximy key.
    var isCustomRule: Bool {
        !detectedTypes.allSatisfy { Self.knownOximyTypes.contains($0) }
    }

    /// Icon for the first detected type (legacy convenience).
    var piiIcon: String { Self.iconForType(detectedTypes.first ?? "") }

    /// Label for the first detected type (legacy convenience).
    var piiLabel: String { Self.labelForType(detectedTypes.first ?? "") }

    static func iconForType(_ type: String) -> String {
        let t = type.lowercased()
        if t.contains("email")                          { return "envelope.fill" }
        if t.contains("credit") || t.contains("card")  { return "creditcard.fill" }
        if t.contains("ssn")                            { return "person.text.rectangle.fill" }
        if t.contains("phone")                          { return "phone.fill" }
        if t.contains("aws")                            { return "key.horizontal.fill" }
        if t.contains("github")                         { return "chevron.left.forwardslash.chevron.right" }
        if t.contains("private")                        { return "lock.fill" }
        if t.contains("ip")                             { return "network" }
        if t.contains("person") || t.contains("name")  { return "person.fill" }
        if t.contains("location")                       { return "location.fill" }
        if t.contains("key") || t.contains("token")    { return "key.fill" }
        return "text.magnifyingglass"
    }

    static func labelForType(_ type: String) -> String {
        let t = type.lowercased()
        if t.contains("email")                              { return "Email Address" }
        if t.contains("credit") || t.contains("card")      { return "Credit Card" }
        if t.contains("ssn")                               { return "Social Security Number" }
        if t.contains("phone")                             { return "Phone Number" }
        if t.contains("aws")                               { return "AWS Access Key" }
        if t.contains("github")                            { return "GitHub Token" }
        if t.contains("private")                           { return "Private Key" }
        if t.contains("api_key") || t.contains("api key") { return "API Key" }
        if t.contains("ip_address") || t.contains("ip address") { return "IP Address" }
        if t.contains("person")                            { return "Person Name" }
        if t.contains("location")                          { return "Location" }
        if t.contains("token") || t.contains("key")        { return "API Key" }
        return type.replacingOccurrences(of: "_", with: " ").capitalized
    }

    /// The redaction placeholders the Python addon actually wrote into the body.
    var redactPlaceholder: String {
        detectedTypes.map { type in
            if Self.knownOximyTypes.contains(type) {
                return "[\(type.uppercased())_REDACTED]"
            }
            return "[CUSTOM_REDACTED]"
        }.joined(separator: ", ")
    }

    /// Relative time string for the violation timestamp (e.g. "2 min ago").
    var relativeTime: String {
        let iso = ISO8601DateFormatter()
        iso.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        let date = iso.date(from: timestamp) ?? ISO8601DateFormatter().date(from: timestamp)
        guard let date else { return "" }
        let fmt = RelativeDateTimeFormatter()
        fmt.unitsStyle = .abbreviated
        return fmt.localizedString(for: date, relativeTo: Date())
    }
}

/// Envelope for the violations JSON file
struct ViolationState: Codable {
    let violations: [ViolationEntry]
    let lastUpdated: String

    enum CodingKeys: String, CodingKey {
        case violations
        case lastUpdated = "last_updated"
    }
}
