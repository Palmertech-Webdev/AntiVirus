import Foundation

struct AgentConfig {
    let backendURL: URL
    let deviceId: String
    let logLevel: String

    static func load() -> AgentConfig {
        let deviceId = Host.current().localizedName ?? "Unknown-Mac"

        let backendURLString = ProcessInfo.processInfo.environment["FENRIR_BACKEND_URL"]
            ?? "http://localhost:3000/api/v1/telemetry"
        let backendURL = URL(string: backendURLString)!

        return AgentConfig(
            backendURL: backendURL,
            deviceId: deviceId,
            logLevel: ProcessInfo.processInfo.environment["FENRIR_LOG_LEVEL"] ?? "INFO"
        )
    }
}
