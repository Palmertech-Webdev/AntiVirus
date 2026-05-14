import Foundation
import EndpointSecurity

class EndpointSecurityManager {
    private var client: OpaquePointer?
    private let backendURL = URL(string: "http://localhost:3000/api/v1/telemetry")!
    private let deviceId: String

    init() {
        deviceId = Host.current().localizedName ?? "Unknown-Mac"
    }

    func start() -> Bool {
        let res = es_new_client(&client) { [weak self] (client, message) in
            self?.handleMessage(message: message.pointee)
        }

        guard res == ES_NEW_CLIENT_RESULT_SUCCESS, let client = client else {
            print("Failed to create ES client. Did you grant the entitlement and Full Disk Access?")
            return false
        }

        let events: [es_event_type_t] = [
            ES_EVENT_TYPE_AUTH_EXEC,
            ES_EVENT_TYPE_AUTH_OPEN
        ]

        let subRes = es_subscribe(client, events, UInt32(events.count))
        if subRes != ES_RETURN_SUCCESS {
            print("Failed to subscribe to ES events.")
            return false
        }

        print("Successfully subscribed to ES events.")
        return true
    }

    private func handleMessage(message: es_message_t) {
        var action = ES_AUTH_RESULT_ALLOW

        switch message.event_type {
        case ES_EVENT_TYPE_AUTH_EXEC:
            handleExec(message: message)
        case ES_EVENT_TYPE_AUTH_OPEN:
            action = handleOpen(message: message)
        default:
            break
        }

        if message.action_type == ES_ACTION_TYPE_AUTH {
            // Note: In a real app we'd need to copy the message if we dispatch asynchronously.
            // For this skeleton, we reply synchronously.
            es_respond_auth_result(client!, message, action, false)
        }
    }

    private func handleExec(message: es_message_t) {
        let exec = message.event.exec
        let target = exec.target.pointee
        let executable = target.executable.pointee
        let processName = String(cString: executable.path.data)
        let pid = target.audit_token.pid

        // Send ProcessStart telemetry
        sendTelemetry(eventType: "ProcessStart", payload: [
            "eventType": "ProcessStart",
            "processName": processName,
            "pid": pid,
            "commandLine": processName // args parsing omitted for simplicity in scaffold
        ])
    }

    private func handleOpen(message: es_message_t) -> es_auth_result_t {
        let open = message.event.open
        let file = open.file.pointee
        let filePath = String(cString: file.path.data)

        let isWrite = (open.fflag & FWRITE) != 0

        if isWrite {
            // Check macOS persistence vectors
            if filePath.hasPrefix("/Library/LaunchDaemons") || 
               filePath.hasPrefix("/Library/LaunchAgents") ||
               filePath.hasPrefix("/System/Library/LaunchDaemons") ||
               filePath.contains("/Library/LaunchAgents") {
                
                print("BLOCKING write to LaunchDaemon/Agent: \(filePath)")
                
                let processName = String(cString: message.process.pointee.executable.pointee.path.data)
                let pid = message.process.pointee.audit_token.pid
                sendTelemetry(eventType: "FileWrite", payload: [
                    "eventType": "FileWrite",
                    "processName": processName,
                    "pid": pid,
                    "filePath": filePath,
                    "action": "Blocked"
                ])
                
                return ES_AUTH_RESULT_DENY
            }

            let processName = String(cString: message.process.pointee.executable.pointee.path.data)
            let pid = message.process.pointee.audit_token.pid
            
            // Log other file writes (Note: this is extremely noisy in production without filters)
            sendTelemetry(eventType: "FileWrite", payload: [
                "eventType": "FileWrite",
                "processName": processName,
                "pid": pid,
                "filePath": filePath
            ])
        }

        return ES_AUTH_RESULT_ALLOW
    }

    private func sendTelemetry(eventType: String, payload: [String: Any]) {
        let formatter = ISO8601DateFormatter()
        let timestamp = formatter.string(from: Date())
        let eventId = UUID().uuidString

        let envelope: [String: Any] = [
            "eventId": eventId,
            "deviceId": deviceId,
            "timestamp": timestamp,
            "eventType": eventType,
            "payload": payload
        ]

        guard let jsonData = try? JSONSerialization.data(withJSONObject: envelope) else { return }

        var request = URLRequest(url: backendURL)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = jsonData

        let task = URLSession.shared.dataTask(with: request) { data, response, error in
            if let error = error {
                print("Telemetry error: \(error)")
            }
        }
        task.resume()
    }
}
