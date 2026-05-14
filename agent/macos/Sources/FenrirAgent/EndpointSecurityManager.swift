import Foundation
import EndpointSecurity

/// Pure ES sensor: intercepts kernel events and delegates all logic to RealtimeProtectionBroker.
class EndpointSecurityManager {
    private var client: OpaquePointer?
    private let broker: RealtimeProtectionBroker

    init(broker: RealtimeProtectionBroker) {
        self.broker = broker
    }

    func start() -> Bool {
        let res = es_new_client(&client) { [weak self] (_, message) in
            self?.handleMessage(message: message)
        }

        guard res == ES_NEW_CLIENT_RESULT_SUCCESS, let client = client else {
            print("[ESManager] Failed to create ES client. Did you grant the entitlement and Full Disk Access?")
            return false
        }

        let events: [es_event_type_t] = [
            ES_EVENT_TYPE_AUTH_EXEC,
            ES_EVENT_TYPE_AUTH_OPEN
        ]

        guard es_subscribe(client, events, UInt32(events.count)) == ES_RETURN_SUCCESS else {
            print("[ESManager] Failed to subscribe to ES events.")
            return false
        }

        print("[ESManager] Successfully subscribed to Endpoint Security events.")
        return true
    }

    func stop() {
        if let client = client {
            es_unsubscribe_all(client)
            es_delete_client(client)
            self.client = nil
        }
    }

    // MARK: - Private

    private func handleMessage(message: UnsafePointer<es_message_t>) {
        guard message.pointee.action_type == ES_ACTION_TYPE_AUTH else { return }

        var verdict: es_auth_result_t = ES_AUTH_RESULT_ALLOW

        switch message.pointee.event_type {
        case ES_EVENT_TYPE_AUTH_EXEC:
            verdict = handleExec(message: message)
        case ES_EVENT_TYPE_AUTH_OPEN:
            verdict = handleOpen(message: message)
        default:
            break
        }

        es_respond_auth_result(client!, message, verdict, false)
    }

    private func handleExec(message: UnsafePointer<es_message_t>) -> es_auth_result_t {
        let path = String(cString: message.pointee.event.exec.target.pointee.executable.pointee.path.data)
        let pid = audit_token_to_pid(message.pointee.event.exec.target.pointee.audit_token)

        let decision = broker.handleExec(executablePath: path, pid: pid)
        return decision == .allow ? ES_AUTH_RESULT_ALLOW : ES_AUTH_RESULT_DENY
    }

    private func handleOpen(message: UnsafePointer<es_message_t>) -> es_auth_result_t {
        let filePath = String(cString: message.pointee.event.open.file.pointee.path.data)
        let pid = audit_token_to_pid(message.pointee.process.pointee.audit_token)
        let isWrite = (message.pointee.event.open.fflag & FWRITE) != 0

        let decision = broker.handleFileOpen(filePath: filePath, pid: pid, isWrite: isWrite)

        switch decision {
        case .allow:
            return ES_AUTH_RESULT_ALLOW
        case .block:
            return ES_AUTH_RESULT_DENY
        }
    }
}
