import Foundation

enum RemediationAction {
    case killProcess
    case quarantineFile
    case deleteFile
    case alertOnly
}

struct RemediationRequest {
    let pid: pid_t
    let filePath: String?
    let reason: String
    let actions: [RemediationAction]
}

struct RemediationResult {
    var success: Bool = true
    var actionsPerformed: [String] = []
    var errors: [String] = []
}

class RemediationEngine {
    private let quarantineStore: QuarantineStore

    init(quarantineStore: QuarantineStore) {
        self.quarantineStore = quarantineStore
    }

    @discardableResult
    func remediate(_ request: RemediationRequest) -> RemediationResult {
        var result = RemediationResult()

        for action in request.actions {
            switch action {
            case .killProcess:
                if kill(request.pid, SIGKILL) == 0 {
                    let msg = "Sent SIGKILL to PID \(request.pid)"
                    print("[RemediationEngine] \(msg)")
                    result.actionsPerformed.append(msg)
                } else {
                    let err = "Failed to kill PID \(request.pid): \(String(cString: strerror(errno)))"
                    print("[RemediationEngine] \(err)")
                    result.errors.append(err)
                    result.success = false
                }

            case .quarantineFile:
                guard let path = request.filePath else { continue }
                let ok = quarantineStore.quarantine(filePath: path, reason: request.reason)
                if ok {
                    result.actionsPerformed.append("Quarantined \(path)")
                } else {
                    let err = "Quarantine failed for \(path)"
                    result.errors.append(err)
                    result.success = false
                }

            case .deleteFile:
                guard let path = request.filePath else { continue }
                do {
                    try FileManager.default.removeItem(atPath: path)
                    let msg = "Deleted \(path)"
                    print("[RemediationEngine] \(msg)")
                    result.actionsPerformed.append(msg)
                } catch {
                    let err = "Delete failed for \(path): \(error)"
                    result.errors.append(err)
                    result.success = false
                }

            case .alertOnly:
                let msg = "[ALERT] \(request.reason) | PID: \(request.pid) | File: \(request.filePath ?? "N/A")"
                print("[RemediationEngine] \(msg)")
                result.actionsPerformed.append("Alert logged")
            }
        }

        return result
    }
}
