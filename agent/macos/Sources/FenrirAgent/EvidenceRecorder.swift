import Foundation

struct EvidenceBundle: Codable {
    let bundleId: String
    let pid: pid_t
    let processName: String
    let createdAt: String
    let processTree: String?
    let openFiles: String?
    let netConnections: String?
}

class EvidenceRecorder {
    private let evidenceRoot: URL

    init() {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .localDomainMask).first!
        evidenceRoot = base.appendingPathComponent("Fenrir/Evidence", isDirectory: true)
        try? FileManager.default.createDirectory(at: evidenceRoot, withIntermediateDirectories: true)
    }

    func collect(pid: pid_t, processName: String) -> EvidenceBundle {
        let bundleId = "\(Date().timeIntervalSince1970)_\(pid)"
        let pidStr = "\(pid)"

        let bundle = EvidenceBundle(
            bundleId: bundleId,
            pid: pid,
            processName: processName,
            createdAt: ISO8601DateFormatter().string(from: Date()),
            processTree: run("pstree", args: [pidStr]),
            openFiles: run("lsof", args: ["-p", pidStr]),
            netConnections: run("lsof", args: ["-i", "-nP", "-p", pidStr])
        )

        let bundlePath = evidenceRoot.appendingPathComponent("\(bundleId).json")
        if let data = try? JSONEncoder().encode(bundle) {
            try? data.write(to: bundlePath, options: .atomic)
        }

        print("[EvidenceRecorder] Saved evidence bundle: \(bundleId)")
        return bundle
    }

    private func run(_ command: String, args: [String]) -> String? {
        let process = Process()
        // Try common system binary paths
        for prefix in ["/usr/bin", "/bin", "/usr/sbin"] {
            let path = "\(prefix)/\(command)"
            if FileManager.default.isExecutableFile(atPath: path) {
                process.executableURL = URL(fileURLWithPath: path)
                break
            }
        }
        guard process.executableURL != nil else { return nil }
        process.arguments = args
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = Pipe() // suppress errors
        try? process.run()
        process.waitUntilExit()
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        return String(data: data, encoding: .utf8)
    }
}
