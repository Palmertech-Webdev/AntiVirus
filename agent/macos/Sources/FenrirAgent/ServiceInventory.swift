import Foundation

struct ServiceRecord {
    let pid: Int?
    let status: Int
    let label: String
}

class ServiceInventory {
    private var lastSnapshot: [String: ServiceRecord] = [:]

    func snapshot() -> [ServiceRecord] {
        guard let output = runCommand("launchctl", args: ["list"]) else { return [] }
        var records: [ServiceRecord] = []
        let lines = output.components(separatedBy: "\n").dropFirst() // skip header
        for line in lines {
            let parts = line.components(separatedBy: "\t")
            guard parts.count == 3 else { continue }
            let pid = Int(parts[0].trimmingCharacters(in: .whitespaces))
            let status = Int(parts[1].trimmingCharacters(in: .whitespaces)) ?? 0
            let label = parts[2].trimmingCharacters(in: .whitespaces)
            records.append(ServiceRecord(pid: pid, status: status, label: label))
        }

        lastSnapshot = Dictionary(uniqueKeysWithValues: records.map { ($0.label, $0) })
        print("[ServiceInventory] Snapshot: \(records.count) services")
        return records
    }

    func delta() -> (added: [ServiceRecord], removed: [ServiceRecord]) {
        let previous = lastSnapshot
        let current = snapshot()
        let currentMap = Dictionary(uniqueKeysWithValues: current.map { ($0.label, $0) })

        let added = current.filter { previous[$0.label] == nil }
        let removed = previous.values.filter { currentMap[$0.label] == nil }
        return (added: added, removed: Array(removed))
    }

    private func runCommand(_ command: String, args: [String]) -> String? {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/\(command)")
        process.arguments = args
        let pipe = Pipe()
        process.standardOutput = pipe
        try? process.run()
        process.waitUntilExit()
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        return String(data: data, encoding: .utf8)
    }
}
