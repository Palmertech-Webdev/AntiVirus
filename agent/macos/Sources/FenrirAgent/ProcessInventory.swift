import Foundation

struct ProcessRecord {
    let pid: pid_t
    let executablePath: String
    let startTime: Date
}

class ProcessInventory {
    private var processes: [pid_t: ProcessRecord] = [:]
    private let lock = NSLock()

    func add(_ record: ProcessRecord) {
        lock.lock()
        defer { lock.unlock() }
        processes[record.pid] = record
    }

    func remove(pid: pid_t) {
        lock.lock()
        defer { lock.unlock() }
        processes.removeValue(forKey: pid)
    }

    func get(pid: pid_t) -> ProcessRecord? {
        lock.lock()
        defer { lock.unlock() }
        return processes[pid]
    }

    func allProcesses() -> [ProcessRecord] {
        lock.lock()
        defer { lock.unlock() }
        return Array(processes.values)
    }
}
