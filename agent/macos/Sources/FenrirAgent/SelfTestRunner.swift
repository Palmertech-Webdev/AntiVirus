import Foundation

struct TestResult {
    let name: String
    let passed: Bool
    let message: String?
}

class SelfTestRunner {
    private let config: AgentConfig

    init(config: AgentConfig) {
        self.config = config
    }

    func runAll() -> [TestResult] {
        let tests: [(name: String, fn: () -> (Bool, String?))] = [
            ("backend_reachable", testBackend),
            ("running_as_root", testRoot),
            ("quarantine_dir_writable", testQuarantineDir),
            ("evidence_dir_writable", testEvidenceDir),
            ("full_disk_access", testFullDiskAccess)
        ]

        var results: [TestResult] = []
        for test in tests {
            let (passed, message) = test.fn()
            results.append(TestResult(name: test.name, passed: passed, message: message))
            let icon = passed ? "✅" : "❌"
            print("[SelfTest] \(icon) \(test.name)\(message.map { ": \($0)" } ?? "")")
        }
        return results
    }

    private func testBackend() -> (Bool, String?) {
        let semaphore = DispatchSemaphore(value: 0)
        var success = false
        let url = config.backendURL.deletingLastPathComponent()
        URLSession.shared.dataTask(with: url) { _, response, _ in
            success = (response as? HTTPURLResponse) != nil
            semaphore.signal()
        }.resume()
        semaphore.wait()
        return (success, success ? nil : "backend unreachable at \(url)")
    }

    private func testRoot() -> (Bool, String?) {
        let isRoot = getuid() == 0
        return (isRoot, isRoot ? nil : "agent should run as root for full ES entitlement")
    }

    private func testQuarantineDir() -> (Bool, String?) {
        return testWritable("Fenrir/Quarantine")
    }

    private func testEvidenceDir() -> (Bool, String?) {
        return testWritable("Fenrir/Evidence")
    }

    private func testFullDiskAccess() -> (Bool, String?) {
        // Probe a protected path to confirm FDA is granted
        let probe = "/Library/Application Support/com.apple.TCC/TCC.db"
        let accessible = FileManager.default.isReadableFile(atPath: probe)
        return (accessible, accessible ? nil : "Full Disk Access not granted in System Preferences")
    }

    private func testWritable(_ subpath: String) -> (Bool, String?) {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .localDomainMask).first!
        let dir = base.appendingPathComponent(subpath)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let test = dir.appendingPathComponent(".write_test")
        do {
            try "ok".write(to: test, atomically: true, encoding: .utf8)
            try FileManager.default.removeItem(at: test)
            return (true, nil)
        } catch {
            return (false, "not writable: \(error.localizedDescription)")
        }
    }
}
