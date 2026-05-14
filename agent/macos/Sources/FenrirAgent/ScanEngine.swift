import Foundation

struct ScanResult {
    let matched: Bool
    let matchedRules: [String]
}

class ScanEngine {
    // TODO: Bind libyara via a bridging header when available.
    // For now this is a structured stub showing the intended API surface.

    private var loadedRules: [String] = []

    func initialize() {
        print("[ScanEngine] Initialized (YARA stub)")
    }

    func loadRule(_ ruleString: String) {
        loadedRules.append(ruleString)
        print("[ScanEngine] Loaded rule: \(ruleString.prefix(80))...")
    }

    func scanFile(at path: String) -> ScanResult {
        // Stub: read file and check against loaded rules
        // In production this calls yr_rules_scan_file(rules, path, ...)
        return ScanResult(matched: false, matchedRules: [])
    }

    func scanMemory(_ buffer: Data) -> ScanResult {
        // Stub: In production this calls yr_rules_scan_mem(rules, buffer, ...)
        return ScanResult(matched: false, matchedRules: [])
    }

    /// Quick heuristic check for ransomware-like rapid file extension rewrites.
    /// Returns true if the process has overwritten >50 unique extensions in 60s.
    func checkRansomwareHeuristic(pid: pid_t, filePath: String, knownWrites: inout [String: Int]) -> Bool {
        let ext = URL(fileURLWithPath: filePath).pathExtension.lowercased()
        knownWrites[ext, default: 0] += 1
        return knownWrites.count > 50
    }
}
