import Foundation

struct HardeningCheck {
    let name: String
    let passed: Bool
    let current: String?
    let message: String?
}

class HardeningManager {
    func runChecks() -> [HardeningCheck] {
        let checks: [(name: String, fn: () -> HardeningCheck)] = [
            ("sip_enabled", checkSIP),
            ("filevault_enabled", checkFileVault),
            ("firewall_enabled", checkFirewall),
            ("gatekeeper_enabled", checkGatekeeper),
            ("xprotect_updated", checkXProtect)
        ]

        var results: [HardeningCheck] = []
        for check in checks {
            let result = check.fn()
            results.append(result)
            let icon = result.passed ? "✅" : "❌"
            print("[Hardening] \(icon) \(result.name)\(result.message.map { ": \($0)" } ?? "")")
        }
        return results
    }

    private func checkSIP() -> HardeningCheck {
        let out = run("csrutil", args: ["status"])
        let enabled = out?.contains("enabled") == true
        return HardeningCheck(name: "sip_enabled", passed: enabled, current: out?.trimmingCharacters(in: .whitespacesAndNewlines),
                              message: enabled ? nil : "System Integrity Protection is disabled — high risk")
    }

    private func checkFileVault() -> HardeningCheck {
        let out = run("fdesetup", args: ["status"])
        let enabled = out?.contains("FileVault is On") == true
        return HardeningCheck(name: "filevault_enabled", passed: enabled, current: out?.trimmingCharacters(in: .whitespacesAndNewlines),
                              message: enabled ? nil : "FileVault encryption is not enabled")
    }

    private func checkFirewall() -> HardeningCheck {
        // socketfilterfw is in /usr/libexec
        let out = run("/usr/libexec/ApplicationFirewall/socketfilterfw", args: ["--getglobalstate"])
        let enabled = out?.contains("enabled") == true
        return HardeningCheck(name: "firewall_enabled", passed: enabled, current: out?.trimmingCharacters(in: .whitespacesAndNewlines),
                              message: enabled ? nil : "macOS Application Firewall is disabled")
    }

    private func checkGatekeeper() -> HardeningCheck {
        let out = run("spctl", args: ["--status"])
        let enabled = out?.contains("assessments enabled") == true
        return HardeningCheck(name: "gatekeeper_enabled", passed: enabled, current: out?.trimmingCharacters(in: .whitespacesAndNewlines),
                              message: enabled ? nil : "Gatekeeper is disabled — allows unsigned code")
    }

    private func checkXProtect() -> HardeningCheck {
        // Check XProtect plist version
        let plistPath = "/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Resources/XProtect.meta.plist"
        if let data = FileManager.default.contents(atPath: plistPath),
           let plist = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any],
           let version = plist["Version"] as? Int {
            return HardeningCheck(name: "xprotect_updated", passed: true, current: "Version \(version)", message: nil)
        }
        return HardeningCheck(name: "xprotect_updated", passed: false, current: nil, message: "Could not read XProtect version")
    }

    private func run(_ command: String, args: [String]) -> String? {
        let process = Process()
        if FileManager.default.isExecutableFile(atPath: command) {
            process.executableURL = URL(fileURLWithPath: command)
        } else {
            process.executableURL = URL(fileURLWithPath: "/usr/bin/\(command)")
        }
        process.arguments = args
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = Pipe()
        try? process.run()
        process.waitUntilExit()
        return String(data: pipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8)
    }
}
