import Foundation

struct DeviceInventory: Codable {
    let hostname: String
    let os: String
    let osVersion: String
    let kernelVersion: String
    let architecture: String
    let cpuModel: String
    let memoryTotalMB: Int
    let collectedAt: String
}

class DeviceInventoryCollector {
    func collect() -> DeviceInventory {
        let process = ProcessInfo.processInfo

        return DeviceInventory(
            hostname: Host.current().localizedName ?? "unknown",
            os: "macOS",
            osVersion: process.operatingSystemVersionString,
            kernelVersion: sysctl("kern.osrelease") ?? "unknown",
            architecture: sysctl("hw.machine") ?? "unknown",
            cpuModel: sysctl("machdep.cpu.brand_string") ?? "unknown",
            memoryTotalMB: Int(process.physicalMemory / 1_048_576),
            collectedAt: ISO8601DateFormatter().string(from: Date())
        )
    }

    private func sysctl(_ name: String) -> String? {
        var size = 0
        sysctlbyname(name, nil, &size, nil, 0)
        guard size > 0 else { return nil }
        var buffer = [CChar](repeating: 0, count: size)
        sysctlbyname(name, &buffer, &size, nil, 0)
        return String(cString: buffer)
    }
}
