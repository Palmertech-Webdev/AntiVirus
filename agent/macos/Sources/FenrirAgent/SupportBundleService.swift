import Foundation

class SupportBundleService {
    private let appSupport: URL

    init() {
        appSupport = FileManager.default.urls(for: .applicationSupportDirectory, in: .localDomainMask).first!
            .appendingPathComponent("Fenrir")
    }

    func collect(to destPath: String) -> String? {
        let timestamp = ISO8601DateFormatter().string(from: Date()).replacingOccurrences(of: ":", with: "-")
        let bundleName = "fenrir-support-\(timestamp)"
        let bundleDir = URL(fileURLWithPath: destPath).appendingPathComponent(bundleName)

        do {
            try FileManager.default.createDirectory(at: bundleDir, withIntermediateDirectories: true)
            let subDirs = ["Evidence", "Quarantine"]
            for sub in subDirs {
                let src = appSupport.appendingPathComponent(sub)
                let dst = bundleDir.appendingPathComponent(sub)
                if FileManager.default.fileExists(atPath: src.path) {
                    try FileManager.default.copyItem(at: src, to: dst)
                }
            }

            // Compress using ditto
            let archivePath = bundleDir.path + ".zip"
            let process = Process()
            process.executableURL = URL(fileURLWithPath: "/usr/bin/ditto")
            process.arguments = ["-c", "-k", "--sequesterRsrc", bundleDir.path, archivePath]
            try process.run()
            process.waitUntilExit()

            // Cleanup staging dir
            try? FileManager.default.removeItem(at: bundleDir)
            print("[Support] Bundle created: \(archivePath)")
            return archivePath
        } catch {
            print("[Support] Failed to create bundle: \(error)")
            return nil
        }
    }
}
