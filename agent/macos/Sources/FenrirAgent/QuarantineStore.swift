import Foundation
import CryptoKit

class QuarantineStore {
    private let quarantineRoot: URL
    private let db: RuntimeDatabase

    init(db: RuntimeDatabase) {
        self.db = db
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .localDomainMask).first!
        quarantineRoot = base.appendingPathComponent("Fenrir/Quarantine", isDirectory: true)
        try? FileManager.default.createDirectory(at: quarantineRoot, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    }

    @discardableResult
    func quarantine(filePath: String, reason: String) -> Bool {
        let sourceURL = URL(fileURLWithPath: filePath)
        let hash = sha256(fileURL: sourceURL) ?? "unknown"

        let destName = "\(Date().timeIntervalSince1970)_\(hash.prefix(16)).quarantine"
        let destURL = quarantineRoot.appendingPathComponent(destName)

        do {
            try FileManager.default.moveItem(at: sourceURL, to: destURL)
            // Strip execute permissions
            try FileManager.default.setAttributes([.posixPermissions: 0o400], ofItemAtPath: destURL.path)

            db.recordQuarantine(
                originalPath: filePath,
                quarantinePath: destURL.path,
                sha256: hash,
                reason: reason
            )
            print("[QuarantineStore] Quarantined: \(filePath) -> \(destURL.path)")
            return true
        } catch {
            print("[QuarantineStore] Failed to quarantine \(filePath): \(error)")
            return false
        }
    }

    func restore(originalPath: String) -> Bool {
        let entries = db.allQuarantineEntries()
        guard let entry = entries.first(where: { $0["originalPath"] as? String == originalPath }),
              let quarantinePath = entry["quarantinePath"] as? String else {
            print("[QuarantineStore] No quarantine entry for \(originalPath)")
            return false
        }

        do {
            try FileManager.default.moveItem(
                at: URL(fileURLWithPath: quarantinePath),
                to: URL(fileURLWithPath: originalPath)
            )
            print("[QuarantineStore] Restored: \(quarantinePath) -> \(originalPath)")
            return true
        } catch {
            print("[QuarantineStore] Restore failed: \(error)")
            return false
        }
    }

    // MARK: - Helpers

    private func sha256(fileURL: URL) -> String? {
        guard let data = try? Data(contentsOf: fileURL) else { return nil }
        let digest = SHA256.hash(data: data)
        return digest.map { String(format: "%02x", $0) }.joined()
    }
}
