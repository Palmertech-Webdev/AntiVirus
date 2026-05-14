import Foundation

/// Lightweight persistent state store backed by a JSON flat-file database.
/// Swap for GRDB/SQLite when the dependency is wired in Package.swift.
class RuntimeDatabase {
    private let storeURL: URL
    private var state: [String: Data] = [:]
    private var quarantineLog: [[String: Any]] = []
    private let lock = NSLock()

    static let shared: RuntimeDatabase = {
        let dir = FileManager.default.urls(for: .applicationSupportDirectory, in: .localDomainMask).first!
            .appendingPathComponent("Fenrir", isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return RuntimeDatabase(directory: dir)
    }()

    init(directory: URL) {
        self.storeURL = directory.appendingPathComponent("runtime_state.json")
        load()
    }

    // MARK: - Key/Value State

    func set<T: Encodable>(key: String, value: T) {
        guard let data = try? JSONEncoder().encode(value) else { return }
        lock.lock()
        state[key] = data
        lock.unlock()
        persist()
    }

    func get<T: Decodable>(key: String, type: T.Type) -> T? {
        lock.lock()
        let data = state[key]
        lock.unlock()
        guard let data = data else { return nil }
        return try? JSONDecoder().decode(type, from: data)
    }

    // MARK: - Quarantine Log

    func recordQuarantine(originalPath: String, quarantinePath: String, sha256: String, reason: String) {
        let entry: [String: Any] = [
            "originalPath": originalPath,
            "quarantinePath": quarantinePath,
            "sha256": sha256,
            "reason": reason,
            "timestamp": ISO8601DateFormatter().string(from: Date())
        ]
        lock.lock()
        quarantineLog.append(entry)
        lock.unlock()
        print("[RuntimeDatabase] Quarantine recorded: \(originalPath)")
    }

    func allQuarantineEntries() -> [[String: Any]] {
        lock.lock()
        defer { lock.unlock() }
        return quarantineLog
    }

    // MARK: - Persistence

    private func persist() {
        lock.lock()
        let snapshot = state
        lock.unlock()
        let encoded = snapshot.mapValues { $0.base64EncodedString() }
        guard let data = try? JSONSerialization.data(withJSONObject: encoded) else { return }
        try? data.write(to: storeURL, options: .atomic)
    }

    private func load() {
        guard let data = try? Data(contentsOf: storeURL),
              let dict = try? JSONSerialization.jsonObject(with: data) as? [String: String] else { return }
        state = dict.compactMapValues { Data(base64Encoded: $0) }
        print("[RuntimeDatabase] Loaded state from \(storeURL.path)")
    }
}
