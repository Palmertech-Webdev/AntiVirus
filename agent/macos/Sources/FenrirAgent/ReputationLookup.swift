import Foundation
import CryptoKit

enum ReputationVerdict: String, Codable {
    case clean = "Clean"
    case malicious = "Malicious"
    case unknown = "Unknown"
}

struct ReputationResult: Codable {
    let sha256: String
    let verdict: ReputationVerdict
    let threatName: String?
    let confidence: Int
}

class ReputationLookup {
    private let config: AgentConfig
    private var cache: [String: (result: ReputationResult, cachedAt: Date)] = [:]
    private let lock = NSLock()
    private let session: URLSession
    private let cacheTTL: TimeInterval = 600 // 10 minutes

    init(config: AgentConfig) {
        self.config = config
        let cfg = URLSessionConfiguration.default
        cfg.timeoutIntervalForRequest = 8
        self.session = URLSession(configuration: cfg)
    }

    func lookupFile(at path: String, completion: @escaping (ReputationResult) -> Void) {
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self = self else { return }
            guard let hash = self.sha256(filePath: path) else {
                completion(ReputationResult(sha256: "unknown", verdict: .unknown, threatName: nil, confidence: 0))
                return
            }
            self.lookupHash(hash, completion: completion)
        }
    }

    func lookupHash(_ hash: String, completion: @escaping (ReputationResult) -> Void) {
        // Check cache
        lock.lock()
        if let cached = cache[hash], Date().timeIntervalSince(cached.cachedAt) < cacheTTL {
            let result = cached.result
            lock.unlock()
            completion(result)
            return
        }
        lock.unlock()

        // Query backend reputation endpoint
        let reputationBase = config.backendURL.deletingLastPathComponent()
        guard let url = URL(string: "\(reputationBase)/api/v1/reputation/\(hash)") else {
            completion(ReputationResult(sha256: hash, verdict: .unknown, threatName: nil, confidence: 0))
            return
        }

        let task = session.dataTask(with: url) { [weak self] data, _, error in
            guard let self = self, let data = data, error == nil,
                  let result = try? JSONDecoder().decode(ReputationResult.self, from: data) else {
                completion(ReputationResult(sha256: hash, verdict: .unknown, threatName: nil, confidence: 0))
                return
            }
            self.lock.lock()
            self.cache[hash] = (result: result, cachedAt: Date())
            self.lock.unlock()
            completion(result)
        }
        task.resume()
    }

    private func sha256(filePath: String) -> String? {
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: filePath)) else { return nil }
        let digest = SHA256.hash(data: data)
        return digest.map { String(format: "%02x", $0) }.joined()
    }
}
