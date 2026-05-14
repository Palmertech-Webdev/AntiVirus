import Foundation
import CryptoKit

struct TrustResult {
    let trusted: Bool
    let reason: String
}

class RuntimeTrustValidator {
    private let expectedSelfHash: String?

    init(expectedHash: String? = nil) {
        self.expectedSelfHash = expectedHash
    }

    func validateSelf() -> TrustResult {
        // macOS primary validation: codesign
        let codesignResult = runCodesignVerify()
        if !codesignResult.trusted {
            return codesignResult
        }

        // Optional: hash self-check
        if let expected = expectedSelfHash {
            guard let selfPath = Bundle.main.executablePath,
                  let hash = sha256(filePath: selfPath) else {
                return TrustResult(trusted: false, reason: "Could not hash self binary")
            }
            if hash != expected {
                return TrustResult(trusted: false, reason: "Self-hash mismatch (binary tampered?)")
            }
        }

        return TrustResult(trusted: true, reason: "Codesign verified")
    }

    func validateFile(at path: String, expectedHash: String) -> TrustResult {
        guard let hash = sha256(filePath: path) else {
            return TrustResult(trusted: false, reason: "Could not hash file: \(path)")
        }
        return hash == expectedHash
            ? TrustResult(trusted: true, reason: "Hash verified")
            : TrustResult(trusted: false, reason: "Hash mismatch for \(path)")
    }

    private func runCodesignVerify() -> TrustResult {
        guard let selfPath = Bundle.main.executablePath else {
            return TrustResult(trusted: false, reason: "No executable path")
        }
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/codesign")
        process.arguments = ["--verify", "--strict", selfPath]
        let pipe = Pipe()
        process.standardError = pipe
        try? process.run()
        process.waitUntilExit()
        if process.terminationStatus == 0 {
            return TrustResult(trusted: true, reason: "codesign --verify passed")
        }
        let errData = pipe.fileHandleForReading.readDataToEndOfFile()
        let errMsg = String(data: errData, encoding: .utf8) ?? "unknown error"
        return TrustResult(trusted: false, reason: "codesign failed: \(errMsg.trimmingCharacters(in: .whitespacesAndNewlines))")
    }

    private func sha256(filePath: String) -> String? {
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: filePath)) else { return nil }
        let digest = SHA256.hash(data: data)
        return digest.map { String(format: "%02x", $0) }.joined()
    }
}
