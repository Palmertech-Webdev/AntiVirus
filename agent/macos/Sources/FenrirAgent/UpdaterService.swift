import Foundation

private let currentVersion = "1.0.0"
private let githubReleaseAPI = "https://api.github.com/repos/AntiVirus/fenrir/releases/latest"

struct GithubRelease: Codable {
    let tagName: String
    let assets: [Asset]

    struct Asset: Codable {
        let name: String
        let browserDownloadUrl: String
    }

    enum CodingKeys: String, CodingKey {
        case tagName = "tag_name"
        case assets
    }
}

class UpdaterService {
    private let session: URLSession

    init() {
        let cfg = URLSessionConfiguration.default
        cfg.timeoutIntervalForRequest = 15
        self.session = URLSession(configuration: cfg)
    }

    func checkForUpdate(completion: @escaping (GithubRelease?, Bool, Error?) -> Void) {
        guard let url = URL(string: githubReleaseAPI) else { return }
        var req = URLRequest(url: url)
        req.setValue("application/vnd.github+json", forHTTPHeaderField: "Accept")

        session.dataTask(with: req) { data, _, error in
            if let error = error { completion(nil, false, error); return }
            guard let data = data,
                  let release = try? JSONDecoder().decode(GithubRelease.self, from: data) else {
                completion(nil, false, nil); return
            }
            let latest = release.tagName.trimmingCharacters(in: CharacterSet(charactersIn: "v"))
            let hasUpdate = latest != currentVersion
            if hasUpdate {
                print("[Updater] New version available: \(release.tagName) (current: \(currentVersion))")
            }
            completion(release, hasUpdate, nil)
        }.resume()
    }

    func downloadAndApply(release: GithubRelease, completion: @escaping (Bool, Error?) -> Void) {
        let arch = ProcessInfo.processInfo.environment["ARCH"] ?? "arm64"
        let assetName = "fenrir-macos-agent-\(arch)"
        guard let asset = release.assets.first(where: { $0.name == assetName }),
              let downloadURL = URL(string: asset.browserDownloadUrl) else {
            print("[Updater] No matching asset for \(assetName)")
            completion(false, nil)
            return
        }

        let tmpURL = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("fenrir-update")
        session.downloadTask(with: downloadURL) { localURL, _, error in
            if let error = error { completion(false, error); return }
            guard let localURL = localURL else { completion(false, nil); return }

            do {
                if FileManager.default.fileExists(atPath: tmpURL.path) {
                    try FileManager.default.removeItem(at: tmpURL)
                }
                try FileManager.default.moveItem(at: localURL, to: tmpURL)
                try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: tmpURL.path)

                // Restart via launchctl
                let selfPath = Bundle.main.executablePath ?? ""
                try FileManager.default.replaceItem(at: URL(fileURLWithPath: selfPath), withItemAt: tmpURL, backupItemName: nil, options: [], resultingItemURL: nil)

                print("[Updater] Updated to \(release.tagName). Restarting...")
                Process.launchedProcess(launchPath: "/bin/launchctl", arguments: ["kickstart", "-k", "system/com.fenrir.agent"])
                completion(true, nil)
            } catch {
                completion(false, error)
            }
        }.resume()
    }
}
