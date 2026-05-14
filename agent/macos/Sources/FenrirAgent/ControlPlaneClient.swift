import Foundation

class ControlPlaneClient {
    private let backendURL: URL
    private let session: URLSession

    init(config: AgentConfig) {
        self.backendURL = config.backendURL
        let sessionConfig = URLSessionConfiguration.default
        sessionConfig.timeoutIntervalForRequest = 10
        self.session = URLSession(configuration: sessionConfig)
    }

    func sendEvent(_ payload: [String: Any], completion: ((Error?) -> Void)? = nil) {
        guard let jsonData = try? JSONSerialization.data(withJSONObject: payload) else {
            completion?(NSError(domain: "FenrirClient", code: 0, userInfo: [NSLocalizedDescriptionKey: "JSON serialization failed"]))
            return
        }

        var request = URLRequest(url: backendURL)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = jsonData

        let task = session.dataTask(with: request) { _, response, error in
            if let error = error {
                print("[ControlPlane] Send failed: \(error.localizedDescription)")
                completion?(error)
                return
            }
            if let httpResponse = response as? HTTPURLResponse, httpResponse.statusCode != 200 {
                print("[ControlPlane] Backend returned HTTP \(httpResponse.statusCode)")
            }
            completion?(nil)
        }
        task.resume()
    }

    func sendBatch(_ payloads: [[String: Any]]) {
        for payload in payloads {
            sendEvent(payload)
        }
    }
}
