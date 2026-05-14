import Foundation

/// Unix-domain socket IPC server allowing a local fenrirctl CLI to query and control the daemon.
class LocalControlChannel {
    private let socketPath = "/var/run/fenrir/fenrir.sock"
    private var serverSocket: Int32 = -1
    private var handlers: [String: (([String: String]) -> [String: Any])] = [:]
    private let queue = DispatchQueue(label: "com.fenrir.ipc", attributes: .concurrent)

    func register(action: String, handler: @escaping ([String: String]) -> [String: Any]) {
        handlers[action.lowercased()] = handler
    }

    func start() {
        try? FileManager.default.createDirectory(atPath: "/var/run/fenrir", withIntermediateDirectories: true, attributes: nil)
        unlink(socketPath)

        serverSocket = socket(AF_UNIX, SOCK_STREAM, 0)
        guard serverSocket >= 0 else {
            print("[IPC] Failed to create socket")
            return
        }

        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        withUnsafeMutablePointer(to: &addr.sun_path.0) { ptr in
            _ = socketPath.withCString { strncpy(ptr, $0, MemoryLayout.size(ofValue: addr.sun_path)) }
        }

        let bindResult = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                bind(serverSocket, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }

        guard bindResult == 0 else {
            print("[IPC] Failed to bind socket: \(String(cString: strerror(errno)))")
            return
        }

        chmod(socketPath, 0o600)
        listen(serverSocket, 5)
        print("[IPC] LocalControlChannel listening on \(socketPath)")

        queue.async { [weak self] in self?.acceptLoop() }
    }

    func stop() {
        if serverSocket >= 0 {
            close(serverSocket)
            serverSocket = -1
            unlink(socketPath)
        }
    }

    private func acceptLoop() {
        while serverSocket >= 0 {
            let clientFd = accept(serverSocket, nil, nil)
            guard clientFd >= 0 else { break }
            queue.async { [weak self] in self?.handleClient(fd: clientFd) }
        }
    }

    private func handleClient(fd: Int32) {
        defer { close(fd) }

        var buffer = [UInt8](repeating: 0, count: 4096)
        let bytesRead = read(fd, &buffer, buffer.count - 1)
        guard bytesRead > 0 else { return }

        let raw = Data(buffer.prefix(bytesRead))
        guard let cmd = try? JSONSerialization.jsonObject(with: raw) as? [String: Any],
              let action = cmd["action"] as? String else {
            send(fd: fd, response: ["success": false, "message": "invalid command"])
            return
        }

        let args = cmd["args"] as? [String: String] ?? [:]
        if let handler = handlers[action.lowercased()] {
            let result = handler(args)
            send(fd: fd, response: result)
        } else {
            send(fd: fd, response: ["success": false, "message": "unknown action: \(action)"])
        }
    }

    private func send(fd: Int32, response: [String: Any]) {
        guard let data = try? JSONSerialization.data(withJSONObject: response),
              let str = String(data: data, encoding: .utf8) else { return }
        let bytes = Array((str + "\n").utf8)
        write(fd, bytes, bytes.count)
    }
}
