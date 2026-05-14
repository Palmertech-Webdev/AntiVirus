import Foundation

class TelemetryQueueStore {
    private var queue: [[String: Any]] = []
    private let lock = NSLock()
    private let maxSize: Int
    private let client: ControlPlaneClient

    init(maxSize: Int = 50, client: ControlPlaneClient) {
        self.maxSize = maxSize
        self.client = client
    }

    func enqueue(_ event: [String: Any]) {
        lock.lock()
        queue.append(event)
        let shouldFlush = queue.count >= maxSize
        let batch = shouldFlush ? drain() : []
        lock.unlock()

        if shouldFlush {
            dispatch(batch)
        }
    }

    func flush() {
        lock.lock()
        let batch = drain()
        lock.unlock()
        dispatch(batch)
    }

    private func drain() -> [[String: Any]] {
        let batch = queue
        queue.removeAll()
        return batch
    }

    private func dispatch(_ batch: [[String: Any]]) {
        guard !batch.isEmpty else { return }
        DispatchQueue.global(qos: .background).async { [weak self] in
            self?.client.sendBatch(batch)
        }
    }
}
