import Foundation
import CoreServices

enum FileChangeKind {
    case created, modified, deleted, renamed
}

struct FileChangeEvent {
    let path: String
    let kind: FileChangeKind
    let timestamp: Date
}

class FileInventory {
    private var stream: FSEventStreamRef?
    private var watchedPaths: [String] = []
    private let callback: (FileChangeEvent) -> Void

    init(callback: @escaping (FileChangeEvent) -> Void) {
        self.callback = callback
    }

    func watch(paths: [String]) {
        watchedPaths = paths
        let ctx = UnsafeMutableRawPointer(Unmanaged.passRetained(self).toOpaque())

        var context = FSEventStreamContext(version: 0, info: ctx, retain: nil, release: nil, copyDescription: nil)
        let flags = UInt32(
            kFSEventStreamCreateFlagUseCFTypes |
            kFSEventStreamCreateFlagFileEvents |
            kFSEventStreamCreateFlagNoDefer
        )

        let cfPaths = paths as CFArray
        stream = FSEventStreamCreate(
            kCFAllocatorDefault,
            { _, info, numEvents, eventPaths, eventFlags, _ in
                guard let info = info else { return }
                let inventory = Unmanaged<FileInventory>.fromOpaque(info).takeUnretainedValue()
                let paths = unsafeBitCast(eventPaths, to: NSArray.self) as! [String]
                let flags = Array(UnsafeBufferPointer(start: eventFlags, count: numEvents))

                for i in 0..<numEvents {
                    let flag = flags[i]
                    var kind: FileChangeKind = .modified
                    if flag & UInt32(kFSEventStreamEventFlagItemCreated) != 0 { kind = .created }
                    else if flag & UInt32(kFSEventStreamEventFlagItemRemoved) != 0 { kind = .deleted }
                    else if flag & UInt32(kFSEventStreamEventFlagItemRenamed) != 0 { kind = .renamed }

                    inventory.callback(FileChangeEvent(path: paths[i], kind: kind, timestamp: Date()))
                }
            },
            &context,
            cfPaths,
            FSEventStreamEventId(kFSEventStreamEventIdSinceNow),
            0.5, // latency in seconds
            flags
        )

        if let stream = stream {
            FSEventStreamSetDispatchQueue(stream, DispatchQueue.main)
            FSEventStreamStart(stream)
            print("[FileInventory] FSEvents watching: \(paths.joined(separator: ", "))")
        }
    }

    func stop() {
        if let stream = stream {
            FSEventStreamStop(stream)
            FSEventStreamInvalidate(stream)
            FSEventStreamRelease(stream)
            self.stream = nil
        }
    }
}
