import Foundation
import Dispatch

/// The output from invoking an external process.
public struct ProcessOutput {
    public let exitCode: Int32
    public let stdout: Data
    public let stderr: Data

    public init(exitCode: Int32, stdout: Data, stderr: Data) {
        self.exitCode = exitCode
        self.stdout = stdout
        self.stderr = stderr
    }
}

/// Abstraction over invoking command line tools so the Secret Service backend can be tested.
public protocol ProcessRunning {
    func run(_ command: [String], input: Data?) throws -> ProcessOutput
}

public enum ProcessRunnerError: Error {
    case missingExecutable
}

/// Default implementation that shells out using `Process`.
public final class ProcessRunner: ProcessRunning {
    public init() {}

    public func run(_ command: [String], input: Data?) throws -> ProcessOutput {
        guard let executable = command.first else {
            throw ProcessRunnerError.missingExecutable
        }

        let process = Process()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = Array(command.dropFirst())

        let stdoutPipe = Pipe()
        let stderrPipe = Pipe()
        process.standardOutput = stdoutPipe
        process.standardError = stderrPipe

        final class DataCollector: @unchecked Sendable {
            private var buffer = Data()
            private let lock = NSLock()

            func append(_ data: Data) {
                guard !data.isEmpty else { return }
                lock.lock()
                buffer.append(data)
                lock.unlock()
            }

            func data() -> Data {
                lock.lock()
                let snapshot = buffer
                lock.unlock()
                return snapshot
            }
        }

        let stdoutCollector = DataCollector()
        let stderrCollector = DataCollector()
        let dispatchGroup = DispatchGroup()

        func drain(_ handle: FileHandle, into collector: DataCollector) {
            dispatchGroup.enter()
            let workItem = DispatchWorkItem {
                defer {
                    handle.closeFile()
                    dispatchGroup.leave()
                }
                while true {
                    let chunk = handle.readData(ofLength: 64 * 1024)
                    if chunk.isEmpty {
                        break
                    }
                    collector.append(chunk)
                }
            }
            DispatchQueue.global(qos: .userInitiated).async(execute: workItem)
        }

        let stdinPipe: Pipe?
        if input != nil {
            let pipe = Pipe()
            stdinPipe = pipe
            process.standardInput = pipe
        } else {
            stdinPipe = nil
        }

        do {
            try process.run()
        } catch {
            stdinPipe?.fileHandleForWriting.closeFile()
            throw error
        }

        drain(stdoutPipe.fileHandleForReading, into: stdoutCollector)
        drain(stderrPipe.fileHandleForReading, into: stderrCollector)

        if let inputPipe = stdinPipe, let payload = input {
            if !payload.isEmpty {
                inputPipe.fileHandleForWriting.write(payload)
            }
            inputPipe.fileHandleForWriting.closeFile()
        }

        _ = stdinPipe // keep strong reference until process exits
        process.waitUntilExit()
        dispatchGroup.wait()

        return ProcessOutput(exitCode: process.terminationStatus, stdout: stdoutCollector.data(), stderr: stderrCollector.data())
    }
}
