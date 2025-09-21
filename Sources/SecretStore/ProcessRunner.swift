import Foundation

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

        let stdinPipe: Pipe?
        if let input = input {
            let pipe = Pipe()
            stdinPipe = pipe
            process.standardInput = pipe
            try process.run()
            pipe.fileHandleForWriting.write(input)
            try pipe.fileHandleForWriting.close()
        } else {
            stdinPipe = nil
            try process.run()
        }

        _ = stdinPipe // keep strong reference until process exits
        process.waitUntilExit()

        let stdout = stdoutPipe.fileHandleForReading.readDataToEndOfFile()
        let stderr = stderrPipe.fileHandleForReading.readDataToEndOfFile()
        return ProcessOutput(exitCode: process.terminationStatus, stdout: stdout, stderr: stderr)
    }
}
