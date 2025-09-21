import Foundation

public enum SecretServiceError: Error, Equatable {
    case commandFailed(code: Int32, message: String)
}

/// Secret Service backend that shells out to the `secret-tool` CLI.
public struct SecretServiceStore: SecretStore {
    private let runner: ProcessRunning
    private let service: String
    private let label: String

    public init(runner: ProcessRunning = ProcessRunner(), service: String) {
        self.runner = runner
        self.service = service
        self.label = "SecretStore:\(service)"
    }

    public func storeSecret(_ secret: Data, for key: String) throws {
        let command = [
            "secret-tool",
            "store",
            "--label",
            label,
            "service",
            service,
            "account",
            key
        ]
        let result = try runner.run(command, input: secret)
        try ensureSuccess(result)
    }

    public func retrieveSecret(for key: String) throws -> Data? {
        let command = [
            "secret-tool",
            "lookup",
            "service",
            service,
            "account",
            key
        ]
        let result = try runner.run(command, input: nil)
        if result.exitCode == 0 {
            return result.stdout
        }
        if result.exitCode == 1 {
            return nil
        }
        throw SecretServiceError.commandFailed(code: result.exitCode, message: result.stderr.utf8String)
    }

    public func deleteSecret(for key: String) throws {
        let command = [
            "secret-tool",
            "clear",
            "service",
            service,
            "account",
            key
        ]
        let result = try runner.run(command, input: nil)
        try ensureSuccess(result)
    }

    private func ensureSuccess(_ result: ProcessOutput) throws {
        guard result.exitCode == 0 else {
            throw SecretServiceError.commandFailed(code: result.exitCode, message: result.stderr.utf8String)
        }
    }
}

private extension Data {
    var utf8String: String {
        String(data: self, encoding: .utf8) ?? ""
    }
}
