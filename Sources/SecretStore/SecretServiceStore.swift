import Foundation

public enum SecretServiceError: Error, Equatable {
    case commandFailed(code: Int32, message: String)
    case collectionMissing(message: String)
}

/// Secret Service backend that shells out to the `secret-tool` CLI.
public struct SecretServiceStore: SecretStore {
    private let runner: ProcessRunning
    private let service: String
    private let label: String
    private let trimsTrailingNewline: Bool

    public init(runner: ProcessRunning = ProcessRunner(), service: String, trimsTrailingNewline: Bool = true) {
        self.runner = runner
        self.service = service
        self.label = "SecretStore:\(service)"
        self.trimsTrailingNewline = trimsTrailingNewline
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
            let payload = trimsTrailingNewline ? result.stdout.normalizedSecretPayload : result.stdout
            return payload
        }
        if result.exitCode == 1 {
            return nil
        }
        throw error(for: result)
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
            throw error(for: result)
        }
    }

    private func error(for result: ProcessOutput) -> SecretServiceError {
        switch result.exitCode {
        case 2:
            return .collectionMissing(message: result.stderr.utf8String)
        default:
            return .commandFailed(code: result.exitCode, message: result.stderr.utf8String)
        }
    }
}

private extension Data {
    var utf8String: String {
        String(data: self, encoding: .utf8) ?? ""
    }

    var normalizedSecretPayload: Data {
        guard String(data: self, encoding: .utf8) != nil else {
            return self
        }
        if hasSuffix([0x0D, 0x0A]) {
            return Data(dropLast(2))
        }
        if hasSuffix([0x0A]) {
            return Data(dropLast())
        }
        return self
    }
}

private extension Data {
    func hasSuffix(_ bytes: [UInt8]) -> Bool {
        guard count >= bytes.count else { return false }
        return self.suffix(bytes.count) == Data(bytes)
    }
}
