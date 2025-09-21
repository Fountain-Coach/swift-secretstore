import XCTest
@testable import SecretStore

final class SecretServiceStoreTests: XCTestCase {
    func testStoreRetrieveDeleteFlow() throws {
        let runner = MockProcessRunner()
        runner.stubbedResults = [
            ProcessOutput(exitCode: 0, stdout: Data(), stderr: Data()),
            ProcessOutput(exitCode: 0, stdout: Data("retrieved-value\r\n".utf8), stderr: Data()),
            ProcessOutput(exitCode: 0, stdout: Data(), stderr: Data())
        ]
        let store = SecretServiceStore(runner: runner, service: "example")

        try store.storeSecret(Data("secret".utf8), for: "account")
        XCTAssertEqual(try store.retrieveSecret(for: "account"), Data("retrieved-value".utf8))
        try store.deleteSecret(for: "account")

        XCTAssertEqual(runner.invocations.count, 3)
        XCTAssertEqual(runner.invocations[0], ["secret-tool", "store", "--label", "SecretStore:example", "service", "example", "account", "account"])
        XCTAssertEqual(runner.invocations[1], ["secret-tool", "lookup", "service", "example", "account", "account"])
        XCTAssertEqual(runner.invocations[2], ["secret-tool", "clear", "service", "example", "account", "account"])
    }

    func testLookupMissingSecretReturnsNil() throws {
        let runner = MockProcessRunner()
        runner.stubbedResults = [
            ProcessOutput(exitCode: 1, stdout: Data(), stderr: Data("No such secret".utf8))
        ]
        let store = SecretServiceStore(runner: runner, service: "example")

        XCTAssertNil(try store.retrieveSecret(for: "missing"))
    }

    func testBinaryPayloadIsReturnedUnchanged() throws {
        let runner = MockProcessRunner()
        let payload = Data([0x00, 0x01, 0x0A])
        runner.stubbedResults = [
            ProcessOutput(exitCode: 0, stdout: payload, stderr: Data())
        ]
        let store = SecretServiceStore(runner: runner, service: "example", trimsTrailingNewline: false)

        XCTAssertEqual(try store.retrieveSecret(for: "binary"), payload)
    }

    func testLookupWithUnixNewlineIsTrimmed() throws {
        let runner = MockProcessRunner()
        runner.stubbedResults = [
            ProcessOutput(exitCode: 0, stdout: Data("value\n".utf8), stderr: Data())
        ]
        let store = SecretServiceStore(runner: runner, service: "example")

        XCTAssertEqual(try store.retrieveSecret(for: "unix"), Data("value".utf8))
    }

    func testLookupWithNonUTF8PayloadIsReturnedVerbatim() throws {
        let runner = MockProcessRunner()
        let payload = Data([0xFF, 0xFE, 0x0A])
        runner.stubbedResults = [
            ProcessOutput(exitCode: 0, stdout: payload, stderr: Data())
        ]
        let store = SecretServiceStore(runner: runner, service: "example")

        XCTAssertEqual(try store.retrieveSecret(for: "binary"), payload)
    }

    func testLookupWithoutTrailingNewlineReturnsOriginalPayload() throws {
        let runner = MockProcessRunner()
        let payload = Data("value".utf8)
        runner.stubbedResults = [
            ProcessOutput(exitCode: 0, stdout: payload, stderr: Data())
        ]
        let store = SecretServiceStore(runner: runner, service: "example")

        XCTAssertEqual(try store.retrieveSecret(for: "plain"), payload)
    }

    func testLookupWithCarriageReturnOnlyPreservesPayload() throws {
        let runner = MockProcessRunner()
        let payload = Data("\r".utf8)
        runner.stubbedResults = [
            ProcessOutput(exitCode: 0, stdout: payload, stderr: Data())
        ]
        let store = SecretServiceStore(runner: runner, service: "example")

        XCTAssertEqual(try store.retrieveSecret(for: "carriage"), payload)
    }

    func testCommandFailureThrows() throws {
        let runner = MockProcessRunner()
        runner.stubbedResults = [
            ProcessOutput(exitCode: 2, stdout: Data(), stderr: Data("boom".utf8))
        ]
        let store = SecretServiceStore(runner: runner, service: "example")

        XCTAssertThrowsError(try store.deleteSecret(for: "account")) { error in
            guard case SecretServiceError.collectionMissing(let message) = error else {
                XCTFail("Expected collectionMissing, got \(error)")
                return
            }
            XCTAssertEqual(message, "boom")
        }
    }

    func testLookupCollectionMissingSurfacesError() throws {
        let runner = MockProcessRunner()
        runner.stubbedResults = [
            ProcessOutput(exitCode: 2, stdout: Data(), stderr: Data("missing".utf8))
        ]
        let store = SecretServiceStore(runner: runner, service: "example")

        XCTAssertThrowsError(try store.retrieveSecret(for: "account")) { error in
            guard case SecretServiceError.collectionMissing(let message) = error else {
                XCTFail("Expected collectionMissing, got \(error)")
                return
            }
            XCTAssertEqual(message, "missing")
        }
    }

    func testUnexpectedFailureIncludesExitCode() throws {
        let runner = MockProcessRunner()
        runner.stubbedResults = [
            ProcessOutput(exitCode: 77, stdout: Data(), stderr: Data("fatal".utf8))
        ]
        let store = SecretServiceStore(runner: runner, service: "example")

        XCTAssertThrowsError(try store.storeSecret(Data(), for: "account")) { error in
            guard case SecretServiceError.commandFailed(let code, let message) = error else {
                XCTFail("Expected commandFailed, got \(error)")
                return
            }
            XCTAssertEqual(code, 77)
            XCTAssertEqual(message, "fatal")
        }
    }

    func testCommandFailureGracefullyHandlesInvalidUTF8() throws {
        let runner = MockProcessRunner()
        runner.stubbedResults = [
            ProcessOutput(exitCode: 9, stdout: Data(), stderr: Data([0xFF]))
        ]
        let store = SecretServiceStore(runner: runner, service: "example")

        XCTAssertThrowsError(try store.deleteSecret(for: "garbage")) { error in
            guard case SecretServiceError.commandFailed(let code, let message) = error else {
                XCTFail("Expected commandFailed, got \(error)")
                return
            }
            XCTAssertEqual(code, 9)
            XCTAssertEqual(message, "")
        }
    }
}

private final class MockProcessRunner: ProcessRunning {
    var stubbedResults: [ProcessOutput] = []
    private(set) var invocations: [[String]] = []

    func run(_ command: [String], input: Data?) throws -> ProcessOutput {
        invocations.append(command)
        guard !stubbedResults.isEmpty else {
            fatalError("No stubbed results left")
        }
        return stubbedResults.removeFirst()
    }
}
