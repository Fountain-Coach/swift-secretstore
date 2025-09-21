import XCTest
@testable import SecretStore

final class SecretServiceStoreTests: XCTestCase {
    func testStoreRetrieveDeleteFlow() throws {
        let runner = MockProcessRunner()
        runner.stubbedResults = [
            .success(""),
            .success("retrieved-value"),
            .success("")
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
            .failure(exitCode: 1, stderr: "No such secret")
        ]
        let store = SecretServiceStore(runner: runner, service: "example")

        XCTAssertNil(try store.retrieveSecret(for: "missing"))
    }

    func testCommandFailureThrows() throws {
        let runner = MockProcessRunner()
        runner.stubbedResults = [
            .failure(exitCode: 2, stderr: "boom")
        ]
        let store = SecretServiceStore(runner: runner, service: "example")

        XCTAssertThrowsError(try store.deleteSecret(for: "account"))
    }
}

private final class MockProcessRunner: ProcessRunning {
    enum Result {
        case success(String)
        case failure(exitCode: Int32, stderr: String)
    }

    var stubbedResults: [Result] = []
    private(set) var invocations: [[String]] = []

    func run(_ command: [String], input: Data?) throws -> ProcessOutput {
        invocations.append(command)
        guard !stubbedResults.isEmpty else {
            fatalError("No stubbed results left")
        }
        switch stubbedResults.removeFirst() {
        case .success(let stdout):
            return ProcessOutput(exitCode: 0, stdout: Data(stdout.utf8), stderr: Data())
        case .failure(let exitCode, let stderr):
            return ProcessOutput(exitCode: exitCode, stdout: Data(), stderr: Data(stderr.utf8))
        }
    }
}
