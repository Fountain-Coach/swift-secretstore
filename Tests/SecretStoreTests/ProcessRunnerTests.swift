import XCTest
@testable import SecretStore

final class ProcessRunnerTests: XCTestCase {
    func testRunCapturesStdoutAndStderr() throws {
        let runner = ProcessRunner()
        let output = try runner.run(["/bin/sh", "-c", "printf out; printf err 1>&2"], input: nil)

        XCTAssertEqual(output.exitCode, 0)
        XCTAssertEqual(String(data: output.stdout, encoding: .utf8), "out")
        XCTAssertEqual(String(data: output.stderr, encoding: .utf8), "err")
    }

    func testRunWithInputPipesData() throws {
        let runner = ProcessRunner()
        let payload = Data("payload".utf8)
        let output = try runner.run(["/bin/sh", "-c", "cat"], input: payload)

        XCTAssertEqual(output.exitCode, 0)
        XCTAssertEqual(output.stdout, payload)
        XCTAssertTrue(output.stderr.isEmpty)
    }

    func testRunHandlesLargeStdoutWithoutDeadlock() throws {
        let runner = ProcessRunner()
        let command = [
            "/bin/sh",
            "-c",
            "yes X | head -c 131072"
        ]

        let output = try runner.run(command, input: nil)

        XCTAssertEqual(output.exitCode, 0)
        XCTAssertEqual(output.stdout.count, 131072)
        XCTAssertTrue(output.stderr.isEmpty)
    }

    func testMissingExecutableThrows() {
        let runner = ProcessRunner()
        XCTAssertThrowsError(try runner.run([], input: nil)) { error in
            guard case ProcessRunnerError.missingExecutable = error else {
                XCTFail("Expected missingExecutable, got \(error)")
                return
            }
        }
    }

    func testLaunchFailureClosesInputPipe() {
        let runner = ProcessRunner()
        let bogusPath = "/this/path/does/not/exist"

        XCTAssertThrowsError(try runner.run([bogusPath], input: Data("payload".utf8))) { error in
            guard let posix = error as? POSIXError else {
                return
            }
            XCTAssertEqual(posix.code, .ENOENT)
        }
    }
}
