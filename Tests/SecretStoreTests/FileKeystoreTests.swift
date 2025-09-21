import XCTest
@testable import SecretStore

final class FileKeystoreTests: XCTestCase {
    private var temporaryDirectory: URL!

    override func setUpWithError() throws {
        try super.setUpWithError()
        temporaryDirectory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: temporaryDirectory, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws {
        if let url = temporaryDirectory {
            try? FileManager.default.removeItem(at: url)
        }
        try super.tearDownWithError()
    }

    func testStoreRetrieveAndDeleteSecret() throws {
        let keystoreURL = temporaryDirectory.appendingPathComponent("keystore.json")
        let store = try FileKeystore(storeURL: keystoreURL, password: "passw0rd", iterations: 50_000)

        let secret = Data("super-secret".utf8)
        try store.storeSecret(secret, for: "api-token")

        XCTAssertEqual(try store.retrieveSecret(for: "api-token"), secret)

        try store.deleteSecret(for: "api-token")
        XCTAssertNil(try store.retrieveSecret(for: "api-token"))
    }

    func testInvalidConfigurationThrows() {
        let keystoreURL = temporaryDirectory.appendingPathComponent("keystore.json")
        XCTAssertThrowsError(try FileKeystore(storeURL: keystoreURL, password: "passw0rd", iterations: 0)) { error in
            guard case FileKeystoreError.invalidConfiguration = error else {
                XCTFail("Expected invalidConfiguration, got \(error)")
                return
            }
        }
    }

    func testTamperingDetection() throws {
        let keystoreURL = temporaryDirectory.appendingPathComponent("keystore.json")
        let store = try FileKeystore(storeURL: keystoreURL, password: "passw0rd", iterations: 20_000)

        try store.storeSecret(Data("value".utf8), for: "key")

        var contents = try Data(contentsOf: keystoreURL)
        XCTAssertFalse(contents.isEmpty)
        contents[contents.startIndex] = contents[contents.startIndex] ^ 0xFF
        try contents.write(to: keystoreURL, options: .atomic)

        XCTAssertThrowsError(try store.retrieveSecret(for: "key")) { error in
            guard case FileKeystoreError.decodingFailure = error else {
                XCTFail("Expected decoding failure, got \(error)")
                return
            }
        }
    }

    func testCorruptSaltTriggersIntegrityFailure() throws {
        let keystoreURL = temporaryDirectory.appendingPathComponent("keystore.json")
        let store = try FileKeystore(storeURL: keystoreURL, password: "passw0rd", iterations: 35_000)

        var payload = try JSONSerialization.jsonObject(with: Data(contentsOf: keystoreURL)) as! [String: Any]
        payload["salt"] = "@@@"
        let corrupted = try JSONSerialization.data(withJSONObject: payload, options: [.sortedKeys])
        try corrupted.write(to: keystoreURL, options: .atomic)

        XCTAssertThrowsError(try store.storeSecret(Data("secret".utf8), for: "key")) { error in
            guard case FileKeystoreError.integrityFailure = error else {
                XCTFail("Expected integrity failure, got \(error)")
                return
            }
        }
    }

    func testCorruptCiphertextTriggersIntegrityFailure() throws {
        let keystoreURL = temporaryDirectory.appendingPathComponent("keystore.json")
        let store = try FileKeystore(storeURL: keystoreURL, password: "passw0rd", iterations: 25_000)
        try store.storeSecret(Data("value".utf8), for: "key")

        var payload = try JSONSerialization.jsonObject(with: Data(contentsOf: keystoreURL)) as! [String: Any]
        var secrets = payload["secrets"] as! [String: String]
        let originalCombined = Data(base64Encoded: secrets["key"] ?? "") ?? Data()
        let zeros = Data(repeating: 0, count: originalCombined.count)
        secrets["key"] = zeros.base64EncodedString()
        payload["secrets"] = secrets
        let corrupted = try JSONSerialization.data(withJSONObject: payload, options: [.sortedKeys])
        try corrupted.write(to: keystoreURL, options: .atomic)

        XCTAssertThrowsError(try store.retrieveSecret(for: "key")) { error in
            guard case FileKeystoreError.integrityFailure = error else {
                XCTFail("Expected integrity failure, got \(error)")
                return
            }
        }
    }

    func testDecodingFailureIsSurfaced() throws {
        let keystoreURL = temporaryDirectory.appendingPathComponent("keystore.json")
        let malformedJSON = Data("{".utf8)
        try malformedJSON.write(to: keystoreURL)

        let store = try FileKeystore(storeURL: keystoreURL, password: "passw0rd", iterations: 10_000)

        XCTAssertThrowsError(try store.retrieveSecret(for: "anything")) { error in
            guard case FileKeystoreError.decodingFailure(let underlying) = error,
                  underlying is DecodingError else {
                XCTFail("Expected decoding failure, got \(error)")
                return
            }
        }
    }

    func testMissingStorePropagatesNotFound() throws {
        let keystoreURL = temporaryDirectory.appendingPathComponent("keystore.json")
        let store = try FileKeystore(storeURL: keystoreURL, password: "passw0rd", iterations: 10_000)
        try FileManager.default.removeItem(at: keystoreURL)

        XCTAssertThrowsError(try store.retrieveSecret(for: "any")) { error in
            guard case FileKeystoreError.notFound = error else {
                XCTFail("Expected notFound, got \(error)")
                return
            }
        }
    }

    func testCorruptBase64TriggersIntegrityFailure() throws {
        let keystoreURL = temporaryDirectory.appendingPathComponent("keystore.json")
        let store = try FileKeystore(storeURL: keystoreURL, password: "passw0rd", iterations: 40_000)
        try store.storeSecret(Data("secret".utf8), for: "key")

        var payload = try JSONSerialization.jsonObject(with: Data(contentsOf: keystoreURL)) as! [String: Any]
        var secrets = payload["secrets"] as! [String: String]
        secrets["key"] = "!!!invalid!!!"
        payload["secrets"] = secrets
        let corrupted = try JSONSerialization.data(withJSONObject: payload, options: [.sortedKeys])
        try corrupted.write(to: keystoreURL, options: .atomic)

        XCTAssertThrowsError(try store.retrieveSecret(for: "key")) { error in
            guard case FileKeystoreError.integrityFailure = error else {
                XCTFail("Expected integrity failure, got \(error)")
                return
            }
        }
    }

    func testReplacingStoreWithDirectoryProducesIOError() throws {
        let keystoreURL = temporaryDirectory.appendingPathComponent("keystore.json")
        let store = try FileKeystore(storeURL: keystoreURL, password: "passw0rd", iterations: 30_000)
        try store.storeSecret(Data("secret".utf8), for: "protected")

        try FileManager.default.removeItem(at: keystoreURL)
        try FileManager.default.createDirectory(at: keystoreURL, withIntermediateDirectories: false)

        XCTAssertThrowsError(try store.retrieveSecret(for: "protected")) { error in
            guard case FileKeystoreError.ioError(let underlying) = error,
                  let posixError = underlying as? POSIXError,
                  posixError.code == .EISDIR else {
                XCTFail("Expected IO error wrapping EISDIR, got \(error)")
                return
            }
        }
    }

    func testSymbolicLinkProducesPosixIOError() throws {
        let keystoreURL = temporaryDirectory.appendingPathComponent("keystore.json")
        let store = try FileKeystore(storeURL: keystoreURL, password: "passw0rd", iterations: 45_000)
        try store.storeSecret(Data("secret".utf8), for: "loop")

        try FileManager.default.removeItem(at: keystoreURL)
        try FileManager.default.createSymbolicLink(atPath: keystoreURL.path, withDestinationPath: keystoreURL.path)

        XCTAssertThrowsError(try store.retrieveSecret(for: "loop")) { error in
            guard case FileKeystoreError.ioError(let underlying) = error,
                  let posixError = underlying as? POSIXError,
                  posixError.code == .ELOOP else {
                XCTFail("Expected IO error wrapping ELOOP, got \(error)")
                return
            }
        }
    }

    func testUnsupportedURLSchemeProducesIOError() throws {
        final class StubFileManager: FileManager, @unchecked Sendable {
            override func fileExists(atPath path: String) -> Bool {
                true
            }
        }

        let keystoreURL = URL(string: "http://example.com/keystore.json")!
        let store = try FileKeystore(storeURL: keystoreURL, password: "passw0rd", iterations: 5_000, fileManager: StubFileManager())

        XCTAssertThrowsError(try store.retrieveSecret(for: "key")) { error in
            guard case FileKeystoreError.ioError(let underlying) = error,
                  let cocoaError = underlying as? CocoaError,
                  cocoaError.code == .fileReadUnsupportedScheme else {
                XCTFail("Expected IO error wrapping CocoaError, got \(error)")
                return
            }
        }
    }
}
