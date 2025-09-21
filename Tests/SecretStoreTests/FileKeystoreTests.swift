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

    func testTamperingDetection() throws {
        let keystoreURL = temporaryDirectory.appendingPathComponent("keystore.json")
        let store = try FileKeystore(storeURL: keystoreURL, password: "passw0rd", iterations: 20_000)

        try store.storeSecret(Data("value".utf8), for: "key")

        var contents = try Data(contentsOf: keystoreURL)
        XCTAssertFalse(contents.isEmpty)
        contents[contents.startIndex] = contents[contents.startIndex] ^ 0xFF
        try contents.write(to: keystoreURL, options: .atomic)

        XCTAssertThrowsError(try store.retrieveSecret(for: "key")) { error in
            guard case FileKeystoreError.integrityFailure = error else {
                XCTFail("Expected integrity failure, got \(error)")
                return
            }
        }
    }
}
