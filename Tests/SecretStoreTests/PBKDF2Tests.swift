import XCTest
@testable import SecretStore

final class PBKDF2Tests: XCTestCase {
    func testVectorRFC6070() throws {
        let password = Data("password".utf8)
        let salt = Data("salt".utf8)
        let derived = try PBKDF2.deriveKey(password: password, salt: salt, iterations: 2, keyLength: 32)
        XCTAssertEqual(derived.hexString, "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43")
    }
}

private extension Data {
    var hexString: String {
        map { String(format: "%02x", $0) }.joined()
    }
}
