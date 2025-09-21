import XCTest
@testable import SecretStore

final class PBKDF2Tests: XCTestCase {
    func testVectorIteration1() throws {
        let password = Data("password".utf8)
        let salt = Data("salt".utf8)
        let derived = try PBKDF2.deriveKey(password: password, salt: salt, iterations: 1, keyLength: 32)
        XCTAssertEqual(derived.hexString, "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b")
    }

    func testVectorIteration2() throws {
        let password = Data("password".utf8)
        let salt = Data("salt".utf8)
        let derived = try PBKDF2.deriveKey(password: password, salt: salt, iterations: 2, keyLength: 32)
        XCTAssertEqual(derived.hexString, "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43")
    }

    func testVectorIteration4096() throws {
        let password = Data("password".utf8)
        let salt = Data("salt".utf8)
        let derived = try PBKDF2.deriveKey(password: password, salt: salt, iterations: 4096, keyLength: 32)
        XCTAssertEqual(derived.hexString, "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a")
    }

    func testMultipleBlocksAndLongInputs() throws {
        let password = Data("passwordPASSWORDpassword".utf8)
        let salt = Data("saltSALTsaltSALTsaltSALTsaltSALTsalt".utf8)
        let derived = try PBKDF2.deriveKey(password: password, salt: salt, iterations: 4096, keyLength: 40)
        XCTAssertEqual(derived.hexString, "348c89dbcbd32b2f32d814b8116e84cf2b17347ebc1800181c4e2a1fb8dd53e1c635518c7dac47e9")
    }

    func testInvalidParametersThrow() {
        XCTAssertThrowsError(try PBKDF2.deriveKey(password: Data(), salt: Data("salt".utf8), iterations: 1, keyLength: 32))
        XCTAssertThrowsError(try PBKDF2.deriveKey(password: Data("pwd".utf8), salt: Data(), iterations: 1, keyLength: 32))
        XCTAssertThrowsError(try PBKDF2.deriveKey(password: Data("pwd".utf8), salt: Data("salt".utf8), iterations: 0, keyLength: 32))
        XCTAssertThrowsError(try PBKDF2.deriveKey(password: Data("pwd".utf8), salt: Data("salt".utf8), iterations: 1, keyLength: 0))
    }
}

private extension Data {
    var hexString: String {
        map { String(format: "%02x", $0) }.joined()
    }
}
