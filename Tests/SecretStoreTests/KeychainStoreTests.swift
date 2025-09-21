import XCTest
@testable import SecretStore

final class KeychainStoreTests: XCTestCase {
    func testUnsupportedOnLinux() {
        #if os(Linux)
        let store = KeychainStore()
        XCTAssertThrowsError(try store.storeSecret(Data(), for: "key")) { error in
            guard case KeychainStoreError.unsupportedPlatform = error else {
                XCTFail("Expected unsupportedPlatform, got \(error)")
                return
            }
        }
        #else
        XCTAssertTrue(KeychainStore.isSupported)
        #endif
    }
}
