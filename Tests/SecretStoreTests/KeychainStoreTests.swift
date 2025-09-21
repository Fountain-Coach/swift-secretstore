import XCTest
@testable import SecretStore

final class KeychainStoreTests: XCTestCase {
    func testUnsupportedOnLinux() {
        #if os(Linux)
        XCTAssertFalse(KeychainStore.isSupported)
        let store = KeychainStore()
        XCTAssertThrowsError(try store.storeSecret(Data(), for: "key")) { error in
            guard case KeychainStoreError.unsupportedPlatform = error else {
                XCTFail("Expected unsupportedPlatform, got \(error)")
                return
            }
        }
        let configuredStore = KeychainStore(service: "com.example.service", accessibility: "ignored")
        XCTAssertThrowsError(try configuredStore.deleteSecret(for: "any")) { error in
            guard case KeychainStoreError.unsupportedPlatform = error else {
                XCTFail("Expected unsupportedPlatform, got \(error)")
                return
            }
        }
        XCTAssertThrowsError(try configuredStore.retrieveSecret(for: "any")) { error in
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
