import Foundation

public enum KeychainStoreError: Error, Equatable {
    case unsupportedPlatform
    case operationFailed(status: Int32)
}

public struct KeychainStore: SecretStore {
#if canImport(Security)
    private static let defaultAccessibility = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly as String
    private let serviceIdentifier: String
    private let accessibility: String?
#else
    private let serviceIdentifier: String
#endif

    public static var isSupported: Bool {
        #if canImport(Security)
        return true
        #else
        return false
        #endif
    }

    public init(service: String = "SecretStore", accessibility: String? = nil) {
#if canImport(Security)
        self.serviceIdentifier = service
        self.accessibility = accessibility ?? KeychainStore.defaultAccessibility
#else
        _ = accessibility
        self.serviceIdentifier = service
#endif
    }

    public func storeSecret(_ secret: Data, for key: String) throws {
        #if canImport(Security)
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceIdentifier,
            kSecAttrAccount as String: key,
            kSecValueData as String: secret
        ]
        if let accessibility = accessibility {
            query[kSecAttrAccessible as String] = accessibility
        }
        let status = SecItemAdd(query as CFDictionary, nil)
        if status == errSecDuplicateItem {
            let matchQuery: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: serviceIdentifier,
                kSecAttrAccount as String: key
            ]
            var attributes: [String: Any] = [kSecValueData as String: secret]
            if let accessibility = accessibility {
                attributes[kSecAttrAccessible as String] = accessibility
            }
            let updateStatus = SecItemUpdate(matchQuery as CFDictionary, attributes as CFDictionary)
            guard updateStatus == errSecSuccess else {
                throw KeychainStoreError.operationFailed(status: updateStatus)
            }
        } else if status != errSecSuccess {
            throw KeychainStoreError.operationFailed(status: status)
        }
        #else
        throw KeychainStoreError.unsupportedPlatform
        #endif
    }

    public func retrieveSecret(for key: String) throws -> Data? {
        #if canImport(Security)
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceIdentifier,
            kSecAttrAccount as String: key,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        if status == errSecItemNotFound {
            return nil
        }
        guard status == errSecSuccess, let data = item as? Data else {
            throw KeychainStoreError.operationFailed(status: status)
        }
        return data
        #else
        throw KeychainStoreError.unsupportedPlatform
        #endif
    }

    public func deleteSecret(for key: String) throws {
        #if canImport(Security)
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceIdentifier,
            kSecAttrAccount as String: key
        ]
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw KeychainStoreError.operationFailed(status: status)
        }
        #else
        throw KeychainStoreError.unsupportedPlatform
        #endif
    }
}

#if canImport(Security)
import Security
#endif
