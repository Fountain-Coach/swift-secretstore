import Foundation

public enum KeychainStoreError: Error, Equatable {
    case unsupportedPlatform
    case operationFailed(status: Int32)
}

public struct KeychainStore: SecretStore {
    public static var isSupported: Bool {
        #if canImport(Security)
        return true
        #else
        return false
        #endif
    }

    public init() {}

    public func storeSecret(_ secret: Data, for key: String) throws {
        #if canImport(Security)
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceIdentifier,
            kSecAttrAccount as String: key,
            kSecValueData as String: secret
        ]
        let status = SecItemAdd(query as CFDictionary, nil)
        if status == errSecDuplicateItem {
            let matchQuery: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: serviceIdentifier,
                kSecAttrAccount as String: key
            ]
            let attributes: [String: Any] = [kSecValueData as String: secret]
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

private let serviceIdentifier = "SecretStore"
#endif
