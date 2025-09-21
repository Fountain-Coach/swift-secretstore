import Foundation
import Crypto

public enum FileKeystoreError: Error, Equatable {
    case integrityFailure
    case invalidConfiguration
}

/// Headless keystore that persists AEAD-encrypted secrets to disk.
public final class FileKeystore: SecretStore {
    private struct KeystoreFile: Codable {
        var salt: String
        var iterations: Int
        var secrets: [String: String]
    }

    private let storeURL: URL
    private let passwordData: Data
    private let defaultIterations: Int
    private let encoder = JSONEncoder()
    private let decoder = JSONDecoder()

    public init(storeURL: URL, password: String, iterations: Int, fileManager: FileManager = .default) throws {
        guard iterations > 0 else {
            throw FileKeystoreError.invalidConfiguration
        }
        self.storeURL = storeURL
        self.passwordData = Data(password.utf8)
        self.defaultIterations = iterations

        if !fileManager.fileExists(atPath: storeURL.path) {
            try createEmptyStore()
        }
    }

    public func storeSecret(_ secret: Data, for key: String) throws {
        var keystore = try loadStore()
        let symmetricKey = try deriveKey(from: keystore)
        let nonce = ChaChaPoly.Nonce()
        let sealedBox = try ChaChaPoly.seal(secret, using: symmetricKey, nonce: nonce)
        keystore.secrets[key] = sealedBox.combined.base64EncodedString()
        try writeStore(keystore)
    }

    public func retrieveSecret(for key: String) throws -> Data? {
        let keystore = try loadStore()
        guard let encoded = keystore.secrets[key], let combined = Data(base64Encoded: encoded) else {
            return nil
        }
        let symmetricKey = try deriveKey(from: keystore)
        do {
            let sealedBox = try ChaChaPoly.SealedBox(combined: combined)
            return try ChaChaPoly.open(sealedBox, using: symmetricKey)
        } catch {
            throw FileKeystoreError.integrityFailure
        }
    }

    public func deleteSecret(for key: String) throws {
        var keystore = try loadStore()
        keystore.secrets.removeValue(forKey: key)
        try writeStore(keystore)
    }

    private func loadStore() throws -> KeystoreFile {
        do {
            let data = try Data(contentsOf: storeURL)
            let keystore = try decoder.decode(KeystoreFile.self, from: data)
            guard Data(base64Encoded: keystore.salt) != nil else {
                throw FileKeystoreError.integrityFailure
            }
            return keystore
        } catch {
            throw FileKeystoreError.integrityFailure
        }
    }

    private func deriveKey(from keystore: KeystoreFile) throws -> SymmetricKey {
        guard let salt = Data(base64Encoded: keystore.salt) else {
            throw FileKeystoreError.integrityFailure
        }
        let keyMaterial = try PBKDF2.deriveKey(password: passwordData, salt: salt, iterations: keystore.iterations, keyLength: 32)
        return SymmetricKey(data: keyMaterial)
    }

    private func writeStore(_ keystore: KeystoreFile) throws {
        let data = try encoder.encode(keystore)
        try data.write(to: storeURL, options: .atomic)
    }

    private func createEmptyStore() throws {
        let salt = try randomSalt(count: 16)
        let keystore = KeystoreFile(salt: salt.base64EncodedString(), iterations: defaultIterations, secrets: [:])
        try writeStore(keystore)
    }

    private func randomSalt(count: Int) throws -> Data {
        var generator = SystemRandomNumberGenerator()
        var bytes: [UInt8] = []
        bytes.reserveCapacity(count)
        for _ in 0..<count {
            bytes.append(UInt8.random(in: UInt8.min...UInt8.max, using: &generator))
        }
        return Data(bytes)
    }
}
