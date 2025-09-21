import Foundation
import Crypto

public enum FileKeystoreError: Error {
    case integrityFailure
    case invalidConfiguration
    case notFound
    case ioError(underlying: Error)
    case decodingFailure(underlying: Error)
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
        guard let encoded = keystore.secrets[key] else {
            return nil
        }
        guard let combined = Data(base64Encoded: encoded) else {
            throw FileKeystoreError.integrityFailure
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
            do {
                let keystore = try decoder.decode(KeystoreFile.self, from: data)
                _ = try decodedSalt(from: keystore.salt)
                return keystore
            } catch let error as FileKeystoreError {
                throw error
            } catch {
                throw FileKeystoreError.decodingFailure(underlying: error)
            }
        } catch let fileError as FileKeystoreError {
            throw fileError
        } catch {
            if let cocoaError = error as? CocoaError {
                if cocoaError.code == .fileReadNoSuchFile {
                    throw FileKeystoreError.notFound
                }
                if let posix = cocoaError.userInfo[NSUnderlyingErrorKey] as? POSIXError {
                    throw FileKeystoreError.ioError(underlying: posix)
                }
            }
            throw FileKeystoreError.ioError(underlying: error)
        }
    }

    private func deriveKey(from keystore: KeystoreFile) throws -> SymmetricKey {
        let salt = try decodedSalt(from: keystore.salt)
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

    private func decodedSalt(from base64: String) throws -> Data {
        guard let data = Data(base64Encoded: base64) else {
            throw FileKeystoreError.integrityFailure
        }
        return data
    }
}
