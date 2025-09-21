import Foundation

/// A type that can persist arbitrary secret data by key.
public protocol SecretStore {
    /// Stores or replaces the secret for the provided key.
    func storeSecret(_ secret: Data, for key: String) throws

    /// Retrieves the secret for the provided key.
    func retrieveSecret(for key: String) throws -> Data?

    /// Deletes the secret for the provided key.
    func deleteSecret(for key: String) throws
}
