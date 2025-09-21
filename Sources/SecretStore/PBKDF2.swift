import Foundation
import Crypto

public enum PBKDF2Error: Error {
    case invalidParameters
}

/// Minimal PBKDF2-HMAC-SHA256 implementation backed by swift-crypto.
public enum PBKDF2 {
    public static func deriveKey(password: Data, salt: Data, iterations: Int, keyLength: Int) throws -> Data {
        guard !password.isEmpty, !salt.isEmpty, iterations > 0, keyLength > 0 else {
            throw PBKDF2Error.invalidParameters
        }

        let prfLength = SHA256.byteCount
        let blockCount = Int(ceil(Double(keyLength) / Double(prfLength)))
        var derivedBytes: [UInt8] = []
        derivedBytes.reserveCapacity(blockCount * prfLength)
        let key = SymmetricKey(data: password)

        for blockIndex in 1...blockCount {
            var saltBlock = Data()
            saltBlock.append(salt)
            var blockNumber = UInt32(blockIndex).bigEndian
            withUnsafeBytes(of: &blockNumber) { saltBlock.append(contentsOf: $0) }

            var u = Array(HMAC<SHA256>.authenticationCode(for: saltBlock, using: key))
            var block = u
            if iterations > 1 {
                for _ in 2...iterations {
                    u = Array(HMAC<SHA256>.authenticationCode(for: Data(u), using: key))
                    for index in 0..<block.count {
                        block[index] ^= u[index]
                    }
                }
            }
            derivedBytes.append(contentsOf: block)
        }

        return Data(derivedBytes.prefix(keyLength))
    }
}
