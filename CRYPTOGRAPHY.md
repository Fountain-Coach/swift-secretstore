# Cryptography

This repository does not implement novel cryptographic primitives.

The file keystore uses:

- PBKDF2-HMAC-SHA256 for password-based key derivation;
- a random salt stored with the encrypted keystore metadata;
- ChaCha20-Poly1305 through Swift Crypto for authenticated encryption.

Known-answer tests cover PBKDF2 behavior and file-keystore tests cover ciphertext/salt corruption and tamper refusal.

Cryptographic policy is separate from authorization policy. Possession of a decrypting credential or successful retrieval does not itself authorize a higher-level application operation.
