# swift-secretstore

`swift-secretstore` is a cross-platform secrets library that exposes a single `SecretStore`
protocol backed by platform-appropriate implementations. It ships with production-ready
stores for Apple platforms (Keychain), Linux desktops (Secret Service via `secret-tool`),
and headless Linux deployments (file-based keystore protected with ChaChaPoly and PBKDF2).

The project emphasises transparent, testable code: each backend is fully unit-tested and
keeps external interactions (like spawning `secret-tool`) behind small abstractions so
they can be mocked in tests.

## Features

- **Unified API** – A tiny `SecretStore` protocol with `store`, `retrieve`, and `delete`
  operations that work across backends.
- **Keychain backend** – `KeychainStore` integrates with the Apple Security framework when
  available and gracefully reports `unsupportedPlatform` on Linux builds.
- **Secret Service backend** – `SecretServiceStore` shells out to the `secret-tool`
  command, trimming trailing newlines from UTF-8 payloads by default while preserving
  binary data.
- **File keystore** – `FileKeystore` persists ChaChaPoly-encrypted secrets to disk using
  keys derived with PBKDF2-HMAC-SHA256 (provided by `swift-crypto`).
- **Process abstraction** – `ProcessRunner` centralises spawning external processes so the
  Linux backend can be tested without running real commands.
- **Extensive test suite** – Property-like checks cover success paths, error surfaces,
  tampering scenarios, and OS-specific behaviour. PBKDF2 is validated against known
  vectors.

## Installation

Add `swift-secretstore` to the dependency list in your `Package.swift`:

```swift
.package(url: "https://github.com/fountain-coach/swift-secretstore.git", from: "0.1.0")
```

Then depend on the `SecretStore` product from your target:

```swift
.target(
    name: "YourApp",
    dependencies: [
        .product(name: "SecretStore", package: "swift-secretstore")
    ]
)
```

## Usage

Select the backend that matches your deployment target and interact with it via the shared
protocol:

```swift
import SecretStore

let store: SecretStore
#if canImport(Security)
store = KeychainStore(service: "com.example.app")
#elseif os(Linux)
if ProcessInfo.processInfo.environment["USE_SECRET_SERVICE"] == "1" {
    store = SecretServiceStore(service: "com.example.app")
} else {
    let url = URL(fileURLWithPath: "/var/lib/example/keystore.json")
    store = try FileKeystore(storeURL: url, password: "change-me", iterations: 100_000)
}
#else
fatalError("No supported backend for this platform")
#endif

let secret = Data("super-secret-token".utf8)
try store.storeSecret(secret, for: "api-token")
let retrieved = try store.retrieveSecret(for: "api-token")
```

### Backend notes

- **KeychainStore**
  - Requires Apple platforms with the Security framework.
  - Allows configuring `service` and optional `accessibility` class (defaults to
    `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`).
- **SecretServiceStore**
  - Requires the `secret-tool` CLI (typically provided by `libsecret`) and access to a
    running Secret Service daemon.
  - Accepts a custom `ProcessRunning` implementation for dependency injection in tests.
  - Trims trailing `\n`/`\r\n` by default so secrets stored via the CLI round-trip cleanly.
- **FileKeystore**
  - Stores metadata and ciphertext in a JSON file alongside a random salt and iteration
    count.
  - Derives a 32-byte key from a user-supplied password using PBKDF2-HMAC-SHA256.
  - Uses ChaChaPoly for authenticated encryption and validates integrity before returning
    secrets.

## Platform support

| Backend             | macOS/iOS/tvOS/watchOS | Linux (Desktop) | Linux (Headless) |
|---------------------|------------------------|-----------------|------------------|
| KeychainStore       | ✅                     | ❌ (unsupported) | ❌                |
| SecretServiceStore  | ❌                     | ✅ (via secret-tool) | ⚠️ depends on D-Bus |
| FileKeystore        | ✅                     | ✅               | ✅                |

⚠️ `SecretServiceStore` assumes a running D-Bus session. For headless systems without D-Bus,
use `FileKeystore` instead.

## Development

Run the test suite locally before sending changes:

```bash
swift test --enable-code-coverage
```

The project strives to maintain complete test coverage; please ensure new behaviour is
accompanied by tests and keep coverage reports at 100% locally.

## Contributing

See [`AGENTS.md`](AGENTS.md) for details on the automation model, coverage expectations,
and security review requirements.

## License

Distributed under the terms of the [MIT License](LICENSE).
