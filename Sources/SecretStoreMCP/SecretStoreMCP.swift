import Foundation
import SecretStore

@main
struct SecretStoreMCP {
    static func main() async {
        let env = ProcessInfo.processInfo.environment
        let manager = StoreManager(env: env)

        let server = StdioJsonRpcServer()
        await server.run { msg in
            switch msg.method {
            case "initialize":
                let result: [String: Any] = [
                    "protocolVersion": "2024-11-05",
                    "serverInfo": ["name": "SecretStoreMCP", "version": "0.1.1"],
                    "capabilities": [
                        "tools": ["listChanged": false],
                        "resources": ["listChanged": false],
                        "prompts": ["listChanged": false]
                    ]
                ]
                return JsonRpcReply.result(id: msg.id ?? NSNull(), value: result)
            case "initialized":
                return JsonRpcReply.none()
            case "shutdown":
                return JsonRpcReply.result(id: msg.id ?? NSNull(), value: NSNull())
            case "exit":
                return JsonRpcReply.exit()
            case "tools/list":
                return JsonRpcReply.result(id: msg.id ?? NSNull(), value: ["tools": toolSpecs()])
            case "tools/call":
                return manager.callTool(msg: msg)
            case "resources/list":
                return JsonRpcReply.result(id: msg.id ?? NSNull(), value: ["resources": []])
            case "resources/read":
                return JsonRpcReply.error(id: msg.id, code: -32000, message: "resources/read not supported")
            case "prompts/list":
                return JsonRpcReply.result(id: msg.id ?? NSNull(), value: ["prompts": []])
            case "prompts/get":
                return JsonRpcReply.error(id: msg.id, code: -32000, message: "prompts/get not supported")
            case "logging/setLevel":
                return JsonRpcReply.result(id: msg.id ?? NSNull(), value: NSNull())
            default:
                return JsonRpcReply.error(id: msg.id, code: -32601, message: "Method not found")
            }
        }
    }

    private static func toolSpecs() -> [[String: Any]] {
        [
            tool(name: "secretstore.backends", description: "List available backends.", properties: [:], required: []),
            tool(name: "secretstore.status", description: "Current backend configuration and readiness.", properties: [:], required: []),
            tool(
                name: "secretstore.configure",
                description: "Configure the backend and reinitialize the store.",
                properties: [
                    "backend": ["type": "string"],
                    "service": ["type": "string"],
                    "accessibility": ["type": "string"],
                    "trimsTrailingNewline": ["type": "boolean"],
                    "path": ["type": "string"],
                    "password": ["type": "string"],
                    "iterations": ["type": "integer"]
                ],
                required: ["backend"]
            ),
            tool(
                name: "secretstore.store",
                description: "Store or replace a secret.",
                properties: [
                    "key": ["type": "string"],
                    "secret": [
                        "type": "object",
                        "properties": [
                            "encoding": ["type": "string"],
                            "data": ["type": "string"]
                        ],
                        "required": ["data"]
                    ]
                ],
                required: ["key", "secret"]
            ),
            tool(
                name: "secretstore.retrieve",
                description: "Retrieve a secret by key.",
                properties: [
                    "key": ["type": "string"]
                ],
                required: ["key"]
            ),
            tool(
                name: "secretstore.delete",
                description: "Delete a secret by key.",
                properties: [
                    "key": ["type": "string"]
                ],
                required: ["key"]
            )
        ]
    }

    private static func tool(name: String, description: String, properties: [String: Any], required: [String]) -> [String: Any] {
        [
            "name": name,
            "description": description,
            "inputSchema": [
                "type": "object",
                "properties": properties,
                "required": required
            ]
        ]
    }
}

private final class StoreManager {
    private var config: StoreConfig
    private var store: (any SecretStore)?
    private var lastError: String?

    init(env: [String: String]) {
        self.config = StoreConfig.from(env: env)
        refreshStore()
    }

    func callTool(msg: JsonRpcMessage) -> JsonRpcReply {
        guard let params = msg.params as? [String: Any],
              let name = params["name"] as? String else {
            return JsonRpcReply.error(id: msg.id, code: -32602, message: "Missing tool name")
        }
        let args = params["arguments"] as? [String: Any] ?? [:]

        do {
            switch name {
            case "secretstore.backends":
                return JsonRpcReply.result(id: msg.id ?? NSNull(), value: ["items": config.backends(current: config.backend)])
            case "secretstore.status":
                return JsonRpcReply.result(id: msg.id ?? NSNull(), value: statusPayload())
            case "secretstore.configure":
                return configure(id: msg.id, args: args)
            case "secretstore.store":
                guard let key = args["key"] as? String else {
                    return JsonRpcReply.error(id: msg.id, code: -32602, message: "Missing key")
                }
                guard let secretValue = args["secret"],
                      let data = decodeSecret(secretValue) else {
                    return JsonRpcReply.error(id: msg.id, code: -32602, message: "Missing or invalid secret")
                }
                guard let store else {
                    return JsonRpcReply.error(id: msg.id, code: -32000, message: "SecretStore not configured", data: lastError)
                }
                try store.storeSecret(data, for: key)
                return JsonRpcReply.result(id: msg.id ?? NSNull(), value: ["status": "ok"])
            case "secretstore.retrieve":
                guard let key = args["key"] as? String else {
                    return JsonRpcReply.error(id: msg.id, code: -32602, message: "Missing key")
                }
                guard let store else {
                    return JsonRpcReply.error(id: msg.id, code: -32000, message: "SecretStore not configured", data: lastError)
                }
                let secret = try store.retrieveSecret(for: key)
                if let secret {
                    return JsonRpcReply.result(id: msg.id ?? NSNull(), value: encodeSecret(secret))
                }
                return JsonRpcReply.result(id: msg.id ?? NSNull(), value: ["found": false])
            case "secretstore.delete":
                guard let key = args["key"] as? String else {
                    return JsonRpcReply.error(id: msg.id, code: -32602, message: "Missing key")
                }
                guard let store else {
                    return JsonRpcReply.error(id: msg.id, code: -32000, message: "SecretStore not configured", data: lastError)
                }
                try store.deleteSecret(for: key)
                return JsonRpcReply.result(id: msg.id ?? NSNull(), value: ["status": "ok"])
            default:
                return JsonRpcReply.error(id: msg.id, code: -32601, message: "Unknown tool \(name)")
            }
        } catch {
            return JsonRpcReply.error(id: msg.id, code: -32000, message: "SecretStore error", data: "\(error)")
        }
    }

    private func configure(id: Any?, args: [String: Any]) -> JsonRpcReply {
        guard let backendRaw = args["backend"] as? String,
              let backend = StoreBackend(rawValue: backendRaw.lowercased()) else {
            return JsonRpcReply.error(id: id, code: -32602, message: "Invalid backend")
        }
        config.backend = backend
        if let service = args["service"] as? String { config.service = service }
        if let accessibility = args["accessibility"] as? String { config.accessibility = accessibility }
        if let trims = args["trimsTrailingNewline"] as? Bool { config.trimsTrailingNewline = trims }
        if let path = args["path"] as? String { config.filePath = path }
        if let password = args["password"] as? String { config.filePassword = password }
        if let iterations = args["iterations"] as? Int { config.iterations = iterations }
        refreshStore()
        return JsonRpcReply.result(id: id ?? NSNull(), value: statusPayload())
    }

    private func refreshStore() {
        do {
            store = try config.makeStore()
            lastError = nil
        } catch {
            store = nil
            lastError = "\(error)"
        }
    }

    private func statusPayload() -> [String: Any] {
        var payload: [String: Any] = [
            "backend": config.backend.rawValue,
            "service": config.service,
            "ready": store != nil,
            "trimsTrailingNewline": config.trimsTrailingNewline,
            "iterations": config.iterations
        ]
        payload["accessibility"] = config.accessibility ?? NSNull()
        payload["path"] = config.filePath ?? NSNull()
        payload["error"] = lastError ?? NSNull()
        return payload
    }

    private func decodeSecret(_ value: Any) -> Data? {
        if let str = value as? String {
            return Data(str.utf8)
        }
        guard let obj = value as? [String: Any],
              let data = obj["data"] as? String else {
            return nil
        }
        let encoding = (obj["encoding"] as? String)?.lowercased() ?? "utf8"
        switch encoding {
        case "base64":
            return Data(base64Encoded: data)
        case "utf8", "text", "string":
            return Data(data.utf8)
        default:
            return nil
        }
    }

    private func encodeSecret(_ data: Data) -> [String: Any] {
        var payload: [String: Any] = [
            "found": true,
            "encoding": "base64",
            "data": data.base64EncodedString()
        ]
        if let text = String(data: data, encoding: .utf8) {
            payload["utf8"] = text
        }
        payload["bytes"] = data.count
        return payload
    }
}

private enum StoreBackend: String {
    case keychain
    case secretService = "secret-service"
    case file
}

private struct StoreConfig {
    var backend: StoreBackend
    var service: String
    var accessibility: String?
    var trimsTrailingNewline: Bool
    var filePath: String?
    var filePassword: String?
    var iterations: Int

    static func from(env: [String: String]) -> StoreConfig {
        let backend = resolveBackend(env: env)
        let service = env["SECRETSTORE_SERVICE"] ?? "SecretStore"
        let accessibility = env["SECRETSTORE_ACCESSIBILITY"]
        let trims = boolEnv(env, "SECRETSTORE_TRIM_NEWLINE") ?? true
        let path = env["SECRETSTORE_PATH"] ?? env["SECRETSTORE_FILE"]
        let password = env["SECRETSTORE_PASSWORD"]
        let iterations = intEnv(env, "SECRETSTORE_ITERATIONS") ?? 100_000
        return StoreConfig(
            backend: backend,
            service: service,
            accessibility: accessibility,
            trimsTrailingNewline: trims,
            filePath: path,
            filePassword: password,
            iterations: iterations
        )
    }

    func backends(current: StoreBackend) -> [[String: Any]] {
        [
            [
                "name": StoreBackend.keychain.rawValue,
                "supported": KeychainStore.isSupported,
                "current": current == .keychain
            ],
            [
                "name": StoreBackend.secretService.rawValue,
                "supported": StoreConfig.isSecretServiceSupported,
                "current": current == .secretService
            ],
            [
                "name": StoreBackend.file.rawValue,
                "supported": true,
                "current": current == .file
            ]
        ]
    }

    func makeStore() throws -> any SecretStore {
        switch backend {
        case .keychain:
            if KeychainStore.isSupported {
                return KeychainStore(service: service, accessibility: accessibility)
            }
            throw StoreConfigError.unsupportedBackend(backend: backend.rawValue)
        case .secretService:
            #if os(Linux)
            return SecretServiceStore(service: service, trimsTrailingNewline: trimsTrailingNewline)
            #else
            throw StoreConfigError.unsupportedBackend(backend: backend.rawValue)
            #endif
        case .file:
            guard let path = filePath, !path.isEmpty else {
                throw StoreConfigError.missingValue(key: "SECRETSTORE_PATH")
            }
            guard let password = filePassword, !password.isEmpty else {
                throw StoreConfigError.missingValue(key: "SECRETSTORE_PASSWORD")
            }
            let iterations = max(1, self.iterations)
            return try FileKeystore(
                storeURL: URL(fileURLWithPath: path),
                password: password,
                iterations: iterations
            )
        }
    }

    private static func resolveBackend(env: [String: String]) -> StoreBackend {
        if let raw = env["SECRETSTORE_BACKEND"],
           let backend = StoreBackend(rawValue: raw.lowercased()) {
            return backend
        }
        let useSecretService = boolEnv(env, "USE_SECRET_SERVICE") ?? false
        if useSecretService {
            return .secretService
        }
        if KeychainStore.isSupported {
            return .keychain
        }
        return .file
    }

    private static var isSecretServiceSupported: Bool {
        #if os(Linux)
        return true
        #else
        return false
        #endif
    }

    private static func boolEnv(_ env: [String: String], _ key: String) -> Bool? {
        guard let raw = env[key]?.lowercased() else { return nil }
        if ["1", "true", "yes"].contains(raw) { return true }
        if ["0", "false", "no"].contains(raw) { return false }
        return nil
    }

    private static func intEnv(_ env: [String: String], _ key: String) -> Int? {
        guard let raw = env[key], !raw.isEmpty else { return nil }
        return Int(raw)
    }
}

private enum StoreConfigError: Error {
    case unsupportedBackend(backend: String)
    case missingValue(key: String)
}
