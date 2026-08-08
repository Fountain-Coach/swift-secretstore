import Foundation

/// WHAT THE PERSON AT THE KEYBOARD DECIDED.
///
/// Reading a secret's data can put a system dialog in front of someone and wait. Whatever they do next — allow,
/// cancel, walk away — is an ANSWER, and it is the only part of the exchange the application cannot reconstruct
/// afterwards. A store that returns `nil` for "there is no such key" and `nil` for "they pressed Cancel" has
/// destroyed the one fact that was theirs.
///
/// Reported against Reframe (2026-08-08): "Copilot doesn't react properly on user dismissal of keychain dialogue."
/// It could not react. `try? keychain.retrieveSecret(...)` flattened the cancel into the same `nil` as an absent
/// item, so by the time anything could have spoken, the decision no longer existed anywhere in the process.
///
/// So the choice is a value, and publishing it is the STORE's obligation rather than each caller's diligence —
/// see `SecretAccessLog`. A caller may ignore what it hears; it may not fail to be told.
public enum SecretAccessDecision: Sendable, Equatable {

    /// The secret was handed over — either the person allowed it just now, or they had allowed it before.
    ///
    /// Deliberately does not distinguish those two: the store cannot tell them apart (macOS does not report
    /// whether a dialog was shown), and a value that claims a distinction it cannot support is worse than one
    /// that does not.
    case released

    /// There is a secret, and it was not handed over. The person declined, in the moment.
    ///
    /// Not an error. Someone deciding not to release their credential is the system working, and an application
    /// that reports it as a failure is arguing with them about their own act.
    case withheld(WithheldReason)

    /// No such secret. Nobody was asked anything, so nobody decided anything — never to be conflated with
    /// `withheld`, which is the distinction whose loss caused the original defect.
    case absent

    /// The lookup itself failed, for a reason that is not about a person. Carries the raw `OSStatus`, because a
    /// remedy depends on which one it was.
    case failed(status: Int32)

    /// HOW it was withheld. Different remedies, so they are different cases.
    public enum WithheldReason: Sendable, Equatable {
        /// They dismissed or cancelled the dialog (`errSecUserCanceled`). A decision; ask again only if they act.
        case dismissed
        /// They tried and it did not authenticate (`errSecAuthFailed`) — a password typed wrong, a Touch ID that
        /// did not read. Unlike `dismissed`, retrying is reasonable.
        case authenticationFailed
        /// The system would not put the dialog up at all (`errSecInteractionNotAllowed`) — a locked keychain, or
        /// a context with no UI. Nobody was actually asked, but the secret is still withheld.
        case interactionNotAllowed

        public var isSomeoneSayingNo: Bool {
            self != .interactionNotAllowed
        }
    }

    /// Whether a person was actually put in front of a choice and made one. What a surface should speak about.
    public var reflectsAHumanChoice: Bool {
        switch self {
        case .withheld(let reason): return reason.isSomeoneSayingNo
        case .released, .absent, .failed: return false
        }
    }

    /// A plain sentence, so a surface reporting this does not have to invent one — and so two surfaces reporting
    /// the same decision cannot describe it differently.
    public var summary: String {
        switch self {
        case .released: return "the secret was released"
        case .withheld(.dismissed): return "the dialog was dismissed, so the secret stayed locked"
        case .withheld(.authenticationFailed): return "authentication did not succeed, so the secret stayed locked"
        case .withheld(.interactionNotAllowed): return "the system would not ask, so the secret stayed locked"
        case .absent: return "there is no such secret"
        case .failed(let status): return "the lookup failed (OSStatus \(status))"
        }
    }
}

#if canImport(Security)
import Security

extension SecretAccessDecision {
    /// CLASSIFY THE STATUS, ONCE, HERE.
    ///
    /// Every caller that switched on `OSStatus` itself was a place the cancel could be mistranslated, and the
    /// codes that mean "a person declined" are not obvious from their names. Doing it in one place means a caller
    /// cannot get it subtly wrong, and means adding a code later fixes every caller at once.
    public init(status: OSStatus) {
        switch status {
        case errSecSuccess: self = .released
        case errSecItemNotFound: self = .absent
        case errSecUserCanceled: self = .withheld(.dismissed)
        case errSecAuthFailed: self = .withheld(.authenticationFailed)
        case errSecInteractionNotAllowed: self = .withheld(.interactionNotAllowed)
        default: self = .failed(status: status)
        }
    }
}
#endif

/// WHERE DECISIONS ARE ANNOUNCED — the store's obligation, not the caller's diligence.
///
/// The alternative was an overload that takes an observer, which any caller can simply not use; the defect being
/// fixed was precisely a caller not carrying the fact onward. So the store publishes on EVERY retrieval that could
/// have prompted, whether or not anyone is listening, and a consumer subscribes once rather than at each call site.
///
/// Deliberately not `NotificationCenter`: a decision about someone's credential should not be readable by every
/// object in the process, and it must not be posted as `Any` that a listener has to guess the shape of.
public final class SecretAccessLog: @unchecked Sendable {

    /// The process-wide log every `KeychainStore` publishes to.
    public static let shared = SecretAccessLog()

    /// A decision, with the secret it concerned. The VALUE is never carried — only what happened to it.
    public struct Event: Sendable, Equatable {
        public let decision: SecretAccessDecision
        public let service: String
        public let account: String
        public let at: Date

        public init(decision: SecretAccessDecision, service: String, account: String, at: Date = Date()) {
            self.decision = decision
            self.service = service
            self.account = account
            self.at = at
        }
    }

    private let lock = NSLock()
    private var observers: [UUID: @Sendable (Event) -> Void] = [:]
    private var recent: [Event] = []

    public init() {}

    /// Subscribe. The returned token unsubscribes when released or cancelled.
    ///
    /// Late subscribers are given what already happened (`recentEvents`) rather than nothing: a decision made
    /// during launch, before the surface existed, is exactly the one worth hearing about.
    @discardableResult
    public func observe(_ handler: @escaping @Sendable (Event) -> Void) -> Subscription {
        let id = UUID()
        lock.lock()
        observers[id] = handler
        let backlog = recent
        lock.unlock()
        backlog.forEach(handler)
        return Subscription(id: id, log: self)
    }

    public final class Subscription: Sendable {
        private let id: UUID
        private let log: SecretAccessLog

        init(id: UUID, log: SecretAccessLog) {
            self.id = id
            self.log = log
        }

        public func cancel() { log.remove(id) }
        deinit { log.remove(id) }
    }

    /// Publish. Called by the store on every retrieval that could have prompted.
    public func record(_ event: Event) {
        lock.lock()
        // Bounded: this is a live signal, not an audit trail, and an unbounded array in a long-running app is a
        // leak. Enough to hand a surface that subscribes moments after launch.
        recent.append(event)
        if recent.count > 32 { recent.removeFirst(recent.count - 32) }
        let handlers = Array(observers.values)
        lock.unlock()
        handlers.forEach { $0(event) }
    }

    /// What has already been decided, oldest first.
    public var recentEvents: [Event] {
        lock.lock()
        defer { lock.unlock() }
        return recent
    }

    private func remove(_ id: UUID) {
        lock.lock()
        observers[id] = nil
        lock.unlock()
    }
}
