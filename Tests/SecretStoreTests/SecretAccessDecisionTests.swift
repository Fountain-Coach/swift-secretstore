import XCTest
@testable import SecretStore

#if canImport(Security)
import Security
#endif

/// A CANCEL IS NOT AN ABSENCE.
///
/// Reported against Reframe (2026-08-08): "Copilot doesn't react properly on user dismissal of keychain dialogue."
/// It could not. `try? keychain.retrieveSecret(...)` flattened `errSecUserCanceled` into the same `nil` as
/// `errSecItemNotFound`, so the person's decision stopped existing inside the process before anything could speak
/// about it.
///
/// These tests hold the two halves of the repair: the decision is CLASSIFIED correctly in one place, and it is
/// ANNOUNCED by the store rather than by whichever caller remembers to.
final class SecretAccessDecisionTests: XCTestCase {

    // MARK: - Classification

#if canImport(Security)
    /// THE INCIDENT. These two must never be the same value, because they call for opposite responses: one is a
    /// person declining, the other is nothing to decline.
    func testDismissalAndAbsenceAreDifferentDecisions() {
        let dismissed = SecretAccessDecision(status: errSecUserCanceled)
        let absent = SecretAccessDecision(status: errSecItemNotFound)

        XCTAssertEqual(dismissed, .withheld(.dismissed))
        XCTAssertEqual(absent, .absent)
        XCTAssertNotEqual(dismissed, absent, "a cancel collapsed into an absence — the original defect")
    }

    func testSuccessIsReleased() {
        XCTAssertEqual(SecretAccessDecision(status: errSecSuccess), .released)
    }

    /// Failed authentication is withheld, not failed: someone tried and it did not take. Unlike a dismissal,
    /// retrying is reasonable — which is why they are separate reasons rather than one "denied".
    func testAuthenticationFailureIsWithheldAndRetryable() {
        let decision = SecretAccessDecision(status: errSecAuthFailed)

        XCTAssertEqual(decision, .withheld(.authenticationFailed))
        XCTAssertTrue(decision.reflectsAHumanChoice)
    }

    /// The system refusing to ASK is withheld too — but nobody chose anything, so a surface must not report it as
    /// the person having declined.
    func testInteractionNotAllowedIsWithheldButNotAHumanChoice() {
        let decision = SecretAccessDecision(status: errSecInteractionNotAllowed)

        XCTAssertEqual(decision, .withheld(.interactionNotAllowed))
        XCTAssertFalse(decision.reflectsAHumanChoice,
                       "a locked keychain was reported as the person saying no")
    }

    /// An unrecognised status keeps its number rather than being folded into a friendlier case. A wrong remedy is
    /// worse than an unspecific one.
    func testAnUnknownStatusKeepsItsNumber() {
        XCTAssertEqual(SecretAccessDecision(status: errSecDuplicateItem), .failed(status: errSecDuplicateItem))
    }

    /// The instrument can distinguish: not everything is `withheld`. Without this, the assertions above would also
    /// pass for an implementation that called every failure a refusal.
    func testNotEveryNonSuccessIsAHumanChoice() {
        XCTAssertFalse(SecretAccessDecision(status: errSecItemNotFound).reflectsAHumanChoice)
        XCTAssertFalse(SecretAccessDecision(status: errSecSuccess).reflectsAHumanChoice)
        XCTAssertFalse(SecretAccessDecision(status: errSecDuplicateItem).reflectsAHumanChoice)
        XCTAssertTrue(SecretAccessDecision(status: errSecUserCanceled).reflectsAHumanChoice)
    }
#endif

    /// Each decision says what happened in its own words, so two surfaces cannot describe one decision differently.
    func testEveryDecisionCarriesItsOwnSentence() {
        let decisions: [SecretAccessDecision] = [
            .released,
            .withheld(.dismissed),
            .withheld(.authenticationFailed),
            .withheld(.interactionNotAllowed),
            .absent,
            .failed(status: -1)
        ]

        for decision in decisions {
            XCTAssertFalse(decision.summary.isEmpty, "\(decision) had nothing to say for itself")
        }
        XCTAssertEqual(Set(decisions.map(\.summary)).count, decisions.count,
                       "two different decisions produced the same sentence")
    }

    // MARK: - The obligation to announce

    func testAnObserverHearsEveryDecision() {
        let log = SecretAccessLog()
        let heard = Recorder()
        let subscription = log.observe { heard.append($0) }
        defer { subscription.cancel() }

        log.record(.init(decision: .withheld(.dismissed), service: "Reframe", account: "openai"))
        log.record(.init(decision: .released, service: "Reframe", account: "openai"))

        XCTAssertEqual(heard.decisions, [.withheld(.dismissed), .released])
    }

    /// A DECISION MADE BEFORE ANYONE WAS LISTENING IS STILL DELIVERED.
    ///
    /// The dialog can appear during launch, before the surface that should speak about it exists. A log that only
    /// forwarded live events would drop exactly the decision most worth hearing.
    func testALateSubscriberIsToldWhatAlreadyHappened() {
        let log = SecretAccessLog()
        log.record(.init(decision: .withheld(.dismissed), service: "Reframe", account: "openai"))

        let heard = Recorder()
        let subscription = log.observe { heard.append($0) }
        defer { subscription.cancel() }

        XCTAssertEqual(heard.decisions, [.withheld(.dismissed)],
                       "a decision made before the surface existed was lost")
    }

    func testCancellingASubscriptionStopsDelivery() {
        let log = SecretAccessLog()
        let heard = Recorder()
        let subscription = log.observe { heard.append($0) }

        subscription.cancel()
        log.record(.init(decision: .released, service: "Reframe", account: "openai"))

        XCTAssertEqual(heard.decisions, [])
    }

    /// The backlog is bounded — this is a live signal, not an audit trail, and an unbounded array in an app that
    /// runs for days is a leak.
    func testTheBacklogDoesNotGrowWithoutBound() {
        let log = SecretAccessLog()
        for _ in 0..<200 {
            log.record(.init(decision: .released, service: "Reframe", account: "openai"))
        }

        XCTAssertLessThanOrEqual(log.recentEvents.count, 32)
    }

    /// The event carries what happened, never the secret itself.
    func testTheEventDoesNotCarryTheSecret() {
        let event = SecretAccessLog.Event(decision: .released, service: "Reframe", account: "openai")

        XCTAssertEqual(event.decision, .released)
        XCTAssertEqual(event.account, "openai")
        // Structural, not a string check: `Event` has no member that could hold one.
        XCTAssertEqual(
            Mirror(reflecting: event).children.compactMap(\.label).sorted(),
            ["account", "at", "decision", "service"]
        )
    }

    private final class Recorder: @unchecked Sendable {
        private let lock = NSLock()
        private var events: [SecretAccessLog.Event] = []

        func append(_ event: SecretAccessLog.Event) {
            lock.lock(); events.append(event); lock.unlock()
        }

        var decisions: [SecretAccessDecision] {
            lock.lock(); defer { lock.unlock() }
            return events.map(\.decision)
        }
    }
}
