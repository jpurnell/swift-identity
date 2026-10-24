import Foundation

/// What a passphrase becomes before it's hashed: NIST SP 800-63B-4's normalization.
///
/// ## The process
///
/// NIST SP 800-63B-4 §3.1.1.2 asks verifiers to "apply the normalization process for stabilized
/// strings using the Normalization Form Canonical Composition (NFC)" of UAX #15 §12.1, before
/// hashing. In order:
///
/// 1. **Refuse any code point unassigned in the pinned Unicode version.** UAX #15 §12.1 says the
///    process "must be aborted with an error" on one. That's what makes the result *stable*: no
///    later Unicode release can change how an accepted passphrase normalizes.
/// 2. **Refuse control characters** (C0, DEL and C1), which NIST's "printing characters" already
///    excludes. Refused, never stripped: a passphrase that's silently changed is a passphrase
///    whose owner can't predict what will match.
/// 3. **Apply NFC.** Canonical equivalents compare equal: "é" as one code point or as "e" and a
///    combining accent. Compatibility characters stay distinct, so fullwidth "Ａ" isn't "A" and a
///    no-break space isn't a space. That's NIST's choice of NFC over NFKC.
///
/// There's no case mapping and no trimming. NIST permits trimming as an allowance for mistyping;
/// this package declines it, because a password manager's output means exactly what it says.
///
/// ## Why the pin is 15.0
///
/// A character's assignment is judged by the Unicode version it was assigned in, not by the
/// runtime's tables, so the answer is the same on every host. The pin is the oldest Unicode
/// version among the runtimes this package supports (Swift 5.9's, on macOS 14 and iOS 17).
/// Raising it only admits characters that were refused before, so it never changes a digest;
/// it's still a new ``identifier``, because what's accepted is part of what a scheme means.
public struct PassphraseCanonicalization: Sendable, Hashable {

    /// Why a passphrase can't be canonicalized.
    ///
    /// Each case names a **position**, counted in Unicode scalars from zero, never the
    /// character: a refusal can reach a log, and the position says where to look without saying
    /// what's there.
    public enum Refusal: Error, Sendable, Hashable {
        /// A code point unassigned in the pinned Unicode version, a noncharacter among them.
        case unassignedCodePoint(position: Int)
        /// A C0 or C1 control character, or DEL.
        case controlCharacter(position: Int)
    }

    /// The name stored in a scheme identifier's suffix, such as `pbkdf2-sha256-c1`.
    public let identifier: String
    /// The Unicode version assignment is judged against: major.
    public let unicodeMajor: Int
    /// The Unicode version assignment is judged against: minor.
    public let unicodeMinor: Int

    /// Scheme 1: the stabilized-strings process with NFC, pinned to Unicode 15.0.
    public static let c1 = PassphraseCanonicalization(identifier: "c1", unicodeMajor: 15, unicodeMinor: 0)

    /// Canonicalizes a passphrase, or says where it can't be.
    ///
    /// ```swift
    /// let canonical = PassphraseCanonicalization.c1.canonicalize("cafe\u{301}")
    /// // .success("café"), as one precomposed scalar
    /// ```
    ///
    /// - Parameter secret: The passphrase as presented.
    /// - Returns: The canonical passphrase, or the first ``Refusal``.
    public func canonicalize(_ secret: String) -> Result<String, Refusal> {
        for (position, scalar) in secret.unicodeScalars.enumerated() {
            guard isAssigned(scalar) else { return .failure(.unassignedCodePoint(position: position)) }
            guard scalar.properties.generalCategory != .control else {
                return .failure(.controlCharacter(position: position))
            }
        }
        return .success(Self.nfc(secret))
    }

    /// NFC, from Foundation: Apple-vended, and on Linux swift-corelibs-foundation's.
    ///
    /// Written as UAX #15 defines NFC, canonical decomposition and then canonical composition,
    /// rather than as Foundation's single `precomposedStringWithCanonicalMapping`. On its own,
    /// that call leaves a precomposed Hangul LV syllable and a trailing jamo apart: "가" + "ᆨ"
    /// stays two scalars where NFC requires "각". Unicode's conformance file caught it, in two
    /// of its 19,074 cases, and the decomposed path passes all of them. (Seen on macOS 27,
    /// 2026-10-22.)
    ///
    /// Checked against Unicode's own `NormalizationTest.txt` for the pinned version, and against
    /// an independent implementation in the differential harness. A runtime whose tables are
    /// newer than the pin normalizes every pinned character the same way, by Unicode's
    /// normalization stability policy; a newer character never gets this far.
    static func nfc(_ text: String) -> String {
        text.decomposedStringWithCanonicalMapping.precomposedStringWithCanonicalMapping
    }

    /// Whether `scalar` is assigned in the pinned version.
    ///
    /// Two checks, because neither is enough alone. A noncharacter such as U+FFFE has an age but
    /// is General_Category=Unassigned, which is what UAX #15 §12.1 names. And a character the
    /// runtime knows but the pin doesn't has a category, but an age past the pin.
    private func isAssigned(_ scalar: Unicode.Scalar) -> Bool {
        let properties = scalar.properties
        guard properties.generalCategory != .unassigned, let age = properties.age else { return false }
        return (age.major, age.minor) <= (unicodeMajor, unicodeMinor)
    }
}
