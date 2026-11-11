import Foundation

/// What to create: a subject, and how it is described.
public struct SubjectSpec: Sendable, Equatable {
    /// The subject's id: 1 to 64 letters, digits, `.`, `_` or `-`. Chosen once and stable forever.
    public let id: String
    /// A person or a service.
    public let kind: Subject.Kind
    /// The consumer's own claims, written as `name=value`. Names and values use the same alphabet as an id.
    public let attributes: [String: String]
    /// When the first key expires, if it does.
    public let expires: Date?

    /// Creates a specification.
    public init(id: String, kind: Subject.Kind, attributes: [String: String] = [:], expires: Date? = nil) {
        self.id = id
        self.kind = kind
        self.attributes = attributes
        self.expires = expires
    }
}

/// One key of a subject, as a listing shows it: never the key, never the whole digest.
public struct KeyListing: Sendable, Equatable {
    /// The first eight hexadecimal characters of the key's digest, enough to name it to `revokeKey`.
    public let digestPrefix: String
    /// When the key expires, if it does.
    public let expires: Date?
}

/// One subject, as a listing shows it.
public struct SubjectListing: Sendable, Equatable {
    /// The subject's id.
    public let id: String
    /// A person or a service.
    public let kind: Subject.Kind
    /// Whether it may authenticate.
    public let status: Subject.Status
    /// The consumer's own claims.
    public let attributes: [String: String]
    /// Its keys.
    public let keys: [KeyListing]
}

/// Why an administrative change was refused. Nothing was written when one of these is thrown.
public enum AdministrationFailure: Error, Equatable, Sendable {
    /// A name was empty, longer than 64, or held a character outside letters, digits, `.`, `_` and `-`.
    case invalidName(String)
    /// The subject, or the identity files, already exist.
    case alreadyExists(String)
    /// There is no such subject.
    case notFound(String)
    /// A digest prefix shorter than eight characters, which could match more than one key.
    case prefixTooShort
    /// No key has that digest prefix.
    case keyNotFound
    /// More than one key has that digest prefix.
    case ambiguousPrefix
    /// A file or the directory was refused by ``SecureIdentityFiles``.
    case files(SecureIdentityFiles.Failure)
    /// The files, as they are or as the change would leave them, would not load through ``FileCredentialStore``.
    case wouldNotLoad(FileCredentialStore.Failure)
}

/// Adds, rotates, revokes and lists the subjects and keys in a directory of the two files ``FileCredentialStore`` reads.
///
/// **Every change is checked before it is made.** The new text of both files is written to a staging directory inside this one and
/// loaded through ``FileCredentialStore``; only if that loads are the live files replaced, each atomically. A writer and the
/// reader therefore cannot disagree about the format, and a change that would leave a store that refuses to start is refused
/// instead. Files that already do not load are never written over.
///
/// **Keys are returned once.** ``create(first:using:)``, ``add(_:using:)`` and ``addKey(for:expires:using:)`` hand back a ``MintedKey``; only its
/// digest is stored, and a listing shows the first eight characters of one.
public struct IdentityDirectory: Sendable {
    private let path: String
    private let minter: BearerKeyMinter

    private static let subjectsHeader = "# subject kind status attributes (written by IdentityDirectory)\n"
    private static let verifiersHeader = "# subject kind sha256-of-key expiry-or-dash (digests only; the keys are not stored)\n"

    /// - Parameters:
    ///   - path: The absolute path of the directory holding `subjects` and `verifiers`.
    ///   - minter: Makes the keys; a prefix can be set on it.
    public init(path: String, minter: BearerKeyMinter = BearerKeyMinter()) {
        self.path = path
        self.minter = minter
    }

    // MARK: Changes

    /// Creates the directory (owner-only; its parent must exist) with its first subject and that subject's first key.
    /// - Parameters:
    ///   - first: The first subject and how its first key is described.
    ///   - generator: The source of the key's randomness: `SystemRandomNumberGenerator()` for a real key, a seeded one in a test.
    /// - Throws: ``AdministrationFailure``, including `alreadyExists` when identity files are already there.
    public func create<Generator: RandomNumberGenerator>(
        first: SubjectSpec, using generator: inout Generator
    ) throws(AdministrationFailure) -> MintedKey {
        try Self.validate(first)
        let subjects = path + "/" + FileCredentialStore.subjectsFile
        let verifiers = path + "/" + FileCredentialStore.verifiersFile
        if SecureIdentityFiles.stamp(of: path) == nil {
            do { try SecureIdentityFiles.makeDirectory(path) } catch { throw .files(error) }
        } else {
            do { try SecureIdentityFiles.requireDirectory(path) } catch { throw .files(error) }
            guard SecureIdentityFiles.stamp(of: subjects) == nil, SecureIdentityFiles.stamp(of: verifiers) == nil else {
                throw .alreadyExists(path)
            }
        }
        let minted = minter.mint(using: &generator)
        let state = State(subjects: Self.subjectsHeader + Self.subjectLine(first), verifiers: Self.verifiersHeader + Self.keyLine(first.id, minted, first.expires))
        try commit(state, replacing: [.subjects, .verifiers])
        return minted
    }

    /// Adds a subject with its first key.
    /// - Parameters:
    ///   - spec: The subject and how its first key is described.
    ///   - generator: The source of the key's randomness.
    /// - Throws: ``AdministrationFailure/alreadyExists(_:)`` if the id is taken, ``AdministrationFailure/invalidName(_:)``, or a refusal of the files.
    public func add<Generator: RandomNumberGenerator>(
        _ spec: SubjectSpec, using generator: inout Generator
    ) throws(AdministrationFailure) -> MintedKey {
        try Self.validate(spec)
        var state = try load()
        guard !state.subjectLines.contains(where: { $0.id == spec.id }) else { throw .alreadyExists(spec.id) }
        let minted = minter.mint(using: &generator)
        state.subjects += Self.subjectLine(spec)
        state.verifiers += Self.keyLine(spec.id, minted, spec.expires)
        try commit(state, replacing: [.subjects, .verifiers])
        return minted
    }

    /// Adds a further key to a subject, which verifies beside its others: rotation by overlap.
    /// - Parameters:
    ///   - subject: The id of the subject the key is for.
    ///   - expires: When the new key expires, if it does.
    ///   - generator: The source of the key's randomness.
    /// - Throws: ``AdministrationFailure/notFound(_:)`` if there is no such subject, or a refusal of the files.
    public func addKey<Generator: RandomNumberGenerator>(
        for subject: String, expires: Date?, using generator: inout Generator
    ) throws(AdministrationFailure) -> MintedKey {
        var state = try load()
        guard state.subjectLines.contains(where: { $0.id == subject }) else { throw .notFound(subject) }
        let minted = minter.mint(using: &generator)
        state.verifiers += Self.keyLine(subject, minted, expires)
        try commit(state, replacing: [.verifiers])
        return minted
    }

    /// Revokes a subject: its status becomes `revoked`, so every key of it refuses. Revoking twice is not an error.
    /// - Parameter subject: The id of the subject to revoke.
    /// - Throws: ``AdministrationFailure/notFound(_:)`` or a refusal of the files.
    public func revoke(subject: String) throws(AdministrationFailure) {
        try setStatus(.revoked, of: subject)
    }

    /// Sets a subject's status, including `honeypot`, which refuses the subject's keys while telling the service who presented one.
    /// - Parameters:
    ///   - status: The new status.
    ///   - subject: The id of the subject.
    /// - Throws: ``AdministrationFailure/notFound(_:)`` or a refusal of the files.
    public func setStatus(_ status: Subject.Status, of subject: String) throws(AdministrationFailure) {
        var state = try load()
        guard state.subjectLines.contains(where: { $0.id == subject }) else { throw .notFound(subject) }
        var lines: [String] = []
        for raw in state.subjects.split(omittingEmptySubsequences: false, whereSeparator: \.isNewline) {
            var fields = raw.split(whereSeparator: \.isWhitespace).map(String.init)
            if fields.count >= 3, fields[0] == subject, !fields[0].hasPrefix("#") {
                fields[2] = status.rawValue
                lines.append(fields.joined(separator: " "))
            } else {
                lines.append(String(raw))
            }
        }
        state.subjects = Self.terminated(lines.joined(separator: "\n"))
        try commit(state, replacing: [.subjects])
    }

    /// Removes one key, named by the first eight or more characters of its digest.
    /// - Parameter digestPrefix: The first eight or more hexadecimal characters of the key's digest, as a listing shows them.
    /// - Throws: ``AdministrationFailure/prefixTooShort``, ``AdministrationFailure/keyNotFound``, ``AdministrationFailure/ambiguousPrefix``, or a refusal of the files.
    public func revokeKey(digestPrefix: String) throws(AdministrationFailure) {
        guard digestPrefix.count >= 8 else { throw .prefixTooShort }
        var state = try load()
        let wanted = digestPrefix.lowercased()
        let matches = state.keyLines.filter { $0.digest.hasPrefix(wanted) }
        guard !matches.isEmpty else { throw .keyNotFound }
        guard matches.count == 1, let target = matches.first else { throw .ambiguousPrefix }
        var lines: [String] = []
        for raw in state.verifiers.split(omittingEmptySubsequences: false, whereSeparator: \.isNewline) {
            let fields = raw.split(whereSeparator: \.isWhitespace).map(String.init)
            if fields.count >= 3, !fields[0].hasPrefix("#"), fields[2] == target.digest { continue }
            lines.append(String(raw))
        }
        state.verifiers = Self.terminated(lines.joined(separator: "\n"))
        try commit(state, replacing: [.verifiers])
    }

    // MARK: Listing

    /// The subjects in id order, with each one's keys by digest prefix and expiry. Never a key.
    /// - Throws: ``AdministrationFailure``.
    public func list() throws(AdministrationFailure) -> [SubjectListing] {
        let state = try load()
        let formatter = ISO8601DateFormatter()
        return state.subjectLines.sorted { $0.id < $1.id }.map { subject in
            SubjectListing(
                id: subject.id, kind: subject.kind, status: subject.status, attributes: subject.attributes,
                keys: state.keyLines.filter { $0.subject == subject.id }.map {
                    KeyListing(digestPrefix: String($0.digest.prefix(8)), expires: $0.expires.flatMap { formatter.date(from: $0) })
                })
        }
    }

    // MARK: State

    private enum Target {
        case subjects
        case verifiers
    }

    private struct SubjectLine {
        let id: String
        let kind: Subject.Kind
        let status: Subject.Status
        let attributes: [String: String]
    }

    private struct KeyLine {
        let subject: String
        let digest: String
        let expires: String?
    }

    private struct State {
        var subjects: String
        var verifiers: String

        var subjectLines: [SubjectLine] {
            subjects.split(whereSeparator: \.isNewline).compactMap { raw in
                let fields = raw.split(whereSeparator: \.isWhitespace).map(String.init)
                guard fields.count >= 3, !fields[0].hasPrefix("#"), let kind = Subject.Kind(rawValue: fields[1]),
                      let status = Subject.Status(rawValue: fields[2]) else { return nil }
                var attributes: [String: String] = [:]
                if fields.count > 3 {
                    for pair in fields[3].split(separator: ",") {
                        let parts = pair.split(separator: "=", maxSplits: 1).map(String.init)
                        if parts.count == 2 { attributes[parts[0]] = parts[1] }
                    }
                }
                return SubjectLine(id: fields[0], kind: kind, status: status, attributes: attributes)
            }
        }

        var keyLines: [KeyLine] {
            verifiers.split(whereSeparator: \.isNewline).compactMap { raw in
                let fields = raw.split(whereSeparator: \.isWhitespace).map(String.init)
                guard fields.count >= 3, !fields[0].hasPrefix("#") else { return nil }
                return KeyLine(subject: fields[0], digest: fields[2], expires: fields.count > 3 && fields[3] != "-" ? fields[3] : nil)
            }
        }
    }

    /// Reads both files, after the directory and each file pass ``SecureIdentityFiles``, and checks they load as they are.
    private func load() throws(AdministrationFailure) -> State {
        let subjectsPath = path + "/" + FileCredentialStore.subjectsFile
        let verifiersPath = path + "/" + FileCredentialStore.verifiersFile
        do {
            try SecureIdentityFiles.requireDirectory(path)
            try SecureIdentityFiles.requireFile(subjectsPath)
            try SecureIdentityFiles.requireFile(verifiersPath)
        } catch {
            throw .files(error)
        }
        do {
            _ = try FileCredentialStore(directory: path)
        } catch let failure as FileCredentialStore.Failure {
            throw .wouldNotLoad(failure)
        } catch {
            throw .files(.unreadable(path))
        }
        do {
            return State(
                subjects: Self.terminated(try String(contentsOfFile: subjectsPath, encoding: .utf8)),
                verifiers: Self.terminated(try String(contentsOfFile: verifiersPath, encoding: .utf8)))
        } catch {
            throw .files(.unreadable(path))
        }
    }

    /// Loads the new state through the reader in a staging directory, and only then replaces the live files.
    private func commit(_ state: State, replacing targets: [Target]) throws(AdministrationFailure) {
        let staging = path + "/.staging-" + String(getpid()) + "-" + String(DispatchTime.now().uptimeNanoseconds, radix: 16)
        do {
            try SecureIdentityFiles.makeDirectory(staging)
            try SecureIdentityFiles.replace(staging + "/" + FileCredentialStore.subjectsFile, with: state.subjects)
            try SecureIdentityFiles.replace(staging + "/" + FileCredentialStore.verifiersFile, with: state.verifiers)
        } catch {
            removeStaging(staging)
            throw .files(error)
        }
        defer { removeStaging(staging) }
        do {
            _ = try FileCredentialStore(directory: staging)
        } catch let failure as FileCredentialStore.Failure {
            throw .wouldNotLoad(failure)
        } catch {
            throw .files(.unreadable(staging))
        }
        do {
            // The roster first, so a verifier never names a subject a reader has not yet been told about.
            if targets.contains(.subjects) {
                try SecureIdentityFiles.replace(path + "/" + FileCredentialStore.subjectsFile, with: state.subjects)
            }
            if targets.contains(.verifiers) {
                try SecureIdentityFiles.replace(path + "/" + FileCredentialStore.verifiersFile, with: state.verifiers)
            }
        } catch {
            throw .files(error)
        }
    }

    /// Removes a staging directory this type made, after proving it is exactly one level inside the identity directory and named
    /// as a staging directory, so a deletion can never reach outside it.
    private func removeStaging(_ staging: String) {
        let root = URL(fileURLWithPath: path).resolvingSymlinksInPath().pathComponents
        let target = URL(fileURLWithPath: staging).resolvingSymlinksInPath().pathComponents
        guard target.count == root.count + 1, target.starts(with: root), target.last?.hasPrefix(".staging-") == true else { return }
        try? FileManager.default.removeItem(atPath: staging)
    }

    // MARK: Lines

    private static func validate(_ spec: SubjectSpec) throws(AdministrationFailure) {
        guard isName(spec.id) else { throw .invalidName(spec.id) }
        for (name, value) in spec.attributes {
            guard isName(name) else { throw .invalidName(name) }
            guard isName(value) else { throw .invalidName(value) }
        }
    }

    private static func isName(_ text: String) -> Bool {
        guard (1...64).contains(text.utf8.count) else { return false }
        return text.utf8.allSatisfy { byte in
            (byte >= 0x30 && byte <= 0x39) || (byte >= 0x41 && byte <= 0x5A) || (byte >= 0x61 && byte <= 0x7A)
                || byte == 0x2E || byte == 0x5F || byte == 0x2D
        }
    }

    private static func subjectLine(_ spec: SubjectSpec) -> String {
        var line = "\(spec.id) \(spec.kind.rawValue) \(Subject.Status.active.rawValue)"
        if !spec.attributes.isEmpty {
            line += " " + spec.attributes.sorted { $0.key < $1.key }.map { "\($0.key)=\($0.value)" }.joined(separator: ",")
        }
        return line + "\n"
    }

    private static func keyLine(_ subject: String, _ minted: MintedKey, _ expires: Date?) -> String {
        "\(subject) \(BearerKey.kind) \(minted.digest) \(expires.map { ISO8601DateFormatter().string(from: $0) } ?? "-")\n"
    }

    private static func terminated(_ text: String) -> String {
        text.isEmpty || text.hasSuffix("\n") ? text : text + "\n"
    }
}
