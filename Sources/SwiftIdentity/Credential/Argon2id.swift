/// Argon2id, RFC 9106 (version 0x13), in Swift.
///
/// Here because the amendment's policy is to write primitives rather than depend on them, and
/// the only Argon2 implementations a Swift package can reach are C (§7, §13.4). It's offered as
/// an opt-in passphrase scheme, ``Argon2idC1``, and never as the default: NIST names PBKDF2, and
/// a pure-Swift Argon2id is the riskiest code in the package (§12). Only
/// ``PassphrasePolicy/owasp`` selects it, and only because the gate in §9 passed: the RFC's
/// vector, differential runs against OpenSSL, phc-winner-argon2 and argon2-swift, timing within
/// 2× of the reference in release builds, and memory bounded as configured.
///
/// ## Bounded work
///
/// Argon2's memory and time are requests the caller makes of the machine, so both are capped:
/// ``maximumMemoryKiB`` (1 GiB), ``maximumIterations`` and ``maximumParallelism``. A value
/// above a cap, or below RFC 9106's minimums, is refused by name when the parameters are made,
/// before any memory is allocated.
///
/// ## Lanes
///
/// Lanes are computed one after another on the calling thread. The RFC permits that: within a
/// slice no lane reads another lane's current segment, so the order within a slice can't change
/// the result. Concurrency would make one derivation faster, not a verifier under load.
///
/// ```swift
/// var generator = SystemRandomNumberGenerator()
/// let salt = (0..<16).map { _ in UInt8.random(in: .min ... .max, using: &generator) }
/// let argon2 = try Argon2id(memoryKiB: 19_456, iterations: 2, parallelism: 1)
/// let tag = try argon2.hash(password: Array("correct horse".utf8), salt: salt)
/// ```
public struct Argon2id: Sendable, Equatable {

    /// Why a derivation was refused.
    public enum Failure: Error, Equatable {
        /// Less memory than RFC 9106's minimum of 8 KiB per lane.
        case memoryBelowMinimum(requested: Int, minimum: Int)
        /// More memory than ``Argon2id/maximumMemoryKiB``.
        case memoryAboveMaximum(requested: Int, maximum: Int)
        /// Fewer than one pass.
        case iterationsBelowMinimum(requested: Int, minimum: Int)
        /// More passes than ``Argon2id/maximumIterations``.
        case iterationsAboveMaximum(requested: Int, maximum: Int)
        /// Fewer than one lane.
        case parallelismBelowMinimum(requested: Int, minimum: Int)
        /// More lanes than ``Argon2id/maximumParallelism``.
        case parallelismAboveMaximum(requested: Int, maximum: Int)
        /// A salt shorter than RFC 9106's minimum of 8 bytes.
        case saltTooShort(length: Int, minimum: Int)
        /// A tag length below RFC 9106's minimum of 4 bytes, or above ``Argon2id/maximumTagLength``.
        case tagLengthOutOfRange(requested: Int, minimum: Int, maximum: Int)
        /// An input whose length can't be encoded in the 32 bits RFC 9106 gives it.
        case inputTooLong(length: Int, maximum: Int)
    }

    /// The Argon2 version this implements, 0x13: the one RFC 9106 specifies.
    public static let version: UInt32 = 0x13
    /// The most memory a derivation may use, in KiB: 1 GiB.
    public static let maximumMemoryKiB = 1_048_576
    /// The most passes a derivation may make.
    public static let maximumIterations = 32
    /// The most lanes a derivation may use.
    public static let maximumParallelism = 16
    /// The longest tag, in bytes. RFC 9106 allows up to 2^32 - 1; nothing here needs more than 64.
    public static let maximumTagLength = 1_024
    /// RFC 9106's shortest tag, in bytes.
    public static let minimumTagLength = 4
    /// RFC 9106's shortest salt, in bytes.
    public static let minimumSaltLength = 8

    /// 64-bit words in a 1 KiB block.
    static let wordsPerBlock = 128
    /// Slices per pass; lanes synchronize at each slice boundary.
    static let syncPoints = 4
    /// The type field for Argon2id in H0 and the address blocks.
    static let typeID: UInt64 = 2

    /// The memory requested, in KiB.
    public let memoryKiB: Int
    /// The number of passes over memory, `t`.
    public let iterations: Int
    /// The number of lanes, `p`.
    public let parallelism: Int

    /// The 1 KiB blocks actually used: `memoryKiB` rounded down to a multiple of `4p` (§3.2).
    public var blockCount: Int { 4 * parallelism * (memoryKiB / (4 * parallelism)) }
    /// Blocks per lane.
    var laneLength: Int { blockCount / parallelism }
    /// Blocks per segment: a lane's share of one slice.
    var segmentLength: Int { laneLength / Self.syncPoints }

    /// Parameters for Argon2id, checked against RFC 9106's minimums and this package's caps.
    ///
    /// - Parameters:
    ///   - memoryKiB: Memory in KiB: at least `8 * parallelism`, at most ``maximumMemoryKiB``.
    ///   - iterations: Passes over memory: 1 to ``maximumIterations``.
    ///   - parallelism: Lanes: 1 to ``maximumParallelism``.
    /// - Throws: ``Failure``, naming the first parameter out of bounds.
    public init(memoryKiB: Int, iterations: Int, parallelism: Int) throws {
        if let refusal = Self.refusal(memoryKiB: memoryKiB, iterations: iterations, parallelism: parallelism) {
            throw refusal
        }
        self.memoryKiB = memoryKiB
        self.iterations = iterations
        self.parallelism = parallelism
    }

    /// Parameters for Argon2id, or nil if ``init(memoryKiB:iterations:parallelism:)`` would
    /// refuse them. For a caller asking only whether they're acceptable, such as a stored value
    /// being decoded, where the reason isn't wanted.
    static func validated(memoryKiB: Int, iterations: Int, parallelism: Int) -> Argon2id? {
        guard refusal(memoryKiB: memoryKiB, iterations: iterations, parallelism: parallelism) == nil else {
            return nil
        }
        return Argon2id(checkedMemoryKiB: memoryKiB, iterations: iterations, parallelism: parallelism)
    }

    /// Parameters already checked by ``refusal(memoryKiB:iterations:parallelism:)``.
    private init(checkedMemoryKiB: Int, iterations: Int, parallelism: Int) {
        self.memoryKiB = checkedMemoryKiB
        self.iterations = iterations
        self.parallelism = parallelism
    }

    /// The first parameter out of bounds, lanes first because the memory minimum depends on them.
    static func refusal(memoryKiB: Int, iterations: Int, parallelism: Int) -> Failure? {
        if parallelism < 1 { return .parallelismBelowMinimum(requested: parallelism, minimum: 1) }
        if parallelism > maximumParallelism {
            return .parallelismAboveMaximum(requested: parallelism, maximum: maximumParallelism)
        }
        if iterations < 1 { return .iterationsBelowMinimum(requested: iterations, minimum: 1) }
        if iterations > maximumIterations {
            return .iterationsAboveMaximum(requested: iterations, maximum: maximumIterations)
        }
        if memoryKiB < 8 * parallelism { return .memoryBelowMinimum(requested: memoryKiB, minimum: 8 * parallelism) }
        if memoryKiB > maximumMemoryKiB { return .memoryAboveMaximum(requested: memoryKiB, maximum: maximumMemoryKiB) }
        return nil
    }

    /// The Argon2id tag of a password.
    ///
    /// - Parameters:
    ///   - password: The password, `P`.
    ///   - salt: The salt, `S`: at least 8 bytes.
    ///   - secret: An optional key, `K`, kept apart from the stored digests.
    ///   - associatedData: Optional associated data, `X`.
    ///   - tagLength: The tag's length in bytes, `T`: 4 to ``maximumTagLength``.
    /// - Returns: `tagLength` bytes.
    /// - Throws: ``Failure``.
    public func hash(
        password: [UInt8], salt: [UInt8], secret: [UInt8] = [], associatedData: [UInt8] = [],
        tagLength: Int = 32
    ) throws -> [UInt8] {
        try hash(
            password: password, salt: salt, secret: secret, associatedData: associatedData,
            tagLength: tagLength, afterEachPass: { _, _ in }
        )
    }

    /// The tag, reporting the whole memory after each pass.
    ///
    /// The observer is how the tests reach the words RFC 9106 prints after each pass, which is
    /// what localizes a fault to a pass rather than only reporting a wrong tag.
    func hash(
        password: [UInt8], salt: [UInt8], secret: [UInt8] = [], associatedData: [UInt8] = [],
        tagLength: Int = 32, afterEachPass: (Int, [UInt64]) -> Void
    ) throws -> [UInt8] {
        let h0 = try preHash(
            password: password, salt: salt, secret: secret, associatedData: associatedData,
            tagLength: tagLength
        )
        var matrix = Argon2idMatrix(self)
        try matrix.initialize(h0)
        for pass in 0..<iterations {
            for slice in 0..<Self.syncPoints {
                for lane in 0..<parallelism {
                    matrix.fillSegment(pass: pass, slice: slice, lane: lane)
                }
            }
            afterEachPass(pass, matrix.memory)
        }
        return try Self.variableLengthHash(Self.bytes(matrix.finalBlock()), length: tagLength)
    }

    /// H0, RFC 9106 §3.2 step 1: every parameter and input, length-prefixed, hashed to 64 bytes.
    ///
    /// The inputs are checked here, because H0 is where their lengths are encoded.
    func preHash(
        password: [UInt8], salt: [UInt8], secret: [UInt8], associatedData: [UInt8], tagLength: Int
    ) throws -> [UInt8] {
        guard salt.count >= Self.minimumSaltLength else {
            throw Failure.saltTooShort(length: salt.count, minimum: Self.minimumSaltLength)
        }
        guard (Self.minimumTagLength...Self.maximumTagLength).contains(tagLength) else {
            throw Failure.tagLengthOutOfRange(
                requested: tagLength, minimum: Self.minimumTagLength, maximum: Self.maximumTagLength
            )
        }
        var input: [UInt8] = []
        for field in [parallelism, tagLength, memoryKiB, iterations, Int(Self.version), Int(Self.typeID)] {
            input += Self.le32(field)
        }
        for field in [password, salt, secret, associatedData] {
            guard field.count <= Int(UInt32.max) else {
                throw Failure.inputTooLong(length: field.count, maximum: Int(UInt32.max))
            }
            input += Self.le32(field.count) + field
        }
        return try BLAKE2b.hash(input, outputLength: BLAKE2b.maximumOutputBytes)
    }

    /// H', RFC 9106 §3.3: BLAKE2b stretched to any length.
    ///
    /// Up to 64 bytes it's one BLAKE2b of the length-prefixed input. Beyond that it chains
    /// 64-byte BLAKE2b outputs, keeping the first half of each, and ends with one of whatever
    /// length remains.
    static func variableLengthHash(_ message: [UInt8], length: Int) throws -> [UInt8] {
        let prefixed = le32(length) + message
        let full = BLAKE2b.maximumOutputBytes
        guard length > full else { return try BLAKE2b.hash(prefixed, outputLength: length) }

        let half = full / 2
        let chained = (length + half - 1) / half - 2
        var link = try BLAKE2b.hash(prefixed, outputLength: full)
        var output = Array(link.prefix(half))
        for _ in 1..<chained {
            link = try BLAKE2b.hash(link, outputLength: full)
            output += link.prefix(half)
        }
        output += try BLAKE2b.hash(link, outputLength: length - half * chained)
        return output
    }

    /// A value as four little-endian bytes. Every caller has already bounded it to 32 bits.
    static func le32(_ value: Int) -> [UInt8] {
        let word = UInt32(truncatingIfNeeded: value)
        return [0, 8, 16, 24].map { UInt8(truncatingIfNeeded: word >> UInt32($0)) }
    }

    /// Little-endian bytes as words; `bytes.count` is a multiple of 8.
    static func words(_ bytes: [UInt8]) -> [UInt64] {
        stride(from: 0, to: bytes.count - 7, by: 8).map { start in
            (0..<8).reduce(UInt64(0)) { word, offset in
                word | UInt64(bytes[start + offset]) << UInt64(8 * offset)
            }
        }
    }

    /// Words as little-endian bytes.
    static func bytes(_ words: [UInt64]) -> [UInt8] {
        BLAKE2b.littleEndianBytes(words)
    }
}

/// Argon2id's memory, and the work of filling it.
///
/// One flat array of 64-bit words, lane after lane, indexed by arithmetic. Two 128-word scratch
/// arrays hold the compression's intermediate values, so filling a block allocates nothing.
struct Argon2idMatrix {

    let parameters: Argon2id
    let lanes: Int
    let laneLength: Int
    let segmentLength: Int
    /// Every block, `blockCount * 128` words.
    var memory: [UInt64]
    /// R in RFC 9106's G: the XOR of the two input blocks.
    private var r = [UInt64](repeating: 0, count: Argon2id.wordsPerBlock)
    /// Q in G: R after the row and column permutations.
    private var q = [UInt64](repeating: 0, count: Argon2id.wordsPerBlock)
    /// The input block for data-independent addressing (§3.4.1.2).
    private var addressInput = [UInt64](repeating: 0, count: Argon2id.wordsPerBlock)
    /// The current block of 128 pseudo-random addresses.
    private var addresses = [UInt64](repeating: 0, count: Argon2id.wordsPerBlock)

    init(_ parameters: Argon2id) {
        self.parameters = parameters
        self.lanes = parameters.parallelism
        self.laneLength = parameters.laneLength
        self.segmentLength = parameters.segmentLength
        self.memory = [UInt64](repeating: 0, count: parameters.blockCount * Argon2id.wordsPerBlock)
    }

    /// RFC 9106 §3.2 steps 3 and 4: the first two blocks of each lane, from H0.
    mutating func initialize(_ h0: [UInt8]) throws {
        let blockBytes = Argon2id.wordsPerBlock * 8
        for lane in 0..<lanes {
            for column in 0..<2 {
                let seed = h0 + Argon2id.le32(column) + Argon2id.le32(lane)
                let words = Argon2id.words(try Argon2id.variableLengthHash(seed, length: blockBytes))
                let start = (lane * laneLength + column) * Argon2id.wordsPerBlock
                for (offset, word) in words.enumerated() {
                    memory[start + offset] = word
                }
            }
        }
    }

    /// RFC 9106 §3.2 step 7: the XOR of every lane's last block.
    func finalBlock() -> [UInt64] {
        var final = [UInt64](repeating: 0, count: Argon2id.wordsPerBlock)
        for lane in 0..<lanes {
            let start = (lane * laneLength + laneLength - 1) * Argon2id.wordsPerBlock
            for offset in 0..<Argon2id.wordsPerBlock {
                final[offset] ^= memory[start + offset]
            }
        }
        return final
    }

    /// Fills one segment: `segmentLength` blocks of one lane within one slice.
    ///
    /// Argon2id addresses data-independently for the first half of the first pass (slices 0 and
    /// 1 of pass 0), drawing reference indices from generated address blocks so the access
    /// pattern reveals nothing about the password; everywhere else it takes them from the
    /// previous block's first word.
    mutating func fillSegment(pass: Int, slice: Int, lane: Int) {
        let independent = pass == 0 && slice < 2
        // The first two blocks of each lane came from H0.
        let first = pass == 0 && slice == 0 ? 2 : 0
        if independent {
            resetAddressInput(pass: pass, slice: slice, lane: lane)
            if first != 0 { nextAddresses() }
        }

        for index in first..<segmentLength {
            let current = lane * laneLength + slice * segmentLength + index
            let previous = current % laneLength == 0 ? current + laneLength - 1 : current - 1
            if independent, index % Argon2id.wordsPerBlock == 0 { nextAddresses() }
            let pseudoRandom = independent
                ? addresses[index % Argon2id.wordsPerBlock]
                : memory[previous * Argon2id.wordsPerBlock]

            // In the first slice of the first pass no other lane has anything to reference yet.
            let referenceLane = pass == 0 && slice == 0 ? lane : Int((pseudoRandom >> 32) % UInt64(lanes))
            let referenceIndex = referenceIndex(
                pass: pass, slice: slice, index: index, sameLane: referenceLane == lane,
                j1: pseudoRandom & 0xFFFF_FFFF
            )
            compressBlocks(
                into: current, previous: previous, reference: referenceLane * laneLength + referenceIndex,
                xorExisting: pass > 0
            )
        }
    }

    /// The reference block's index within its lane, RFC 9106 §3.4.1.1 and §3.4.2.
    ///
    /// The reference set is every block already finished in the referenced lane: in the first
    /// pass, the slices before this one; after it, the whole lane but the current segment. A
    /// block in the same lane may also reference this segment's earlier blocks, though never the
    /// one just before it. J1 is mapped onto that set non-uniformly, favouring recent blocks.
    func referenceIndex(pass: Int, slice: Int, index: Int, sameLane: Bool, j1: UInt64) -> Int {
        let finished = pass == 0 ? slice * segmentLength : laneLength - segmentLength
        let areaSize = UInt64(sameLane ? finished + index - 1 : finished - (index == 0 ? 1 : 0))
        let x = (j1 &* j1) >> 32
        let y = (areaSize &* x) >> 32
        let relative = areaSize - 1 - y
        let start = pass == 0 || slice == Argon2id.syncPoints - 1 ? 0 : (slice + 1) * segmentLength
        return Int((UInt64(start) + relative) % UInt64(laneLength))
    }

    /// Sets up the address input block Z for one segment (§3.4.1.2).
    private mutating func resetAddressInput(pass: Int, slice: Int, lane: Int) {
        for offset in 0..<Argon2id.wordsPerBlock { addressInput[offset] = 0 }
        addressInput[0] = UInt64(pass)
        addressInput[1] = UInt64(lane)
        addressInput[2] = UInt64(slice)
        addressInput[3] = UInt64(parameters.blockCount)
        addressInput[4] = UInt64(parameters.iterations)
        addressInput[5] = Argon2id.typeID
    }

    /// The next 128 addresses: G(0, G(0, Z)) after incrementing Z's counter.
    private mutating func nextAddresses() {
        addressInput[6] &+= 1
        // G(0, Z): R is Z itself, since XOR with zero changes nothing.
        for offset in 0..<Argon2id.wordsPerBlock { r[offset] = addressInput[offset] }
        permuteR()
        for offset in 0..<Argon2id.wordsPerBlock { r[offset] = q[offset] ^ r[offset] }
        // And again, over that result.
        permuteR()
        for offset in 0..<Argon2id.wordsPerBlock { addresses[offset] = q[offset] ^ r[offset] }
    }

    /// The compression G of two memory blocks into a third (§3.5). After the first pass the
    /// result is XORed into the block it replaces, as version 0x13 requires.
    private mutating func compressBlocks(into current: Int, previous: Int, reference: Int, xorExisting: Bool) {
        let width = Argon2id.wordsPerBlock
        let (out, left, right) = (current * width, previous * width, reference * width)
        for offset in 0..<width {
            r[offset] = memory[left + offset] ^ memory[right + offset]
        }
        permuteR()
        for offset in 0..<width {
            let z = q[offset] ^ r[offset]
            memory[out + offset] = xorExisting ? memory[out + offset] ^ z : z
        }
    }

    /// Q = P applied to R's eight rows, then to its eight columns.
    ///
    /// R is an 8 x 8 matrix of 16-byte registers. A row is 16 consecutive words; a column is a
    /// pair of words from each row, 16 words apart.
    private mutating func permuteR() {
        for offset in 0..<Argon2id.wordsPerBlock { q[offset] = r[offset] }
        for row in 0..<8 { permute(start: 16 * row, stride: 2) }
        for column in 0..<8 { permute(start: 2 * column, stride: 16) }
    }

    /// The permutation P (§3.6) over the eight registers at `start`, `stride` words apart.
    private mutating func permute(start: Int, stride: Int) {
        var v0 = q[start], v1 = q[start + 1]
        var v2 = q[start + stride], v3 = q[start + stride + 1]
        var v4 = q[start + 2 * stride], v5 = q[start + 2 * stride + 1]
        var v6 = q[start + 3 * stride], v7 = q[start + 3 * stride + 1]
        var v8 = q[start + 4 * stride], v9 = q[start + 4 * stride + 1]
        var v10 = q[start + 5 * stride], v11 = q[start + 5 * stride + 1]
        var v12 = q[start + 6 * stride], v13 = q[start + 6 * stride + 1]
        var v14 = q[start + 7 * stride], v15 = q[start + 7 * stride + 1]

        Self.mix(&v0, &v4, &v8, &v12)
        Self.mix(&v1, &v5, &v9, &v13)
        Self.mix(&v2, &v6, &v10, &v14)
        Self.mix(&v3, &v7, &v11, &v15)
        Self.mix(&v0, &v5, &v10, &v15)
        Self.mix(&v1, &v6, &v11, &v12)
        Self.mix(&v2, &v7, &v8, &v13)
        Self.mix(&v3, &v4, &v9, &v14)

        q[start] = v0; q[start + 1] = v1
        q[start + stride] = v2; q[start + stride + 1] = v3
        q[start + 2 * stride] = v4; q[start + 2 * stride + 1] = v5
        q[start + 3 * stride] = v6; q[start + 3 * stride + 1] = v7
        q[start + 4 * stride] = v8; q[start + 4 * stride + 1] = v9
        q[start + 5 * stride] = v10; q[start + 5 * stride + 1] = v11
        q[start + 6 * stride] = v12; q[start + 6 * stride + 1] = v13
        q[start + 7 * stride] = v14; q[start + 7 * stride + 1] = v15
    }

    /// GB (§3.6): BLAKE2b's G with BlaMka's multiplications in place of the message words.
    private static func mix(_ a: inout UInt64, _ b: inout UInt64, _ c: inout UInt64, _ d: inout UInt64) {
        a = blaMka(a, b)
        d = (d ^ a).rotatedRight(by: 32)
        c = blaMka(c, d)
        b = (b ^ c).rotatedRight(by: 24)
        a = blaMka(a, b)
        d = (d ^ a).rotatedRight(by: 16)
        c = blaMka(c, d)
        b = (b ^ c).rotatedRight(by: 63)
    }

    /// `x + y + 2 * lo(x) * lo(y)`, all mod 2^64: the multiplication that makes Argon2 cost the
    /// same on hardware that's fast at addition.
    private static func blaMka(_ x: UInt64, _ y: UInt64) -> UInt64 {
        x &+ y &+ 2 &* (x & 0xFFFF_FFFF) &* (y & 0xFFFF_FFFF)
    }
}

