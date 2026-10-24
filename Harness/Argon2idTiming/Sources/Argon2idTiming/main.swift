// The Argon2id timing comparison: this package's implementation against the phc-winner-argon2
// CLI, as CPU time, at the deployment parameters the amendment names (§9).
//
// CPU time rather than wall-clock time, because the machine this runs on is shared and loaded:
// wall-clock time is mostly the scheduler. Ours runs on one thread, so its cost is that thread's
// CPU time. The reference's is the time the CLI itself reports, which is `clock()` around the
// hash alone, the whole process's CPU time across its lane threads; the CLI's total CPU time
// from `getrusage(RUSAGE_CHILDREN)`, which adds process start-up, is printed beside it. The
// minimum over several runs is the comparison, since load only ever adds time.
//
// Before timing, each parameter set's tag from ours must equal the reference's, so the numbers
// compare the same computation.
//
//     argon2id-timing [path to argon2 CLI] [runs]

#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif
import Foundation
import SwiftIdentity

/// One deployment parameter set.
struct Parameters {
    let memoryKiB: Int
    let iterations: Int
    let parallelism: Int

    var label: String { "m=\(memoryKiB) t=\(iterations) p=\(parallelism)" }
}

/// What one run of the reference reported.
struct ReferenceRun {
    let tag: String
    let reportedSeconds: Double
    let processCPUSeconds: Double
}

enum TimingFailure: Error, CustomStringConvertible {
    case referenceFailed(String)
    case tagsDiffer(String, ours: String, reference: String)

    var description: String {
        switch self {
        case .referenceFailed(let detail): "the reference failed: \(detail)"
        case .tagsDiffer(let label, let ours, let reference):
            "\(label): ours \(ours), the reference's \(reference)"
        }
    }
}

let deployment = [
    Parameters(memoryKiB: 19_456, iterations: 2, parallelism: 1),
    Parameters(memoryKiB: 65_536, iterations: 3, parallelism: 4),
]
let password = Array("correct horse battery staple".utf8)
let salt = Array("timingsalt012345".utf8)

/// This thread's CPU time so far, in seconds.
func threadCPUSeconds() -> Double {
    var spec = timespec()
    guard clock_gettime(CLOCK_THREAD_CPUTIME_ID, &spec) == 0 else { return 0 }
    return Double(spec.tv_sec) + Double(spec.tv_nsec) / 1e9
}

/// User plus system CPU time of every waited-for child, in seconds.
func childrenCPUSeconds() -> Double {
    var usage = rusage()
    guard getrusage(RUSAGE_CHILDREN, &usage) == 0 else { return 0 }
    let user = Double(usage.ru_utime.tv_sec) + Double(usage.ru_utime.tv_usec) / 1e6
    let system = Double(usage.ru_stime.tv_sec) + Double(usage.ru_stime.tv_usec) / 1e6
    return user + system
}

func hex(_ bytes: [UInt8]) -> String {
    bytes.map { byte in
        let digits = String(byte, radix: 16)
        return digits.count == 1 ? "0" + digits : digits
    }.joined()
}

/// One run of ours: the tag, and this thread's CPU time for it.
func runOurs(_ parameters: Parameters) throws -> (tag: String, seconds: Double) {
    let argon2 = try Argon2id(
        memoryKiB: parameters.memoryKiB, iterations: parameters.iterations,
        parallelism: parameters.parallelism
    )
    let started = threadCPUSeconds()
    let tag = try argon2.hash(password: password, salt: salt, tagLength: 32)
    return (hex(tag), threadCPUSeconds() - started)
}

/// One run of the reference CLI, which prints `Hash:` and `<seconds> seconds` without `-r`.
func runReference(_ cli: String, _ parameters: Parameters) throws -> ReferenceRun {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: cli)
    process.arguments = [
        String(decoding: salt, as: UTF8.self), "-id", "-t", "\(parameters.iterations)",
        "-k", "\(parameters.memoryKiB)", "-p", "\(parameters.parallelism)", "-l", "32",
    ]
    let input = Pipe()
    let output = Pipe()
    process.standardInput = input
    process.standardOutput = output
    let before = childrenCPUSeconds()
    try process.run()
    input.fileHandleForWriting.write(Data(password))
    try input.fileHandleForWriting.close()
    let printed = output.fileHandleForReading.readDataToEndOfFile()
    process.waitUntilExit()
    let after = childrenCPUSeconds()
    guard process.terminationStatus == 0 else {
        throw TimingFailure.referenceFailed("exit status \(process.terminationStatus)")
    }

    var tag: String?
    var seconds: Double?
    for line in String(decoding: printed, as: UTF8.self).split(whereSeparator: \.isNewline) {
        if line.hasPrefix("Hash:") {
            tag = line.dropFirst("Hash:".count).trimmingCharacters(in: .whitespaces)
        } else if line.hasSuffix(" seconds"), let value = Double(line.dropLast(" seconds".count)) {
            seconds = value
        }
    }
    guard let tag, let seconds else { throw TimingFailure.referenceFailed("unexpected output") }
    return ReferenceRun(tag: tag, reportedSeconds: seconds, processCPUSeconds: after - before)
}

func milliseconds(_ seconds: Double) -> String {
    let tenths = (seconds * 10_000).rounded() / 10
    return "\(tenths) ms"
}

func median(_ values: [Double]) -> Double {
    let sorted = values.sorted()
    guard !sorted.isEmpty else { return 0 }
    return sorted[sorted.count / 2]
}

func ratio(_ numerator: Double, _ denominator: Double) -> String {
    guard denominator > 0 else { return "n/a" }
    let hundredths = (numerator / denominator * 100).rounded() / 100
    return "\(hundredths)x"
}

let arguments = CommandLine.arguments
let cli = arguments.count > 1 ? arguments[1] : "/opt/homebrew/bin/argon2"
let runs = arguments.count > 2 ? max(1, Int(arguments[2]) ?? 7) : 7

do {
    print("runs per measurement: \(runs); the minimum is the comparison")
    for parameters in deployment {
        var ours: [Double] = []
        var reported: [Double] = []
        var processCPU: [Double] = []
        for _ in 0..<runs {
            let mine = try runOurs(parameters)
            let reference = try runReference(cli, parameters)
            guard mine.tag == reference.tag else {
                throw TimingFailure.tagsDiffer(parameters.label, ours: mine.tag, reference: reference.tag)
            }
            ours.append(mine.seconds)
            reported.append(reference.reportedSeconds)
            processCPU.append(reference.processCPUSeconds)
        }
        let oursMin = ours.min() ?? 0
        let reportedMin = reported.min() ?? 0
        let processMin = processCPU.min() ?? 0
        print(parameters.label + ": tags agree")
        print("  ours, thread CPU:              min \(milliseconds(oursMin)), median \(milliseconds(median(ours)))")
        print("  reference, as it reports:      min \(milliseconds(reportedMin)), median \(milliseconds(median(reported)))")
        print("  reference, process CPU:        min \(milliseconds(processMin)), median \(milliseconds(median(processCPU)))")
        print("  ours / reference (reported):   \(ratio(oursMin, reportedMin)) at the minimum, \(ratio(median(ours), median(reported))) at the median")
        print("  ours / reference (process):    \(ratio(oursMin, processMin)) at the minimum")
    }
} catch {
    print("argon2id-timing: \(error)")
    exit(1)
}
