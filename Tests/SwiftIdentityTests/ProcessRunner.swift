import Foundation

/// The one place these tests spawn a process.
///
/// Every run is bounded: a child that outlives its timeout, or whose waiting test is
/// cancelled, is terminated rather than left behind. Output goes to the null device rather than
/// a pipe, so there is no pipe to fill and nothing to drain; a child's result is its exit
/// status.
enum ProcessRunner {

    /// Why a child produced no exit status.
    enum Failure: Error, Equatable {
        /// It outlived its timeout and was terminated.
        case timedOut(executable: String)
    }

    /// Runs an executable to completion, or terminates it at the timeout.
    ///
    /// - Parameters:
    ///   - executable: Absolute path to the binary.
    ///   - arguments: Passed as a vector, never through a shell.
    ///   - environment: The child's whole environment.
    ///   - timeout: The wall-clock ceiling.
    /// - Returns: The exit status.
    /// - Throws: ``Failure/timedOut(executable:)``, a launch failure, or cancellation.
    static func run(
        _ executable: String,
        arguments: [String],
        environment: [String: String],
        timeout: Duration
    ) async throws -> Int32 {
        // SAFETY: the executable is this test runner's own path, and arguments are a vector — no shell.
        let process = Process()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = arguments
        process.environment = environment
        process.standardInput = FileHandle.nullDevice
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        try process.run()

        let deadline = ContinuousClock.now + timeout
        // Bounded by the deadline: every pass sleeps, and the pass after it terminates.
        while process.isRunning {
            guard ContinuousClock.now < deadline else {
                process.terminate()
                throw Failure.timedOut(executable: executable)
            }
            do {
                try await Task.sleep(for: .milliseconds(10))
            } catch {
                process.terminate()
                throw error
            }
        }
        return process.terminationStatus
    }
}
