import Foundation
import Testing
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif
@testable import SwiftIdentity

@Suite("SecureIdentityFiles")
struct SecureIdentityFilesTests {
    private typealias Support = AdministrationTestSupport

    @Test("A relative path and a path that climbs are refused")
    func unsafePaths() {
        #expect(throws: SecureIdentityFiles.Failure.unsafePath("identity")) { try SecureIdentityFiles.requireDirectory("identity") }
        #expect(throws: SecureIdentityFiles.Failure.unsafePath("/tmp/../etc")) { try SecureIdentityFiles.requireDirectory("/tmp/../etc") }
    }

    @Test("An owner-only directory passes; one anyone can enter is refused as permissive")
    func directoryPermissions() throws {
        let dir = try Support.directory()
        defer { Support.remove(dir) }
        #expect(throws: Never.self) { try SecureIdentityFiles.requireDirectory(dir) }
        #expect(chmod(dir, 0o755) == 0)
        #expect(throws: SecureIdentityFiles.Failure.permissive(dir)) { try SecureIdentityFiles.requireDirectory(dir) }
    }

    @Test("A file anyone can read is refused, and a missing one is unreadable")
    func filePermissions() throws {
        let dir = try Support.directory()
        defer { Support.remove(dir) }
        let path = dir + "/verifiers"
        try SecureIdentityFiles.replace(path, with: "x\n")
        #expect(throws: Never.self) { try SecureIdentityFiles.requireFile(path) }
        #expect(chmod(path, 0o644) == 0)
        #expect(throws: SecureIdentityFiles.Failure.permissive(path)) { try SecureIdentityFiles.requireFile(path) }
        #expect(throws: SecureIdentityFiles.Failure.unreadable(dir + "/absent")) { try SecureIdentityFiles.requireFile(dir + "/absent") }
    }

    @Test("A symbolic link is refused, whatever it points to")
    func symbolicLink() throws {
        let dir = try Support.directory()
        defer { Support.remove(dir) }
        try SecureIdentityFiles.replace(dir + "/real", with: "x\n")
        #expect(symlink(dir + "/real", dir + "/link") == 0)
        #expect(throws: SecureIdentityFiles.Failure.symbolicLink(dir + "/link")) { try SecureIdentityFiles.requireFile(dir + "/link") }
    }

    @Test("A directory where a file is expected, and a file where a directory is expected, are the wrong kind")
    func wrongKind() throws {
        let dir = try Support.directory()
        defer { Support.remove(dir) }
        try SecureIdentityFiles.replace(dir + "/f", with: "x\n")
        #expect(throws: SecureIdentityFiles.Failure.wrongKind(dir)) { try SecureIdentityFiles.requireFile(dir) }
        #expect(throws: SecureIdentityFiles.Failure.wrongKind(dir + "/f")) { try SecureIdentityFiles.requireDirectory(dir + "/f") }
    }

    @Test("makeDirectory gives 0700 whatever the umask says, and refuses one that exists")
    func makeDirectory() throws {
        let dir = try Support.directory()
        defer { Support.remove(dir) }
        let old = umask(0)
        defer { umask(old) }
        try SecureIdentityFiles.makeDirectory(dir + "/made")
        #expect(Support.mode(of: dir + "/made") == 0o700)
        #expect(throws: SecureIdentityFiles.Failure.alreadyExists(dir + "/made")) { try SecureIdentityFiles.makeDirectory(dir + "/made") }
    }

    @Test("replace writes 0600, replaces whole, and leaves no temporary file")
    func replace() throws {
        let dir = try Support.directory()
        defer { Support.remove(dir) }
        let old = umask(0)
        defer { umask(old) }
        let path = dir + "/subjects"
        try SecureIdentityFiles.replace(path, with: "first\n")
        try SecureIdentityFiles.replace(path, with: "second\n")
        #expect(try Support.read(path) == "second\n")
        #expect(Support.mode(of: path) == 0o600)
        let names = try FileManager.default.contentsOfDirectory(atPath: dir)
        #expect(names == ["subjects"], "no leftover temporary file: \(names)")
    }

    @Test("replace will not write through a symbolic link at the target: it replaces the link, never the file it points to")
    func replaceDoesNotFollow() throws {
        let dir = try Support.directory()
        defer { Support.remove(dir) }
        try SecureIdentityFiles.replace(dir + "/victim", with: "untouched\n")
        #expect(symlink(dir + "/victim", dir + "/target") == 0)
        try SecureIdentityFiles.replace(dir + "/target", with: "new\n")
        #expect(try Support.read(dir + "/victim") == "untouched\n")
    }

    @Test("A stamp changes when a file is replaced, and is nil for a path that is not there")
    func stamps() throws {
        let dir = try Support.directory()
        defer { Support.remove(dir) }
        let path = dir + "/verifiers"
        #expect(SecureIdentityFiles.stamp(of: path) == nil)
        try SecureIdentityFiles.replace(path, with: "a\n")
        let first = try #require(SecureIdentityFiles.stamp(of: path))
        try SecureIdentityFiles.replace(path, with: "b\n")
        #expect(SecureIdentityFiles.stamp(of: path) != first)
    }
}
