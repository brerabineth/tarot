// models.zig — shared types for tarot
const std = @import("std");

pub const version = "0.1.0";

pub const Severity = enum(u8) {
    info = 0,
    low = 1,
    medium = 2,
    high = 3,
    critical = 4,

    pub fn label(self: Severity) []const u8 {
        return switch (self) {
            .info => "INFO",
            .low => "LOW",
            .medium => "MEDIUM",
            .high => "HIGH",
            .critical => "CRITICAL",
        };
    }
};

pub const Band = enum {
    clean,
    low,
    suspect,
    critical,

    pub fn label(self: Band) []const u8 {
        return switch (self) {
            .clean => "CLEAN",
            .low => "LOW",
            .suspect => "SUSPECT",
            .critical => "CRITICAL",
        };
    }

    pub fn exitCode(self: Band) u8 {
        return switch (self) {
            .clean, .low => 0,
            .suspect => 1,
            .critical => 2,
        };
    }
};

pub const Finding = struct {
    card: []const u8, // rule name, e.g. "the tower"
    severity: Severity,
    detail: []const u8, // human-readable, one line
    path: []const u8 = "", // archive entry or file it came from
};

pub const EntryKind = enum { file, directory, symlink, other };

pub const EntryInfo = struct {
    name: []const u8,
    link_name: []const u8 = "",
    kind: EntryKind,
    size: u64 = 0,
    mode: u32 = 0,
};

pub const FileContent = struct {
    path: []const u8, // entry name
    bytes: []const u8, // bounded
    truncated: bool = false,
};

/// Everything the deck needs to judge an artifact.
pub const PackageFacts = struct {
    alloc: std.mem.Allocator,
    source: []const u8, // what was scanned (path as given by user)
    kind: InputKind,
    package_name: []const u8 = "", // from package.json if found
    entries: std.ArrayList(EntryInfo),
    files: std.ArrayList(FileContent), // text files we kept (bounded)
    package_json: ?[]const u8 = null, // raw bytes of root package.json
    npmrc: ?[]const u8 = null, // raw bytes of root .npmrc
    lockfile: ?[]const u8 = null, // raw bytes of package-lock.json
    entry_count: u64 = 0, // real count (may exceed entries list cap)
    bytes_seen: u64 = 0,
    truncated_files: u32 = 0, // files dropped by caps

    pub fn init(alloc: std.mem.Allocator, source: []const u8, kind: InputKind) PackageFacts {
        return .{
            .alloc = alloc,
            .source = source,
            .kind = kind,
            .entries = std.ArrayList(EntryInfo).init(alloc),
            .files = std.ArrayList(FileContent).init(alloc),
        };
    }
};

pub const InputKind = enum {
    tarball,
    directory,
    lockfile,

    pub fn label(self: InputKind) []const u8 {
        return switch (self) {
            .tarball => "tarball",
            .directory => "directory",
            .lockfile => "lockfile",
        };
    }
};

pub const Verdict = struct {
    score: u8, // 0..100
    band: Band,
    findings: std.ArrayList(Finding),
    package_name: []const u8 = "",
    source: []const u8 = "",
    kind: InputKind = .tarball,
    entry_count: u64 = 0,
    bytes_seen: u64 = 0,
    truncated_files: u32 = 0,
    elapsed_ms: u64 = 0,
};

pub fn bandFor(score: u8) Band {
    if (score >= 60) return .critical;
    if (score >= 30) return .suspect;
    if (score >= 10) return .low;
    return .clean;
}

pub const exit_ok: u8 = 0; // clean/low
pub const exit_suspect: u8 = 1;
pub const exit_critical: u8 = 2;
pub const exit_error: u8 = 3; // input/usage error
pub const exit_gate: u8 = 10; // --fail-on threshold crossed

test "bandFor thresholds" {
    try std.testing.expectEqual(Band.clean, bandFor(0));
    try std.testing.expectEqual(Band.clean, bandFor(9));
    try std.testing.expectEqual(Band.low, bandFor(10));
    try std.testing.expectEqual(Band.suspect, bandFor(30));
    try std.testing.expectEqual(Band.suspect, bandFor(59));
    try std.testing.expectEqual(Band.critical, bandFor(60));
    try std.testing.expectEqual(Band.critical, bandFor(100));
}
