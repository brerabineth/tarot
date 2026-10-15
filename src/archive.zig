// archive.zig — input readers: tar/tgz, extracted directory, raw lockfile.
// Bounded everything: no entry content is trusted, nothing executes.
const std = @import("std");
const models = @import("models.zig");

pub const max_input_bytes: usize = 512 * 1024 * 1024; // compressed input cap
pub const max_decompressed_bytes: usize = 1024 * 1024 * 1024; // 1 GiB
pub const max_file_bytes: usize = 2 * 1024 * 1024; // per stored file
pub const max_total_file_bytes: usize = 64 * 1024 * 1024; // sum of stored files
pub const max_entries_stored: usize = 20000;

pub const Error = error{
    TarCorrupt,
    ArchiveTooLarge,
    NotTarball,
    InputTooLarge,
    InvalidLockfile,
} || std.mem.Allocator.Error || std.fs.File.OpenError || std.fs.File.ReadError || std.fs.File.StatError;

fn isTextName(name_lower: []const u8) bool {
    const exts = [_][]const u8{
        ".js", ".cjs", ".mjs", ".json", ".sh", ".bash", ".yml",
        ".yaml", ".txt", ".md", ".ts", ".mts", ".cts", ".toml", ".ini", ".xml", ".html",
    };
    for (exts) |e| {
        if (std.mem.endsWith(u8, name_lower, e)) return true;
    }
    return false;
}

fn depthOf(name: []const u8) usize {
    var d: usize = 0;
    for (name) |c| {
        if (c == '/') d += 1;
    }
    return d;
}

/// basename of a normalized (no trailing slash) path
fn baseName(name: []const u8) []const u8 {
    if (std.mem.lastIndexOfScalar(u8, name, '/')) |i| return name[i + 1 ..];
    return name;
}

fn normalizeName(buf: []const u8, alloc: std.mem.Allocator) ![]const u8 {
    var s = buf;
    while (s.len >= 2 and s[0] == '.' and s[1] == '/') s = s[2..]; // strip leading ./
    if (s.len > 1 and s[s.len - 1] == '/') s = s[0 .. s.len - 1]; // dirs
    return alloc.dupe(u8, s);
}

fn considerSpecial(facts: *models.PackageFacts, name: []const u8, content: []const u8) !void {
    const b = baseName(name);
    if (depthOf(name) <= 1) {
        if (std.mem.eql(u8, b, "package.json") and facts.package_json == null) {
            facts.package_json = try facts.alloc.dupe(u8, content);
        } else if (std.mem.eql(u8, b, ".npmrc") and facts.npmrc == null) {
            facts.npmrc = try facts.alloc.dupe(u8, content);
        } else if (std.mem.eql(u8, b, "package-lock.json") and facts.lockfile == null) {
            facts.lockfile = try facts.alloc.dupe(u8, content);
        }
    }
}

fn recordEntry(facts: *models.PackageFacts, name: []const u8, link: []const u8, kind: models.EntryKind, size: u64, mode: u32) !void {
    facts.entry_count += 1;
    if (facts.entries.items.len < max_entries_stored) {
        try facts.entries.append(.{
            .name = name,
            .link_name = link,
            .kind = kind,
            .size = size,
            .mode = mode,
        });
    }
}

fn recordFile(facts: *models.PackageFacts, name: []const u8, content: []const u8) !void {
    var total: usize = 0;
    for (facts.files.items) |f| total += f.bytes.len;
    const lower = try std.ascii.allocLowerString(facts.alloc, name);
    defer facts.alloc.free(lower);
    if (!isTextName(lower) and !std.mem.eql(u8, baseName(name), ".npmrc")) return;
    if (content.len > max_file_bytes) {
        facts.truncated_files += 1;
        return;
    }
    if (total + content.len > max_total_file_bytes) {
        facts.truncated_files += 1;
        return;
    }
    const kept = try facts.alloc.dupe(u8, content);
    try facts.files.append(.{ .path = name, .bytes = kept });
    try considerSpecial(facts, name, content);
}

fn inflateTar(facts: *models.PackageFacts, tar_bytes: []const u8) !void {
    var fbs = std.io.fixedBufferStream(tar_bytes);
    var name_buf: [std.fs.max_path_bytes]u8 = undefined;
    var link_buf: [std.fs.max_path_bytes]u8 = undefined;
    var iter = std.tar.iterator(fbs.reader(), .{
        .file_name_buffer = &name_buf,
        .link_name_buffer = &link_buf,
    });
    while (true) {
        const next = iter.next() catch return error.TarCorrupt;
        const f = next orelse break;
        const name = try normalizeName(f.name, facts.alloc);
        const link = if (f.kind == .sym_link)
            try facts.alloc.dupe(u8, std.mem.trim(u8, f.link_name, " \x00"))
        else
            try facts.alloc.dupe(u8, "");
        const kind: models.EntryKind = switch (f.kind) {
            .directory => .directory,
            .sym_link => .symlink,
            .file => .file,
        };
        try recordEntry(facts, name, link, kind, f.size, f.mode);
        if (f.kind == .file and f.size > 0) {
            if (f.size <= max_file_bytes and facts.bytes_seen + f.size <= max_total_file_bytes) {
                var content = std.ArrayList(u8).init(facts.alloc);
                try f.writeAll(content.writer());
                facts.bytes_seen += content.items.len;
                try recordFile(facts, name, content.items);
            } else if (f.size > max_file_bytes) {
                facts.truncated_files += 1;
                // content is auto-skipped by the iterator on next()
            }
        }
    }
}

/// Scan a .tgz or .tar file. Reads the compressed input with a hard cap,
/// sniffs gzip magic, inflates into a bounded buffer, walks the tar.
pub fn scanTarball(alloc: std.mem.Allocator, path: []const u8) !models.PackageFacts {
    var facts = models.PackageFacts.init(alloc, path, .tarball);
    const file = try std.fs.cwd().openFile(path, .{});
    defer file.close();
    const stat = try file.stat();
    if (stat.size > max_input_bytes) return error.InputTooLarge;
    const raw = try alloc.alloc(u8, @intCast(stat.size));
    const got = try file.readAll(raw);
    if (got != raw.len) return error.TarCorrupt;

    var tar_bytes: []const u8 = raw;
    var inflated = std.ArrayList(u8).init(alloc);
    defer inflated.deinit();
    if (raw.len >= 2 and raw[0] == 0x1f and raw[1] == 0x8b) {
        var fbs = std.io.fixedBufferStream(raw);
        var decomp = std.compress.gzip.decompressor(fbs.reader());
        var buf: [65536]u8 = undefined;
        while (true) {
            const n = try decomp.read(&buf);
            if (n == 0) break;
            if (inflated.items.len + n > max_decompressed_bytes) return error.ArchiveTooLarge;
            try inflated.appendSlice(buf[0..n]);
        }
        tar_bytes = inflated.items;
    }
    try inflateTar(&facts, tar_bytes);
    return facts;
}

/// Scan an extracted package directory. Same caps, recursive walk.
pub fn scanDirectory(alloc: std.mem.Allocator, path: []const u8) !models.PackageFacts {
    var facts = models.PackageFacts.init(alloc, path, .directory);
    var dir = try std.fs.cwd().openDir(path, .{ .iterate = true });
    defer dir.close();
    var walker = try dir.walk(alloc);
    defer walker.deinit();
    while (try walker.next()) |entry| {
        if (entry.kind != .file) {
            try recordEntry(&facts, try facts.alloc.dupe(u8, entry.path), "", .directory, 0, 0);
            continue;
        }
        const stat = try dir.statFile(entry.path);
        const rel = try facts.alloc.dupe(u8, entry.path);
        try recordEntry(&facts, rel, "", .file, stat.size, 0);
        if (stat.size <= max_file_bytes) {
            const f = try dir.openFile(entry.path, .{});
            defer f.close();
            const content = try f.readToEndAlloc(alloc, max_file_bytes);
            facts.bytes_seen += content.len;
            try recordFile(&facts, rel, content);
        } else {
            facts.truncated_files += 1;
        }
    }
    return facts;
}

/// Raw lockfile bytes.
pub fn scanLockfile(alloc: std.mem.Allocator, path: []const u8) !models.PackageFacts {
    var facts = models.PackageFacts.init(alloc, path, .lockfile);
    const file = try std.fs.cwd().openFile(path, .{});
    defer file.close();
    const stat = try file.stat();
    if (stat.size > max_input_bytes) return error.InputTooLarge;
    const content = try file.readToEndAlloc(alloc, max_input_bytes);
    facts.lockfile = content;
    facts.bytes_seen = content.len;
    facts.entry_count = 0;
    return facts;
}

test "normalizeName strips ./ and trailing slash" {
    const a = std.testing.allocator;
    const n1 = try normalizeName("./package/lib.js", a);
    defer a.free(n1);
    try std.testing.expectEqualStrings("package/lib.js", n1);
    const n2 = try normalizeName("package/", a);
    defer a.free(n2);
    try std.testing.expectEqualStrings("package", n2);
}
