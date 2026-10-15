// report.zig — verdict rendering: ANSI terminal (ASCII only) and JSON.
const std = @import("std");
const models = @import("models.zig");

const Verdict = models.Verdict;

const c_reset = "\x1b[0m";
const c_bold = "\x1b[1m";
const c_dim = "\x1b[2m";
const c_red = "\x1b[31m";
const c_green = "\x1b[32m";
const c_yellow = "\x1b[33m";
const c_cyan = "\x1b[36m";
const c_gray = "\x1b[90m";

const banner =
    \\  _____
    \\ |_   _| __ ___  _ __ ___  _   _
    \\   | || '_ ` _ \| '_ ` _ \| | | |
    \\   | || | | | | | | | | | | |_| |
    \\   |_||_| |_| |_|_| |_| |_|\__,_|
;

fn sevColor(sev: models.Severity) []const u8 {
    return switch (sev) {
        .critical => c_red,
        .high => c_yellow,
        .medium => c_cyan,
        .low => c_green,
        .info => c_gray,
    };
}

fn bandColor(band: models.Band) []const u8 {
    return switch (band) {
        .critical => c_red,
        .suspect => c_yellow,
        .low => c_cyan,
        .clean => c_green,
    };
}

pub fn writeTerminal(w: anytype, v: *const Verdict) !void {
    try w.print("{s}{s}{s}\n", .{ c_cyan, banner, c_reset });
    try w.print("{s}  v{s} — static pre-install triage. nothing executes.{s}\n\n", .{ c_dim, models.version, c_reset });

    try w.print("  {s}reading{s}    {s} ({s}, {d} entries, {s}", .{ c_bold, c_reset, v.source, v.kind.label(), v.entry_count, fmtBytes(v.bytes_seen) });
    if (v.truncated_files > 0) try w.print(", {d} file(s) skipped by cap", .{v.truncated_files});
    try w.print(")\n", .{});
    if (v.package_name.len > 0) {
        try w.print("  {s}package{s}    {s}\n", .{ c_bold, c_reset, v.package_name });
    }
    try w.print("  {s}verdict{s}    {s}{s}{s} — score {d}/100", .{ c_bold, c_reset, bandColor(v.band), c_bold, v.band.label(), v.score });
    if (v.band == .suspect or v.band == .critical) {
        try w.print("  {s}[do not install]{s}", .{ c_red, c_reset });
    }
    try w.print("\n", .{});

    if (v.findings.items.len == 0) {
        try w.print("\n  {s}no cards drawn. the deck stays dark.{s}\n", .{ c_dim, c_reset });
        return;
    }
    try w.print("\n", .{});
    for (v.findings.items, 0..) |f, i| {
        try w.print("  {s}{d:>2}{s}  {s}{s:<13}{s} {s}{s}{s}  {s}\n", .{
            c_dim, i + 1, c_reset,
            sevColor(f.severity), f.severity.label(), c_reset,
            sevColor(f.severity), f.card, c_reset,
            f.detail,
        });
        if (f.path.len > 0) {
            try w.print("       {s}{s}{s}\n", .{ c_dim, f.path, c_reset });
        }
    }
    try w.print("\n  {s}{d} card(s) drawn in {d} ms{s}\n", .{ c_dim, v.findings.items.len, v.elapsed_ms, c_reset });
}

fn fmtBytes(n: u64) []const u8 {
    // small static buffer trick is not safe for multiple calls per line;
    // only used once per report here.
    if (n >= 1024 * 1024) return fmtBytesCached(n, "M");
    if (n >= 1024) return fmtBytesCached(n, "K");
    return fmtBytesCached(n, "B");
}

var bytes_buf: [32]u8 = undefined;

fn fmtBytesCached(n: u64, unit: []const u8) []const u8 {
    const v: u64 = switch (unit[0]) {
        'M' => n / (1024 * 1024),
        'K' => n / 1024,
        else => n,
    };
    return std.fmt.bufPrint(&bytes_buf, "{d} {s}", .{ v, unit }) catch "?";
}

// ---- JSON ---------------------------------------------------------------
pub fn jsonEscape(w: anytype, s: []const u8) !void {
    for (s) |c| {
        switch (c) {
            '"' => try w.writeAll("\\\""),
            '\\' => try w.writeAll("\\\\"),
            '\n' => try w.writeAll("\\n"),
            '\r' => try w.writeAll("\\r"),
            '\t' => try w.writeAll("\\t"),
            else => {
                if (c < 0x20) {
                    try w.print("\\u{x:0>4}", .{c});
                } else {
                    try w.writeByte(c);
                }
            },
        }
    }
}

pub fn writeJson(w: anytype, v: *const Verdict) !void {
    try w.writeAll("{\n");
    try w.writeAll("  \"tool\": \"tarot\",\n");
    try w.print("  \"version\": \"{s}\",\n", .{models.version});
    try w.writeAll("  \"source\": \"");
    try jsonEscape(w, v.source);
    try w.writeAll("\",\n");
    try w.print("  \"kind\": \"{s}\",\n", .{v.kind.label()});
    try w.writeAll("  \"package\": \"");
    try jsonEscape(w, v.package_name);
    try w.writeAll("\",\n");
    try w.print("  \"score\": {d},\n", .{v.score});
    try w.print("  \"band\": \"{s}\",\n", .{v.band.label()});
    try w.print("  \"entry_count\": {d},\n", .{v.entry_count});
    try w.print("  \"bytes_read\": {d},\n", .{v.bytes_seen});
    try w.print("  \"truncated_files\": {d},\n", .{v.truncated_files});
    try w.print("  \"elapsed_ms\": {d},\n", .{v.elapsed_ms});
    try w.writeAll("  \"findings\": [\n");
    for (v.findings.items, 0..) |f, i| {
        try w.writeAll("    {\"card\": \"");
        try jsonEscape(w, f.card);
        try w.print("\", \"severity\": \"{s}\", \"path\": \"", .{f.severity.label()});
        try jsonEscape(w, f.path);
        try w.writeAll("\", \"detail\": \"");
        try jsonEscape(w, f.detail);
        try w.writeAll("\"}");
        if (i + 1 < v.findings.items.len) try w.writeAll(",");
        try w.writeAll("\n");
    }
    try w.writeAll("  ]\n}\n");
}

// ---- tests ---------------------------------------------------------------
test "jsonEscape" {
    var buf = std.ArrayList(u8).init(std.testing.allocator);
    defer buf.deinit();
    try jsonEscape(buf.writer(), "a\"b\\c\nd\x01");
    try std.testing.expectEqualStrings("a\\\"b\\\\c\\nd\\u0001", buf.items);
}

test "writeJson parses" {
    var v = Verdict{
        .score = 40,
        .band = .critical,
        .findings = std.ArrayList(models.Finding).init(std.testing.allocator),
        .source = "x.tgz",
        .kind = .tarball,
    };
    defer v.findings.deinit();
    v.findings.append(.{ .card = "the key", .severity = .critical, .detail = "token \"quoted\"", .path = "lib/a.js" }) catch unreachable;
    var buf = std.ArrayList(u8).init(std.testing.allocator);
    defer buf.deinit();
    try writeJson(buf.writer(), &v);
    const parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, buf.items, .{});
    defer parsed.deinit();
    try std.testing.expectEqualStrings(models.Band.critical.label(), parsed.value.object.get("band").?.string);
}
