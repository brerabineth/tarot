// main.zig — tarot: static pre-install triage for npm artifacts.
// scan | list | cards | forge. nothing executes, nothing leaves the machine.
const std = @import("std");
const models = @import("models.zig");
const archive = @import("archive.zig");
const deck = @import("deck.zig");
const report = @import("report.zig");
const forge = @import("forge.zig");

const usage =
    \\tarot v{s} — read the package before it reads you.
    \\
    \\usage:
    \\  tarot scan <target> [--json] [--quiet] [--fail-on BAND]
    \\  tarot list <tarball>
    \\  tarot cards
    \\  tarot forge <preset> <out.tar>
    \\
    \\targets: .tgz / .tar tarball, extracted package directory,
    \\         package-lock.json. static analysis only — nothing executes.
    \\
    \\bands:   clean < low < suspect < critical
    \\exits:   0 clean/low   1 suspect   2 critical   3 error   10 --fail-on gate
    \\
    \\presets: clean, clipper, worm, traversal, typosquat, secrets
;

fn bandOrder(b: models.Band) u8 {
    return switch (b) {
        .clean => 0,
        .low => 1,
        .suspect => 2,
        .critical => 3,
    };
}

fn parseBand(s: []const u8) ?models.Band {
    if (std.mem.eql(u8, s, "clean")) return .clean;
    if (std.mem.eql(u8, s, "low")) return .low;
    if (std.mem.eql(u8, s, "suspect")) return .suspect;
    if (std.mem.eql(u8, s, "critical")) return .critical;
    return null;
}

fn fail(w: anytype, comptime fmt: []const u8, args: anytype) u8 {
    w.print("tarot: " ++ fmt ++ "\n", args) catch {};
    return models.exit_error;
}

pub fn main() u8 {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const args = std.process.argsAlloc(alloc) catch return models.exit_error;
    const stdout = std.io.getStdOut().writer();
    const stderr = std.io.getStdErr().writer();

    if (args.len < 2) {
        stderr.print(usage ++ "\n", .{models.version}) catch {};
        return models.exit_error;
    }
    const cmd = args[1];

    if (std.mem.eql(u8, cmd, "scan")) {
        return cmdScan(alloc, args[2..], stdout, stderr);
    } else if (std.mem.eql(u8, cmd, "list")) {
        return cmdList(alloc, args[2..], stdout, stderr);
    } else if (std.mem.eql(u8, cmd, "cards")) {
        return cmdCards(stdout);
    } else if (std.mem.eql(u8, cmd, "forge")) {
        return cmdForge(alloc, args[2..], stdout, stderr);
    } else if (std.mem.eql(u8, cmd, "version") or std.mem.eql(u8, cmd, "--version")) {
        stdout.print("tarot v{s}\n", .{models.version}) catch {};
        return models.exit_ok;
    } else if (std.mem.eql(u8, cmd, "help") or std.mem.eql(u8, cmd, "--help")) {
        stdout.print(usage ++ "\n", .{models.version}) catch {};
        return models.exit_ok;
    }
    return fail(stderr, "unknown command '{s}' — try: scan | list | cards | forge", .{cmd});
}

fn cmdScan(alloc: std.mem.Allocator, rest: [][:0]u8, stdout: anytype, stderr: anytype) u8 {
    var target: ?[]const u8 = null;
    var want_json = false;
    var quiet = false;
    var gate: ?models.Band = null;

    var i: usize = 0;
    while (i < rest.len) : (i += 1) {
        const a = rest[i];
        if (std.mem.eql(u8, a, "--json")) {
            want_json = true;
        } else if (std.mem.eql(u8, a, "--quiet")) {
            quiet = true;
        } else if (std.mem.eql(u8, a, "--fail-on")) {
            i += 1;
            if (i >= rest.len) return fail(stderr, "--fail-on needs a band (clean|low|suspect|critical)", .{});
            gate = parseBand(rest[i]) orelse return fail(stderr, "unknown band '{s}'", .{rest[i]});
        } else if (std.mem.startsWith(u8, a, "--")) {
            return fail(stderr, "unknown flag '{s}'", .{a});
        } else if (target == null) {
            target = a;
        } else {
            return fail(stderr, "unexpected extra argument '{s}'", .{a});
        }
    }
    const path = target orelse return fail(stderr, "scan needs a target: a .tgz/.tar, an extracted package directory, or a package-lock.json", .{});

    const t0 = std.time.milliTimestamp();
    var facts = readFacts(alloc, path) catch |e| {
        return switch (e) {
            error.FileNotFound => fail(stderr, "no such file or directory: {s}", .{path}),
            error.InputTooLarge => fail(stderr, "input exceeds scanner cap — refusing to read", .{}),
            error.ArchiveTooLarge => fail(stderr, "decompressed archive exceeds cap — refusing to read", .{}),
            error.TarCorrupt => fail(stderr, "not a readable tar/tgz archive: {s}", .{path}),
            else => fail(stderr, "cannot read {s} ({s})", .{ path, @errorName(e) }),
        };
    };
    var v = deck.judge(alloc, &facts);
    v.elapsed_ms = @intCast(@max(std.time.milliTimestamp() - t0, 0));

    if (want_json) {
        report.writeJson(stdout, &v) catch return models.exit_error;
    } else if (!quiet) {
        report.writeTerminal(stdout, &v) catch return models.exit_error;
    }

    if (gate) |g| {
        if (bandOrder(v.band) >= bandOrder(g)) return models.exit_gate;
        return models.exit_ok;
    }
    return v.band.exitCode();
}

fn readFacts(alloc: std.mem.Allocator, path: []const u8) !models.PackageFacts {
    const base = std.fs.path.basename(path);
    const stat = try std.fs.cwd().statFile(path);
    if (stat.kind == .directory) {
        return archive.scanDirectory(alloc, path);
    }
    if (std.mem.eql(u8, base, "package-lock.json") or std.mem.eql(u8, base, "npm-shrinkwrap.json")) {
        return archive.scanLockfile(alloc, path);
    }
    return archive.scanTarball(alloc, path);
}

fn cmdList(alloc: std.mem.Allocator, rest: [][:0]u8, stdout: anytype, stderr: anytype) u8 {
    if (rest.len < 1) return fail(stderr, "list needs a tarball (.tgz/.tar)", .{});
    const facts = archive.scanTarball(alloc, rest[0]) catch |e| {
        return switch (e) {
            error.FileNotFound => fail(stderr, "no such file or directory: {s}", .{rest[0]}),
            else => fail(stderr, "cannot read {s} ({s})", .{ rest[0], @errorName(e) }),
        };
    };
    stdout.print("{s} — {d} entries\n", .{ rest[0], facts.entry_count }) catch {};
    for (facts.entries.items) |e| {
        const kind_s: []const u8 = switch (e.kind) {
            .file => "file",
            .directory => "dir ",
            .symlink => "link",
            .other => "oth ",
        };
        if (e.kind == .symlink) {
            stdout.print("  {s} {d:>9}  {s} -> {s}\n", .{ kind_s, e.size, e.name, e.link_name }) catch {};
        } else {
            stdout.print("  {s} {d:>9}  {s}\n", .{ kind_s, e.size, e.name }) catch {};
        }
    }
    if (facts.entry_count > facts.entries.items.len) {
        stdout.print("  ... {d} more entries not listed\n", .{facts.entry_count - facts.entries.items.len}) catch {};
    }
    return models.exit_ok;
}

fn cmdCards(stdout: anytype) u8 {
    const cards = [_]struct { name: []const u8, sev: []const u8, meaning: []const u8 }{
        .{ .name = "the tower", .sev = "critical", .meaning = "path-traversal entries (zip-slip) in the archive" },
        .{ .name = "the chain", .sev = "critical", .meaning = "remote code piped straight into a shell" },
        .{ .name = "the faceless", .sev = "critical", .meaning = "decoded payload executed via eval/Function" },
        .{ .name = "the key", .sev = "critical", .meaning = "live-looking credentials embedded in the package" },
        .{ .name = "the impostor", .sev = "critical", .meaning = "typosquat: one edit from a trusted name, or homoglyphs" },
        .{ .name = "the plague", .sev = "varies", .meaning = "worm markers: Shai-Hulud IOCs, self-publish, credential sweepers" },
        .{ .name = "the gatekeeper", .sev = "varies", .meaning = "registry redirection (.npmrc or lifecycle script)" },
        .{ .name = "the puppeteer", .sev = "high", .meaning = "child_process exec/spawn, worst in the install path" },
        .{ .name = "the hangman", .sev = "high", .meaning = "known exfiltration endpoints: webhooks, telegram, pastebin, raw IPs" },
        .{ .name = "the stray", .sev = "varies", .meaning = "symlinks, worst when they escape the package root" },
        .{ .name = "the whisperer", .sev = "medium", .meaning = "install-path code reading credential env vars" },
        .{ .name = "the veil", .sev = "medium", .meaning = "obfuscation: escape soup, embedded base64 blobs" },
        .{ .name = "the mimic", .sev = "medium", .meaning = "double extensions: invoice.pdf.js and friends" },
        .{ .name = "the wanderer", .sev = "medium", .meaning = "lockfile resolving over plain http://" },
        .{ .name = "the seeker", .sev = "info", .meaning = "dependencies pulled straight from git" },
        .{ .name = "the summoner", .sev = "low", .meaning = "lifecycle hooks present at all" },
        .{ .name = "the fool", .sev = "medium", .meaning = "malformed manifests — something is wrong with this package" },
    };
    stdout.print("the deck — {d} cards, weighted. score caps at 100.\n\n", .{cards.len}) catch {};
    for (cards) |c| {
        stdout.print("  {s:<14} {s:<9} {s}\n", .{ c.name, c.sev, c.meaning }) catch {};
    }
    return models.exit_ok;
}

fn cmdForge(alloc: std.mem.Allocator, rest: [][:0]u8, stdout: anytype, stderr: anytype) u8 {
    if (rest.len < 2) {
        stderr.print("usage: tarot forge <preset> <out.tar>\npresets: ", .{}) catch {};
        for (&forge.presets, 0..) |p, i| {
            stderr.print("{s}{s}", .{ if (i > 0) ", " else "", p.name }) catch {};
        }
        stderr.print("\n", .{}) catch {};
        return models.exit_error;
    }
    const preset = forge.presetByName(rest[0]) orelse return fail(stderr, "unknown preset '{s}'", .{rest[0]});
    const size = forge.writePreset(alloc, rest[0], rest[1]) catch |e| {
        return fail(stderr, "cannot write {s} ({s})", .{ rest[1], @errorName(e) });
    };
    stdout.print("forged {s} -> {s} ({d} bytes)\n  {s}\n", .{ rest[0], rest[1], size, preset.desc }) catch {};
    return models.exit_ok;
}

test {
    _ = @import("models.zig");
    _ = @import("archive.zig");
    _ = @import("deck.zig");
    _ = @import("report.zig");
    _ = @import("forge.zig");
}
