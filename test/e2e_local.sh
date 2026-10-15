#!/usr/bin/env bash
# e2e_local.sh — end-to-end verification for tarot.
# Every check runs the real binary against real artifacts. Nothing mocked.
set -u
cd "$(dirname "$0")/.."
ROOT="$(pwd)"
BIN="${TAROT_BIN:-$ROOT/zig-out/bin/tarot}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

PASS=0
FAIL=0
say()  { printf '%s\n' "$*"; }
ok()   { PASS=$((PASS+1)); say "  PASS  $*"; }
bad()  { FAIL=$((FAIL+1)); say "  FAIL  $*"; }
expect_exit() { # code description cmd...
  local want="$1" desc="$2"; shift 2
  "$@" >/dev/null 2>&1
  local got=$?
  if [ "$got" = "$want" ]; then ok "$desc (exit $got)"; else bad "$desc — want exit $want, got $got"; fi
}
jband() { # band of a scan result, via --json
  "$@" --json 2>/dev/null | sed -n 's/.*"band": *"\([A-Z]*\)".*/\1/p' | head -1
}
expect_band() { # want desc cmd...
  local want="$1" desc="$2"; shift 2
  local got
  got="$(jband "$@")"
  if [ "$got" = "$want" ]; then ok "$desc (band $got)"; else bad "$desc — want band $want, got '$got'"; fi
}

say "== e2e: tarot =="
[ -x "$BIN" ] || { say "FAIL binary missing at $BIN (run: zig build -Doptimize=ReleaseSafe)"; exit 1; }
cd "$WORK"

# --- forge all presets --------------------------------------------------
for p in clean clipper worm traversal typosquat secrets; do
  expect_exit 0 "forge $p" "$BIN" forge "$p" "$p.tar"
done

# determinism: identical bytes on rebuild
"$BIN" forge worm d1.tar >/dev/null 2>&1
"$BIN" forge worm d2.tar >/dev/null 2>&1
if [ "$(sha256sum d1.tar | cut -d' ' -f1)" = "$(sha256sum d2.tar | cut -d' ' -f1)" ]; then
  ok "forge determinism (byte-identical)"
else bad "forge determinism"; fi

# --- verdicts and exit codes -------------------------------------------
expect_band CLEAN    "scan clean.tar"      "$BIN" scan clean.tar
expect_exit 0        "scan clean.tar exit"  "$BIN" scan clean.tar --quiet
expect_band CRITICAL "scan clipper.tar"    "$BIN" scan clipper.tar
expect_exit 2        "scan clipper.tar exit" "$BIN" scan clipper.tar --quiet
expect_band CRITICAL "scan worm.tar"       "$BIN" scan worm.tar
expect_exit 2        "scan worm.tar exit"   "$BIN" scan worm.tar --quiet
expect_band CRITICAL "scan traversal.tar"  "$BIN" scan traversal.tar
expect_exit 2        "scan traversal.tar exit" "$BIN" scan traversal.tar --quiet
expect_band SUSPECT  "scan typosquat.tar"  "$BIN" scan typosquat.tar
expect_exit 1        "scan typosquat.tar exit" "$BIN" scan typosquat.tar --quiet
expect_band CRITICAL "scan secrets.tar"    "$BIN" scan secrets.tar
expect_exit 2        "scan secrets.tar exit" "$BIN" scan secrets.tar --quiet

# specific cards must fire
"$BIN" scan worm.tar --json | grep -qE '"card": "the plague"' && ok "worm: plague card" || bad "worm: plague card missing"
"$BIN" scan traversal.tar --json | grep -qE '"card": "the tower"' && ok "traversal: tower card" || bad "traversal: tower card missing"
"$BIN" scan traversal.tar --json | grep -qE '"card": "the mimic"' && ok "traversal: mimic card" || bad "traversal: mimic card missing"
"$BIN" scan clipper.tar --json | grep -qE '"card": "the chain"' && ok "clipper: chain card" || bad "clipper: chain card missing"
"$BIN" scan clipper.tar --json | grep -qE '"card": "the hangman"' && ok "clipper: hangman card" || bad "clipper: hangman card missing"
"$BIN" scan typosquat.tar --json | grep -qE '"card": "the impostor"' && ok "typosquat: impostor card" || bad "typosquat: impostor card missing"

# --- gzip path -----------------------------------------------------------
gzip -n -c clipper.tar > clipper.tgz
expect_band CRITICAL "scan clipper.tgz (gzip)" "$BIN" scan clipper.tgz
expect_exit 2        "scan clipper.tgz exit"    "$BIN" scan clipper.tgz --quiet

# --- directory mode -------------------------------------------------------
mkdir -p pkgdir && tar -xf clean.tar -C pkgdir
expect_band CLEAN "scan extracted directory" "$BIN" scan pkgdir
expect_exit 0     "scan directory exit"       "$BIN" scan pkgdir --quiet

# --- lockfile mode ---------------------------------------------------------
cat > package-lock.json <<'EOF'
{
  "name": "lab",
  "lockfileVersion": 3,
  "packages": {
    "": { "name": "lab" },
    "node_modules/reactx": { "resolved": "https://registry.npmjs.org/reactx", "hasInstallScript": true },
    "node_modules/chalkk": { "resolved": "git+ssh://git@github.com/evil/chalkk.git" },
    "node_modules/left-pad": { "resolved": "http://registry.npmjs.org/left-pad" }
  }
}
EOF
expect_band CRITICAL "scan lockfile (2 typosquats)" "$BIN" scan package-lock.json
"$BIN" scan package-lock.json --json | grep -qE '"card": "the impostor"' && ok "lockfile: impostor card" || bad "lockfile: impostor card missing"
"$BIN" scan package-lock.json --json | grep -qE '"card": "the seeker"' && ok "lockfile: seeker card" || bad "lockfile: seeker card missing"
"$BIN" scan package-lock.json --json | grep -qE '"card": "the wanderer"' && ok "lockfile: wanderer card" || bad "lockfile: wanderer card missing"

# --- secret masking: no full credential ever printed -----------------------
if "$BIN" scan secrets.tar --json | grep -qE 'ghp_16C7e42F292c6912E7710c838347Ae178B4a'; then
  bad "masking: full token leaked in output"
else ok "masking: token truncated in output"; fi
if "$BIN" scan secrets.tar --json | grep -qE 'AKIAIOSFODNN7EXAMPLE'; then
  bad "masking: full AWS key leaked"
else ok "masking: AWS key truncated"; fi

# --- fail-on gate -----------------------------------------------------------
expect_exit 10 "fail-on suspect flags typosquat" "$BIN" scan typosquat.tar --quiet --fail-on suspect
expect_exit 0  "fail-on suspect passes clean"    "$BIN" scan clean.tar --quiet --fail-on suspect
expect_exit 10 "fail-on critical flags worm"     "$BIN" scan worm.tar --quiet --fail-on critical

# --- list / cards / version / help ------------------------------------------
"$BIN" list traversal.tar | grep -qE '\.\./\.bashrc' && ok "list shows traversal entry" || bad "list: traversal entry missing"
"$BIN" list traversal.tar | grep -qE 'escape -> ' && ok "list shows symlink target" || bad "list: symlink missing"
[ "$("$BIN" cards | grep -cE '^  the ' )" -ge 17 ] && ok "cards lists full deck" || bad "cards: deck incomplete"
expect_exit 0 "version" "$BIN" version
expect_exit 3 "scan missing file"  "$BIN" scan /nonexistent/x.tgz
expect_exit 3 "unknown preset"     "$BIN" forge nope out.tar
expect_exit 3 "unknown command"    "$BIN" séance
head -c 600 /dev/urandom > garbage.bin
expect_exit 3 "corrupt tar refused" "$BIN" scan garbage.bin

# --- oversized entry handled gracefully --------------------------------------
mkdir -p big/pkg && python3 -c "open('big/pkg/blob.js','wb').write(b'//' + b'x'*3*1024*1024)" 2>/dev/null || \
  dd if=/dev/zero of=big/pkg/blob.js bs=1024 count=3072 2>/dev/null
printf '{"name":"big","version":"1.0.0"}' > big/pkg/package.json
tar -cf big.tar -C big pkg
out="$("$BIN" scan big.tar --json)"
echo "$out" | grep -qE '"truncated_files": [1-9]' && ok "oversized entry counted as truncated" || bad "oversized entry handling: $out"
echo "$out" | grep -qE '"band":' && ok "oversized archive still judged" || bad "oversized archive broke scan"

# --- path hygiene: no host paths in any output -------------------------------
leak=0
for f in clean.tar clipper.tar worm.tar traversal.tar typosquat.tar secrets.tar package-lock.json; do
  if "$BIN" scan "$f" 2>&1 | grep -qE '/home/|/root/|/Users/'; then leak=1; fi
done
"$BIN" cards 2>&1 | grep -qE '/home/|/root/' && leak=1
"$BIN" list traversal.tar 2>&1 | grep -qE '/home/|/root/' && leak=1
[ "$leak" = "0" ] && ok "path hygiene: no host paths in any output" || bad "path hygiene: HOST PATH LEAKED"

say ""
say "== e2e summary: $PASS passed, $FAIL failed =="
[ "$FAIL" = "0" ] || exit 1
exit 0
