# tarot

read the package before it reads you.

static pre-install triage for npm artifacts — tarballs (`.tgz` / `.tar`),
extracted packages, and lockfiles. tarot parses everything, executes
nothing, and tells you what the package intends to do to you.

```
$ tarot scan clipper.tgz
verdict    CRITICAL — score 100/100  [do not install]

  1  LOW       the summoner   lifecycle hook present: postinstall
  2  HIGH      the puppeteer  child_process execution in install path
  3  CRITICAL  the chain      remote code piped straight into a shell
  4  MEDIUM    the whisperer  install-path code reads credential env vars
  5  HIGH      the hangman    known exfiltration endpoint: webhook.site
```

## why this exists

the dangerous moment in npm is `npm install`: lifecycle scripts run
before anyone reads the code. 2026 alone delivered the axios compromise,
the node-ipc credential harvester, and the "mini shai-hulud" worm wave.
the audit tooling that exists is SaaS-bound (accounts, agents, telemetry)
or advisory-bound (npm audit matches CVE ids after the fact). nothing
sits in front of the artifact you are about to execute, offline.

tarot is that reader. it never extracts to disk, never spawns a process,
never opens a socket. one static binary, zero runtime dependencies.

## the deck

verdicts are drawn as cards — each one a weighted detection rule:

| card | weight | fires when |
|---|---|---|
| the tower | 60 | path-traversal entries (`../`, absolute, drive letters) — zip-slip |
| the chain | 60 | `curl … \| sh` piped into a shell, in scripts or install path |
| the faceless | 60 | base64/atob-decoded payload executed via `eval` / `Function` |
| the key | 60 | live-looking credentials embedded in source (GitHub, AWS, Stripe, Slack, npm, Anthropic) |
| the impostor | 60/12 | package or dependency name one/two edits from a trusted name; homoglyphs |
| the gatekeeper | 60 | packaged `.npmrc` or lifecycle script redirecting the registry |
| the plague | 60/30 | worm markers: Shai-Hulud IOCs, self-`npm publish`, credential sweepers in install path |
| the puppeteer | 30/12 | `child_process` exec/spawn, weighted worst in the install path |
| the hangman | 30/12 | known exfil endpoints: webhook.site, discord, telegram, pastebin, raw IPs |
| the stray | 30/0 | symlinks — worst when they escape the package root |
| the whisperer | 12 | install-path code reading `NPM_TOKEN`, `GITHUB_TOKEN`, `AWS_*`, … |
| the veil | 12 | obfuscation: `\x` escape soup, embedded base64 blobs |
| the mimic | 12 | double extensions: `invoice.pdf.js` and friends |
| the wanderer | 12 | lockfile resolving over plain `http://` |
| the summoner | 5 | lifecycle hooks present at all |
| the seeker | 0 | dependencies pulled straight from git |
| the fool | 12 | manifests that don't parse — something is already wrong |

score is the sum, capped at 100.

| band | score | exit |
|---|---|---|
| clean | 0–9 | 0 |
| low | 10–29 | 0 |
| suspect | 30–59 | 1 |
| critical | 60+ | 2 |

`--fail-on BAND` forces exit 10 when the verdict meets or exceeds the
band — wire it into CI and nothing suspect installs unattended.

## usage

```console
$ tarot scan evil.tgz              # tarball, tar or tgz
$ tarot scan ./node_modules/left-pad-clone   # extracted package
$ tarot scan package-lock.json     # lockfile sweep
$ tarot scan evil.tgz --json       # machine output
$ tarot scan evil.tgz --fail-on suspect
$ tarot list evil.tgz              # entries: files, sizes, symlinks
$ tarot cards                      # the full deck
```

flags: `--json`, `--quiet` (verdict-free, exit code only), `--fail-on BAND`.

## forge

synthetic fixtures, deterministic to the byte — for tests, demos and
detection tuning without touching real malware:

```console
$ tarot forge clipper clipper.tar      # postinstall credential harvest + exfil
$ tarot forge worm worm.tar            # shai-hulud-style self-publisher
$ tarot forge traversal slip.tar       # zip-slip + escaping symlink
$ tarot forge typosquat reqeust.tar    # one edit from a household name
$ tarot forge secrets leak.tar         # live-looking keys baked in
$ tarot forge clean boring.tar         # the control group
```

presets never contain real payloads — every string is synthetic and
every host is reserved or dead.

## build

zig 0.14.x:

```console
$ zig build -Doptimize=ReleaseSafe
$ zig build test
$ bash test/e2e_local.sh
```

cross-compiles trivially (`-Dtarget=x86_64-windows`, `-Dtarget=aarch64-linux-musl`, …).

## limits, stated plainly

heuristic static analysis, not a sandbox. it reads what the package
*declares and carries* — scripts, payloads, structure, names. packed
binaries, wasm payloads and dynamic construction can hide. use it as
the gate in front of install, not the only gate.

## license

MIT
