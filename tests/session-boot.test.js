#!/usr/bin/env node
// A remembered session must not survive a reboot. Runs the real scripts
// against a stand-in secret-tool.
//
//   node tests/session-boot.test.js

const { createSuite, loadModule } = require("./harness")
const fs = require("fs")
const os = require("os")
const path = require("path")
const { execFileSync, spawnSync } = require("child_process")

const Model = loadModule()

const { check, done } = createSuite("session-boot")

// A stand-in for libsecret. Keeps the stored blob in a file, records every
// call, and can be told to refuse the session collection the way a secret
// service without one would (STUB_NO_SESSION_COLLECTION), to accept the
// write but file it in the login collection (STUB_MISPLACE), or to fail
// every search (STUB_SEARCH_DOWN). Like secret-tool 0.21.8, `store` takes
// a collection only by bus path (or `default`); `busctl` answers SearchItems
// with the item's path, as the secret service does.
const stub = fs.mkdtempSync(path.join(os.tmpdir(), "qsbw-keyring-"))
fs.writeFileSync(path.join(stub, "secret-tool"), `#!/usr/bin/env bash
set -uo pipefail
echo "$*" >> "$STUB/calls"
cmd="\${1:-}"; shift || true
collection=""
for a in "$@"; do case "$a" in --collection=*) collection="\${a#--collection=}" ;; esac; done
case "$cmd" in
  store)
    case "$collection" in ""|default|/*) ;; *) cat >/dev/null; echo "secret-tool: collection must be a full path, or the 'default' alias" >&2; exit 2 ;; esac
    if [ "\${STUB_NO_SESSION_COLLECTION:-}" = "1" ] && [ "$collection" = "/org/freedesktop/secrets/collection/session" ]; then
      cat >/dev/null; exit 1
    fi
    [ "\${STUB_MISPLACE:-}" = "1" ] && collection="/org/freedesktop/secrets/collection/login"
    cat > "$STUB/value"; printf '%s' "$collection" > "$STUB/collection"; exit 0 ;;
  lookup) [ -s "$STUB/value" ] || exit 1; cat "$STUB/value"; exit 0 ;;
  clear)  rm -f "$STUB/value"; exit 0 ;;
esac
exit 1
`)
fs.chmodSync(path.join(stub, "secret-tool"), 0o755)
fs.writeFileSync(path.join(stub, "busctl"), `#!/usr/bin/env bash
echo "busctl $*" >> "$STUB/calls"
[ "\${STUB_SEARCH_DOWN:-}" = "1" ] && exit 1
[ -s "$STUB/value" ] || { echo 'aoao 0 0'; exit 0; }
c=$(cat "$STUB/collection"); [ -n "$c" ] || c="/org/freedesktop/secrets/collection/login"
echo "aoao 1 \\"$c/7\\" 0"
`)
fs.chmodSync(path.join(stub, "busctl"), 0o755)

const TOKEN = "not-a-real-session-token"
const bootId = fs.readFileSync(Model.BOOT_ID_PATH, "utf8").trim()

const reset = () => {
  for (const f of ["value", "collection", "calls"]) fs.rmSync(path.join(stub, f), { force: true })
}
const run = (command, extraEnv) => {
  const env = Object.assign({}, process.env, { PATH: `${stub}:${process.env.PATH}`, STUB: stub }, extraEnv || {})
  return execFileSync(command[0], command.slice(1), { env, encoding: "utf8" })
}
// The store's exit status (it is allowed to fail), and its output.
const runStatus = (command, extraEnv) => {
  const env = Object.assign({}, process.env, { PATH: `${stub}:${process.env.PATH}`, STUB: stub }, extraEnv || {})
  const r = spawnSync(command[0], command.slice(1), { env, encoding: "utf8" })
  return { status: r.status, stdout: r.stdout, stderr: r.stderr }
}
const stored = () => fs.existsSync(path.join(stub, "value"))
  ? fs.readFileSync(path.join(stub, "value"), "utf8") : null
const calls = () => fs.existsSync(path.join(stub, "calls"))
  ? fs.readFileSync(path.join(stub, "calls"), "utf8") : ""

const secretEnv = { [Model.keyringSecretEnvVar()]: TOKEN }

// --- storing ---
reset()
const storedOk = runStatus(Model.keyringStoreCommand(), secretEnv)
check("the session is stored in the memory-only session collection",
  storedOk.status === 0 && fs.readFileSync(path.join(stub, "collection"), "utf8") === "/org/freedesktop/secrets/collection/session",
  storedOk.status + " " + fs.readFileSync(path.join(stub, "collection"), "utf8"))
check("the store is checked by searching for the item afterwards",
  /^busctl --user call .* SearchItems /m.test(calls()), calls())
check("the stored blob carries the boot id that minted the session",
  stored() === `${bootId} ${TOKEN}`, JSON.stringify(stored()))
check("the token still never reaches a command line",
  !Model.keyringStoreCommand().join(" ").includes(TOKEN) && !calls().includes(TOKEN),
  Model.keyringStoreCommand().join(" ") + " || " + calls())
check("the check prints nothing (the search output holds the secret)",
  storedOk.stdout === "" && !storedOk.stderr.includes(TOKEN), JSON.stringify(storedOk))

// A secret service with no session collection: the store fails, with no
// fallback to the default collection, which on Omarchy is a plaintext file
// on disk. The boot-id check is the panel's alone; bw would accept the key
// from that file until `bw lock`.
reset()
const refused = runStatus(Model.keyringStoreCommand(), Object.assign({ STUB_NO_SESSION_COLLECTION: "1" }, secretEnv))
check("a service without a session collection does not get the session at all",
  refused.status === Model.keyringStoreUnavailableCode() && stored() === null,
  refused.status + " " + JSON.stringify(stored()))
check("and the default collection is never tried",
  calls().split("\n").filter(l => l.startsWith("store ")).every(l => l.includes("--collection=/org/freedesktop/secrets/collection/session"))
    && calls().split("\n").filter(l => l.startsWith("store ")).length === 1,
  calls())
check("the store script names no other collection",
  !/store[^|;]*\|\|\s*store\b/.test(Model.keyringStoreCommand()[2]), Model.keyringStoreCommand()[2])

// The write was accepted but the item ended up in another collection (a
// service that ignores --collection): it is removed again.
reset()
const misplaced = runStatus(Model.keyringStoreCommand(), Object.assign({ STUB_MISPLACE: "1" }, secretEnv))
check("an item that landed outside the session collection is removed and reported",
  misplaced.status === Model.keyringStoreMisplacedCode() && stored() === null
    && /^clear /m.test(calls()),
  misplaced.status + " " + JSON.stringify(stored()) + "\n" + calls())

// The write was accepted but the check cannot see where it went: not kept.
reset()
const unseen = runStatus(Model.keyringStoreCommand(), Object.assign({ STUB_SEARCH_DOWN: "1" }, secretEnv))
check("an item the search cannot confirm is removed and reported",
  unseen.status === Model.keyringStoreUnverifiedCode() && stored() === null,
  unseen.status + " " + JSON.stringify(stored()))
check("the store's exit codes are distinct and past secret-tool's own",
  new Set([Model.keyringStoreUnavailableCode(), Model.keyringStoreMisplacedCode(),
    Model.keyringStoreUnverifiedCode()]).size === 3
    && [Model.keyringStoreUnavailableCode(), Model.keyringStoreMisplacedCode(),
      Model.keyringStoreUnverifiedCode()].every(c => c > 1), "")

// --- looking up on the same boot ---
reset()
run(Model.keyringStoreCommand(), secretEnv)
check("a session from this boot is handed back, boot id stripped",
  run(Model.keyringLookupCommand()) === TOKEN, JSON.stringify(run(Model.keyringLookupCommand())))
check("a usable session is left in the keyring",
  stored() !== null, "expected the entry to survive a lookup")

// --- looking up after a reboot ---
reset()
fs.writeFileSync(path.join(stub, "value"), `11111111-2222-3333-4444-555555555555 ${TOKEN}`)
check("a session from another boot is not handed back",
  run(Model.keyringLookupCommand()) === "", JSON.stringify(run(Model.keyringLookupCommand())))
check("a session from another boot is cleared out of the keyring",
  stored() === null, JSON.stringify(stored()))

// An entry written before the boot id existed has no provenance at all, so it
// gets the same treatment rather than the benefit of the doubt.
reset()
fs.writeFileSync(path.join(stub, "value"), TOKEN)
check("a bare pre-boot-id entry is refused and cleared",
  run(Model.keyringLookupCommand()) === "" && stored() === null, JSON.stringify(stored()))

// --- nothing to find ---
reset()
check("an empty keyring is not an error, so the panel falls through to bw status",
  run(Model.keyringLookupCommand()) === "", "expected empty output and exit 0")

fs.rmSync(stub, { recursive: true, force: true })

done()
