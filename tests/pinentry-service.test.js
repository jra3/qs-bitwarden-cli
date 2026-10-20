#!/usr/bin/env node
// Typed secrets in pinentry (Service.qml, "Typed secrets in pinentry"): the
// flows are run here against a stand-in vault (the state they read and write,
// a pinentry process that answers when the test says so); the wiring that
// cannot be run is checked in the source.
//
//   node tests/pinentry-service.test.js

const { createSuite, functionBody, loadModule, read } = require("./harness")

const Model = loadModule()
const service = read("Service.qml")
const body = name => functionBody(service, name)
const { check, eq, done } = createSuite("pinentry-service")

const names = ["requestPinentry", "onPinentryExited", "beginPinentry", "endPinentry", "cancelPinentry",
  "resumeFromPinentry", "unlockWithPinentry", "unlockPinWithPinentry", "retryPinentryPin", "releaseHeldPin",
  "submitRepromptWithPinentry", "submitReprompt", "forgetHeldPassword", "forgetHeldAfter", "onUnlockOutput",
  "declinePinentry", "resetPinentryChoice",
  // The login and the quick-unlock setup forms.
  "loginSecret", "forgetLoginMaster", "submitLoginWithPinentry", "submitLogin", "clearLoginAttempt",
  "requestSetupSecrets", "submitPinSetup", "savePinSetup", "submitFingerprintSetup", "saveFingerprintSetup",
  "submitFidoSetup"]

function makeVault(extra) {
  const v = {
    Model, Qt: { callLater: f => f() },
    usePinentry: true, pinentryMissing: false, pinentryDeclined: false, vaultHelperActive: true,
    // As Service.qml binds them.
    get vaultHelperState() { return this.vaultHelperActive ? "active" : "stopped" },
    get typedSecretEntry() { return Model.typedSecretEntry({ usePinentry: this.usePinentry,
      missing: this.pinentryMissing, declined: this.pinentryDeclined, helperState: this.vaultHelperState }) },
    get pinentryAvailable() { return this.typedSecretEntry === "pinentry" },
    get typedSecretWaits() { return this.typedSecretEntry === "wait" },
    pinentryProgramName: "pinentry", userEmail: "me@example.com",
    pinentryActive: false, pinentryRun: null, pinentryView: null, pinentryWasOpen: false, pinentryReturning: false,
    pinentryMasterName: "", pinentryNotice: "", heldPinName: "",
    status: "locked", errorMessage: "", isUnlocking: false, masterPassword: "", pinEntry: "", pinUnlockError: "",
    pinReady: true, pinBusy: false, pinUnlockSubmitted: false, sshAuthSurfaceActive: true,
    pendingUnlockFrom: "", pendingUnlockPassword: "", pendingPinForMigration: "", fingerprintFromEnvelope: false,
    pinFromEnvelope: false, fidoFromEnvelope: false, restored: 0,
    repromptPending: false, repromptBusy: false, repromptError: "", repromptItemId: "", repromptEpoch: 1,
    vaultEpoch: 1, repromptCallback: null, repromptVerifiedId: "", repromptActionId: "", detailItem: null,
    opened: true, seq: 0, forgotten: [], unlocks: [], pinSubmits: [], shows: 0, verifies: [],
    proc: { running: false, runId: 0, command: null, environment: {}, capture: "", starts: [] },
    newHeldName() { this.seq += 1; return "pw" + this.seq },
    forgetVaultSecret(name) { this.forgotten.push(name) },
    restoreScreenFocus() { this.restored += 1 },
    unlockVaultWithPassword(p) { this.unlocks.push(p) },
    submitPinUnlock(p) { this.pinSubmits.push(p); this.pinUnlockSubmitted = this.submitTakesIt },
    submitTakesIt: true,
    verifyMasterPassword(pw, cb) { this.verifies.push(pw); this.verifyDone = cb },
    prepareUnlock() {}, clearRepromptGrant() {},
    view: null,
    eachView(fn) { fn(this.view) },
    get presenter() { return this.view }
  }
  Object.defineProperty(v, "pinentryProc", { get() { return this.proc } })
  v.view = { hidePopout() { v.opened = false }, showPopout() { v.opened = true; v.shows += 1 } }
  Object.assign(v, extra || {})
  v.root = v
  const make = new Function("root", "with (root) {\n" + names.map(body).join("\n")
    + "\nreturn {" + names.map(n => `${n}: ${n}`).join(", ") + "} }")
  Object.assign(v, make(v))
  return v
}

// The run's end as the process reports it.
function finish(v, code, held, stderr) {
  v.proc.running = false
  v.onPinentryExited(code, held, stderr || "")
}

// --- the master password unlock -------------------------------------------------------

{
  const v = makeVault()
  // `proc.running = true` is the start: record the command it was given.
  Object.defineProperty(v.proc, "running", {
    configurable: true, get() { return this._r === true },
    set(value) { if (value) this.starts.push({ command: this.command, environment: this.environment, capture: this.capture }); this._r = value }
  })
  v.unlockWithPinentry()
  const run = v.proc.starts[0]
  check("an unlock starts a pinentry run that the helper holds", run && /^pinentry:pw\d+$/.test(run.capture), JSON.stringify(run))
  check("the run is the pinentry script, asking for the account's master password",
    run && run.command[1] === Model.pinentryCommand("pinentry", {})[1] && run.command[4] === "pinentry"
      && /me@example\.com/.test(run.environment.QSBW_PE_DESC) && run.command[6] === "Master password:"
      && run.environment.QSBW_PE_ERR === "" && run.command[7] === "0",
    JSON.stringify(run && run.command.slice(3)))
  check("the account is not in the argv, only in the environment",
    !JSON.stringify(run.command).includes("me@example.com"), JSON.stringify(run.command.slice(3)))
  check("the panel is hidden meanwhile and the unlock is not yet started",
    v.pinentryActive && !v.opened && v.unlocks.length === 0, "")
  const name = run.capture.slice("pinentry:".length)
  finish(v, 0, true)
  eq("the held name, not the password, goes to the unlock", v.unlocks.join(), Model.heldSecretRef(name))
  check("nothing typed is in the shell's fields", v.masterPassword === "" && v.pinEntry === "", "")
  check("the unlock remembers the name for a retry and the panel comes back",
    v.pinentryMasterName === name && v.opened && v.shows === 1 && !v.pinentryActive && v.pinentryReturning, "")
  check("coming back is a resume, not a fresh open", v.resumeFromPinentry() === true && v.restored === 1
    && v.resumeFromPinentry() === false, "")

  // `bw` refuses it: forgotten, and asked for again with the reason.
  v.proc.starts.length = 0
  v.isUnlocking = true
  v.pendingUnlockPassword = Model.heldSecretRef(name)
  v.onUnlockOutput("", "Invalid master password.", 1)
  check("a refused password is forgotten", v.forgotten.includes(name) && v.pendingUnlockPassword === "", v.forgotten.join())
  check("and pinentry asks again with an error, in a new run",
    v.proc.starts.length === 1 && v.proc.starts[0].environment.QSBW_PE_ERR === "That is not your master password."
      && v.proc.starts[0].capture !== run.capture, JSON.stringify(v.proc.starts))
  check("no error is shown in the panel for it", v.errorMessage === "" || /not logged in/.test(v.errorMessage), v.errorMessage)

  // Cancelled: back to the unlock screen, nothing said.
  const second = v.proc.starts[0].capture.slice("pinentry:".length)
  v.unlocks.length = 0
  finish(v, 1, false)
  check("a cancel starts nothing, forgets the name, says nothing and restores the panel",
    v.unlocks.length === 0 && v.forgotten.includes(second) && v.errorMessage === "" && v.opened && !v.pinentryActive
      && v.pinentryNotice === "", "")
}

// --- when pinentry cannot be used ---------------------------------------------------------

{
  const v = makeVault({ vaultHelperActive: false })
  let started = false
  Object.defineProperty(v.proc, "running", { configurable: true, get() { return false }, set() { started = true } })
  v.unlockWithPinentry()
  check("without the vault helper nothing is run and nothing changes", !started && !v.pinentryActive && v.opened
    && v.unlocks.length === 0, "")
  check("it is not available then", v.pinentryAvailable === false, "")
  check("nor when turned off or not installed",
    makeVault({ usePinentry: false }).pinentryAvailable === false && makeVault({ pinentryMissing: true }).pinentryAvailable === false, "")
}

{
  // Where the master password and PIN are typed, for every state of the vault
  // helper. Pinentry runs under the helper: while it is not up the panel
  // waits for it rather than offer its own field, which would keep what is
  // typed in the shell. The field is used only when pinentry is off, reported
  // missing, declined after a failure, or the vault is held in the shell as
  // allowVaultWithoutHelper allows.
  const entry = (helperState, extra) => Model.typedSecretEntry(Object.assign(
    { usePinentry: true, missing: false, declined: false, helperState }, extra || {}))
  const states = { pending: "wait", starting: "wait", active: "pinentry", stopped: "wait", fallback: "field", "": "wait", other: "wait" }
  for (const [state, expected] of Object.entries(states)) eq(`helper ${state || "(none)"}: typed in ${expected}`, entry(state), expected)
  for (const state of Object.keys(states)) {
    eq(`helper ${state || "(none)"}, pinentry turned off: the field`, entry(state, { usePinentry: false }), "field")
    eq(`helper ${state || "(none)"}, pinentry missing: the field`, entry(state, { missing: true }), "field")
    eq(`helper ${state || "(none)"}, the field picked: the field`, entry(state, { declined: true }), "field")
  }
}

{
  const v = makeVault()
  Object.defineProperty(v.proc, "running", { configurable: true, get() { return this._r === true }, set(x) { this._r = x } })
  const failed = () => /stopped before answering/.test(v.pinentryNotice)
  v.unlockWithPinentry()
  finish(v, 4, false, "")
  // A program running as you can kill pinentry: a failure that turned it off
  // would have the master password typed into the shell.
  check("a failed run says so, but pinentry stays offered",
    failed() && !v.pinentryDeclined && v.pinentryAvailable && v.opened && v.unlocks.length === 0, v.pinentryNotice)
  v.unlockWithPinentry()
  check("so the next attempt opens pinentry again", v.pinentryActive && v.pinentryRun !== null, "")
  finish(v, 126, false, "unknown capture")
  check("a helper that does not know the capture is a failure", failed() && v.pinentryAvailable, "")
  v.unlockWithPinentry()
  finish(v, 1, false, "the vault helper stopped")
  check("a helper that stopped is not read as a cancel", failed() && v.pinentryAvailable, "")
  v.declinePinentry()
  check("the field is used only once picked, with what that costs",
    v.pinentryDeclined && !v.pinentryAvailable && /stays in the shell's memory/.test(v.pinentryNotice), v.pinentryNotice)
  v.resetPinentryChoice()
  check("and pinentry is back for the next secret", v.pinentryAvailable && v.pinentryNotice === "", "")
  v.unlockWithPinentry()
  finish(v, 3, false, "")
  check("an empty answer asks for a password and is not a failure",
    v.errorMessage === "Master password required" && v.pinentryNotice === "", v.errorMessage)
  v.unlockWithPinentry()
  v.declinePinentry()
  check("the field cannot be picked while pinentry is asking", !v.pinentryDeclined, "")
  finish(v, 1, false, "")
}

{
  // bw failing for another reason than the password: shown, not asked again.
  const v = makeVault()
  Object.defineProperty(v.proc, "running", { configurable: true, get() { return this._r === true }, set(x) { this._r = x } })
  v.unlockWithPinentry()
  finish(v, 0, true)
  const starts = []
  Object.defineProperty(v.proc, "running", { configurable: true, get() { return this._r === true }, set(x) { if (x) starts.push(1); this._r = x } })
  v.onUnlockOutput("", "Some other failure.", 1)
  check("a failure that is not a wrong password does not reopen pinentry", starts.length === 0 && !v.pinentryActive, "")
  const sdk = "\u001b[31mERROR\u001b[0m bitwarden_crypto::keys::master_key: error=The decryption operation failed\n"
    + "The provided key is not the expected type"
  check("isWrongMasterPassword matches bw's own messages, old and 2026.2, only",
    Model.isWrongMasterPassword("Invalid master password.") && Model.isWrongMasterPassword(sdk)
      && Model.isWrongMasterPassword("The provided key is not the expected type")
      && !Model.isWrongMasterPassword("You are not logged in.") && !Model.isWrongMasterPassword(""), "")
  eq("bwErrorText drops the SDK's log lines", Model.bwErrorText(sdk + "\n"), "The provided key is not the expected type")
  eq("and keeps everything else", Model.bwErrorText("  Something else failed.\n"), "Something else failed.")
  const w = makeVault()
  Object.defineProperty(w.proc, "running", { configurable: true, get() { return this._r === true }, set(x) { this._r = x } })
  w.unlockWithPinentry()
  finish(w, 0, true)
  w.onUnlockOutput("", sdk, 1)
  const f = makeVault()
  f.onUnlockOutput("", sdk, 1)
  eq("typed in the panel, it says so plainly, not with bw's log lines", f.errorMessage, "That is not your master password.")
  const g = makeVault()
  g.onUnlockOutput("", "ERROR bitwarden_core::x: noise\nThe vault is broken.", 1)
  eq("another failure is shown without the log lines", g.errorMessage, "The vault is broken.")
  check("bw 2026.2's wrong password reopens pinentry with the reason",
    w.pinentryActive && /That is not your master password\./.test(w.proc.environment.QSBW_PE_ERR), JSON.stringify(w.proc.command && w.proc.environment.QSBW_PE_ERR))
}

// --- a run in the way, and being cancelled --------------------------------------------------

{
  const v = makeVault()
  Object.defineProperty(v.proc, "running", { configurable: true, get() { return this._r === true }, set(x) { this._r = x } })
  v.unlockWithPinentry()
  const name = v.pinentryRun.name
  v.cancelPinentry()
  check("cancelling stops the run, forgets its name and brings the panel back",
    !v.proc.running && v.forgotten.includes(name) && v.opened && !v.pinentryActive && v.pinentryRun === null, "")
  v.onPinentryExited(1, false, "")
  check("the cancelled run's own exit changes nothing", v.errorMessage === "" && v.pinentryNotice === "", "")
  v.proc.runId = 5
  let answer = null
  v.requestPinentry("unlock", "", r => { answer = r })
  check("a run still ending is not started over", answer && answer.state === "unavailable", JSON.stringify(answer))
}

{
  // The flow that asked is told of a cancel, once: the re-prompt's question
  // is waiting on it ("Checking...", Enter ignored) until it hears.
  const v = makeVault()
  Object.defineProperty(v.proc, "running", { configurable: true, get() { return this._r === true }, set(x) { this._r = x } })
  const answers = []
  v.requestPinentry("unlock", "", r => answers.push(r.state))
  v.cancelPinentry()
  v.cancelPinentry()
  v.onPinentryExited(1, false, "")
  eq("a cancelled run is answered once, as cancelled, and its exit adds nothing", answers.join(), "cancelled")

  const w = makeVault({ status: "unlocked", repromptPending: true, repromptItemId: "i1", repromptItemName: "Bank" })
  Object.defineProperty(w.proc, "running", { configurable: true, get() { return this._r === true }, set(x) { this._r = x } })
  w.submitRepromptWithPinentry()
  check("the re-prompt waits on pinentry", w.repromptBusy && w.pinentryActive, "")
  // The panel asked for while pinentry is up (open()): the panel wins.
  w.cancelPinentry()
  check("a cancel frees the re-prompt question, still open and quiet",
    !w.repromptBusy && w.repromptPending && w.repromptError === "" && !w.pinentryActive && w.opened,
    JSON.stringify({ busy: w.repromptBusy, pending: w.repromptPending, error: w.repromptError }))
  w.submitRepromptWithPinentry()
  check("so the question can ask pinentry again", w.repromptBusy && w.pinentryActive && w.pinentryRun !== null, "")
}

{
  // Pinentry was already answering when the cancel came: the helper kept the
  // answer after it was told to forget the name. Nothing else would.
  const v = makeVault()
  Object.defineProperty(v.proc, "running", { configurable: true, get() { return this._r === true }, set(x) { this._r = x } })
  v.unlockWithPinentry()
  const name = v.pinentryRun.name
  v.cancelPinentry()
  v.forgotten.length = 0
  v.onPinentryExited(0, true, "")
  check("an answer held after the cancel is forgotten when its run ends, and used for nothing",
    v.forgotten.join() === name && v.unlocks.length === 0 && !v.pinentryActive && v.pinentryNotice === "",
    JSON.stringify({ forgotten: v.forgotten, unlocks: v.unlocks }))
}

// --- the PIN ---------------------------------------------------------------------------------

{
  const v = makeVault()
  Object.defineProperty(v.proc, "running", { configurable: true, get() { return this._r === true }, set(x) { this._r = x } })
  v.unlockPinWithPinentry()
  check("the PIN is asked for by pinentry, with the PIN prompt",
    v.proc.command[6] === "PIN:" && /PIN/.test(v.proc.environment.QSBW_PE_DESC) && /^pinentry:pw\d+$/.test(v.proc.capture), JSON.stringify(v.proc.command.slice(5)))
  const name = v.proc.capture.slice("pinentry:".length)
  finish(v, 0, true)
  eq("the PIN's name goes to the PIN unlock", v.pinSubmits.join(), Model.heldSecretRef(name))
  check("the PIN is not in the shell's field", v.pinEntry === "", "")
  v.proc.starts = []

  // A PIN under the minimum: the same message as the field, asked for again,
  // and no attempt counted.
  const s = makeVault({ pinAttempts: 0, wrong: 0, countWrongPin() { this.wrong += 1 } })
  Object.defineProperty(s.proc, "running", { configurable: true, get() { return this._r === true }, set(x) {
    if (x) s.proc.starts.push({ command: s.proc.command, environment: s.proc.environment, capture: s.proc.capture }); this._r = x } })
  s.unlockPinWithPinentry()
  check("the PIN run carries the unlock minimum", s.proc.starts[0].command[7] === String(Model.pinUnlockMinLength()),
    JSON.stringify(s.proc.starts[0].command.slice(5)))
  finish(s, Model.pinentryExitCodes().short, false)
  check("a short PIN is not submitted and not counted",
    s.pinSubmits.length === 0 && s.wrong === 0 && s.pinAttempts === 0, "")
  check("it asks again with the field's message",
    s.proc.starts.length === 2 && s.pinUnlockError === "PIN must be at least " + Model.pinUnlockMinLength() + " digits"
      && s.proc.starts[1].environment.QSBW_PE_ERR === s.pinUnlockError, JSON.stringify(s.proc.starts[1]))
  check("a master password run has no minimum", makeVault().proc && (() => {
    const m = makeVault()
    Object.defineProperty(m.proc, "running", { configurable: true, get() { return false }, set() {} })
    m.unlockWithPinentry()
    return m.proc.command[7] === "0"
  })(), "")

  // The unlock was not taken up: nothing else would forget it.
  const w = makeVault({ submitTakesIt: false })
  Object.defineProperty(w.proc, "running", { configurable: true, get() { return this._r === true }, set(x) { this._r = x } })
  w.unlockPinWithPinentry()
  const unused = w.proc.capture.slice("pinentry:".length)
  finish(w, 0, true)
  check("a PIN the unlock did not take up is forgotten", w.forgotten.includes(unused), w.forgotten.join())
  w.heldPinName = "p9"
  check("a PIN in use is released once, and reported", w.releaseHeldPin() === true && w.releaseHeldPin() === false
    && w.forgotten.includes("p9"), "")
}

// --- the re-prompt ---------------------------------------------------------------------------

{
  const v = makeVault({ status: "unlocked", repromptPending: true, repromptItemId: "i1", repromptItemName: "Bank" })
  Object.defineProperty(v.proc, "running", { configurable: true, get() { return this._r === true }, set(x) { this._r = x } })
  let acted = false
  v.repromptCallback = () => { acted = true }
  v.submitRepromptWithPinentry()
  const first = v.proc.capture.slice("pinentry:".length)
  check("the confirmation runs pinentry for the master password",
    /^pinentry:pw\d+$/.test(v.proc.capture) && /master password/i.test(v.proc.environment.QSBW_PE_DESC) && v.repromptBusy, JSON.stringify(v.proc.command.slice(5)))
  finish(v, 0, true)
  eq("the held name is what is verified", v.verifies.join(), Model.heldSecretRef(first))
  v.proc.capture = ""
  v.verifyDone(false)
  check("a wrong password is forgotten and pinentry asks again with the reason",
    v.forgotten.includes(first) && /^pinentry:/.test(v.proc.capture) && v.proc.environment.QSBW_PE_ERR === "That is not your master password."
      && !acted, v.proc.capture)
  const second = v.proc.capture.slice("pinentry:".length)
  finish(v, 0, true)
  v.verifyDone(true)
  check("a right one is forgotten and runs the action", v.forgotten.includes(second) && acted && !v.repromptPending, "")
  check("no field of the shell held it", v.masterPassword === "" && v.pinEntry === "", "")

  const w = makeVault({ status: "unlocked", repromptPending: true, repromptItemId: "i1" })
  Object.defineProperty(w.proc, "running", { configurable: true, get() { return this._r === true }, set(x) { this._r = x } })
  w.submitRepromptWithPinentry()
  finish(w, 1, false)
  check("cancelling leaves the question open and quiet",
    w.repromptPending && !w.repromptBusy && w.repromptError === "" && w.verifies.length === 0, "")
  w.submitRepromptWithPinentry()
  finish(w, 4, false)
  check("a pinentry that fails says so and frees the question for the field",
    w.repromptBusy === false && /stopped before answering/.test(w.repromptError) && w.pinentryAvailable, w.repromptError)
}

// --- the login's master password --------------------------------------------------------------------

// The login as the service runs it, with its processes and its other screens
// stood in for: what reaches the FIFO writer and the API-key login's
// environment is what is checked.
function makeLoginVault(extra) {
  const v = makeVault(Object.assign({
    loginMethod: "email", loginEmail: "me@example.com", loginMasterName: "", loginPassword: "",
    loginClientId: "", loginClientSecret: "", login2faCode: "", login2faMethod: -1, loginAttemptMethod: -1,
    loginSubmitted: false, isLoading: false, logoutPending: false, show2faField: false, show2faMethodPicker: false,
    showDeviceCodeField: false, loginDeviceVerification: false, loginAttemptHadCode: false, login2faMethodConfirmed: false,
    loginDeviceCode: "", deviceVerificationAttempt: false, deviceVerificationPending: false, secondFactorStartedAt: 0,
    loginPasswordRetryUsed: false, rememberedTwoFactorMethod: -1, loginPrewarmSignature: "",
    loginPrepareAfterPrewarmStop: false, loginSubmitAfterPrewarmStop: false,
    loginProc: { running: false, command: null }, writes: [], prewarms: 0,
    resolvedLoginServerUrl() { return "" },
    emailLoginSignature() { return "sig" },
    prepareEmailLogin() { this.prewarms += 1 },
    writeAuthPassword(channel, password) { this.writes.push([channel, password]) }
  }, extra || {}))
  // The view is the presenter; the login focuses fields on it.
  v.view.focusField = function() {}
  Object.defineProperty(v.proc, "running", {
    configurable: true, get() { return this._r === true },
    set(value) { if (value) this.starts.push({ command: this.command, environment: this.environment, capture: this.capture }); this._r = value }
  })
  return v
}

{
  const v = makeLoginVault()
  v.submitLogin()
  const run = v.proc.starts[0]
  check("a login with no password typed asks pinentry for it, naming the account",
    run && /^pinentry:pw\d+$/.test(run.capture) && /log in/i.test(run.environment.QSBW_PE_DESC) && /me@example\.com/.test(run.environment.QSBW_PE_DESC)
      && run.command[6] === "Master password:", JSON.stringify(run))
  check("bw is started first, to be waiting on the FIFO", v.prewarms === 1 && !v.opened && v.writes.length === 0, "")
  const name = run.capture.slice("pinentry:".length)
  finish(v, 0, true)
  check("the answer's name is kept for the attempt and the login is submitted with it",
    v.loginMasterName === name && v.loginSubmitted && v.writes.length === 1 && v.writes[0][0] === "login"
      && v.writes[0][1] === Model.heldSecretRef(name) && v.loginProc.command && /bw login/.test(v.loginProc.command.join(" ")),
    JSON.stringify(v.writes))
  check("nothing typed is in the shell's field, and the panel is back", v.loginPassword === "" && v.opened, "")
  // A two-step challenge: the same held password goes again, without asking.
  v.loginSubmitted = false
  v.loginProc.running = true
  v.loginPrewarmSignature = "sig"
  v.show2faField = true
  v.login2faCode = "123456"
  v.submitLogin()
  check("a second stage sends the same held name and does not ask again",
    v.proc.starts.length === 1 && v.writes.length === 2 && v.writes[1][1] === Model.heldSecretRef(name) && !v.forgotten.includes(name),
    JSON.stringify(v.writes))
  v.clearLoginAttempt()
  check("the end of the attempt forgets it", v.forgotten.includes(name) && v.loginMasterName === "" && v.loginSecret() === "", v.forgotten.join())

  const w = makeLoginVault()
  w.submitLogin()
  finish(w, Model.pinentryExitCodes().cancelled, false)
  check("a cancel submits nothing and keeps no name",
    w.writes.length === 0 && w.loginMasterName === "" && !w.loginSubmitted && w.errorMessage === "" && w.opened, w.errorMessage)
  w.submitLogin()
  finish(w, Model.pinentryExitCodes().empty, false)
  eq("an empty answer asks for a password", w.errorMessage, "Master password is required")

  const x = makeLoginVault({ loginMethod: "apikey", loginClientId: "user.1", loginClientSecret: "s" })
  x.submitLogin()
  check("the API-key login asks pinentry too", x.proc.starts.length === 1, "")
  const apiName = x.proc.starts[0].capture.slice("pinentry:".length)
  finish(x, 0, true)
  check("and its environment carries the held name through loginSecret()",
    x.loginSubmitted && x.loginSecret() === Model.heldSecretRef(apiName) && x.loginProc.command && /bw login --apikey/.test(x.loginProc.command.join(" ")),
    String(x.loginProc.command))

  const y = makeLoginVault({ vaultHelperActive: false })
  y.submitLogin()
  check("without the helper the login waits for it rather than offer the field",
    y.proc.starts.length === 0 && /vault helper/.test(y.errorMessage) && y.typedSecretWaits, y.errorMessage)

  const z = makeLoginVault({ usePinentry: false })
  z.submitLogin()
  eq("with pinentry off the field is asked for", z.errorMessage, "Master password is required")
  z.loginPassword = "hunter2"
  z.submitLogin()
  check("and what it holds goes to the writer as before, with no pinentry run",
    z.proc.starts.length === 0 && z.writes.length === 1 && z.writes[0][1] === "hunter2", JSON.stringify(z.writes))
}

// --- the quick-unlock setup forms ----------------------------------------------------------------

function makeSetupVault(extra) {
  const v = makeVault(Object.assign({
    quickUnlockAvailable: true, quickUnlockUnavailableReason: "no tool", currentScreen: "pin", settings: {}, adds: [],
    pinSetupPin: "", pinSetupConfirm: "", pinSetupMaster: "", pinError: "", pinAttempts: 3, legacyPinStored: true,
    fpBusy: false, fpSetupActive: false, fpError: "", fpSetupMaster: "", legacyFingerprintStored: true,
    fidoBusy: false, fidoUnlocker: { error: "", setups: [], submitSetup(master) { this.setups.push(master) } },
    addQuickUnlockMethod(pw, op, extraEnv, done) { this.adds.push({ pw, op, extraEnv, done }) },
    beginEpochOperation() {}, epochOperationIsStale() { return false }, removeQuickUnlockMethod() {},
    noteQuickUnlockEnabled() {}, requestPinCredentialClear() {}, recomputePinConfigured() {},
    requestMasterCredentialClear() {}, recomputeFingerprintStored() {},
    writeSetting(name, value) { this.settings[name] = value }, flashNotification() {},
    quickUnlockErrorText(why, fallback) { return why === "wrong-password" ? "That is not your master password." : fallback }
  }, extra || {}))
  Object.defineProperty(v.proc, "running", {
    configurable: true, get() { return this._r === true },
    set(value) { if (value) this.starts.push({ command: this.command, environment: this.environment, capture: this.capture }); this._r = value }
  })
  return v
}
const nameOf = run => run.capture.slice("pinentry:".length)

{
  const v = makeSetupVault()
  v.submitPinSetup()
  check("PIN setup asks pinentry for the master password first",
    v.proc.starts.length === 1 && /confirm.*master password/i.test(v.proc.starts[0].environment.QSBW_PE_DESC) && v.proc.starts[0].command[6] === "Master password:"
      && !v.opened, JSON.stringify(v.proc.starts[0] && v.proc.starts[0].command.slice(5)))
  const master = nameOf(v.proc.starts[0])
  finish(v, 0, true)
  const pinRun = v.proc.starts[1]
  check("then for the new PIN, twice in one window, digits only, at the setup floor, with the panel still hidden",
    pinRun && /PIN/.test(pinRun.environment.QSBW_PE_DESC) && pinRun.command[6] === "New PIN:" && pinRun.command[7] === String(Model.pinMinLength())
      && pinRun.command[8] === Model.pinentryRepeatPrompt() && pinRun.command[9] === "1" && !v.opened && v.adds.length === 0,
    JSON.stringify(pinRun && pinRun.command.slice(5)))
  finish(v, Model.pinentryExitCodes().short, false)
  check("a short PIN is asked for again with the reason, the master password still held",
    v.proc.starts.length === 3 && v.proc.starts[2].environment.QSBW_PE_ERR === "PIN must be at least " + Model.pinMinLength() + " digits"
      && !v.forgotten.includes(master), JSON.stringify(v.proc.starts[2] && v.proc.starts[2].environment.QSBW_PE_ERR))
  finish(v, Model.pinentryExitCodes().digits, false)
  check("so is one that is not all digits",
    v.proc.starts.length === 4 && v.proc.starts[3].environment.QSBW_PE_ERR === "PIN must contain only digits", "")
  const pin = nameOf(v.proc.starts[3])
  finish(v, 0, true)
  check("both reach the envelope write by name, and nothing is in the form's fields",
    v.adds.length === 1 && v.adds[0].pw === Model.heldSecretRef(master) && v.adds[0].op.kind === "add-pin"
      && v.adds[0].extraEnv[Model.pinEnvVar()] === Model.heldSecretRef(pin) && v.pinBusy && v.opened
      && v.pinSetupMaster === "" && v.pinSetupPin === "" && v.pinSetupConfirm === "", JSON.stringify(v.adds[0] && v.adds[0].pw))
  v.adds[0].done(true, "")
  check("the write's end forgets both, and the method is on",
    v.forgotten.includes(master) && v.forgotten.includes(pin) && !v.pinBusy && v.settings.pinUnlock === true && v.currentScreen === "settings",
    v.forgotten.join())

  const w = makeSetupVault()
  w.submitPinSetup()
  const wMaster = nameOf(w.proc.starts[0])
  finish(w, 0, true)
  finish(w, Model.pinentryExitCodes().norepeat, false)
  check("a pinentry that cannot take the PIN twice keeps nothing, forgets the master password and offers the fields",
    w.adds.length === 0 && w.forgotten.includes(wMaster) && w.pinentryNotice === Model.pinentryNoRepeatNotice() && w.pinentryAvailable && w.opened,
    w.pinentryNotice)
  w.declinePinentry()
  w.pinSetupMaster = "hunter2"; w.pinSetupPin = "123456"; w.pinSetupConfirm = "123456"
  w.submitPinSetup()
  check("picked, the fields are used as before and no pinentry runs",
    w.proc.starts.length === 2 && w.adds.length === 1 && w.adds[0].pw === "hunter2" && w.adds[0].extraEnv[Model.pinEnvVar()] === "123456"
      && w.pinSetupMaster === "", JSON.stringify(w.adds[0] && w.adds[0].pw))

  const x = makeSetupVault()
  x.submitPinSetup()
  const xMaster = nameOf(x.proc.starts[0])
  finish(x, 0, true)
  finish(x, Model.pinentryExitCodes().cancelled, false)
  check("cancelling at the PIN forgets the master password and writes nothing",
    x.adds.length === 0 && x.forgotten.includes(xMaster) && x.pinError === "" && x.opened, "")
  x.submitPinSetup()
  const xm = nameOf(x.proc.starts[2])
  finish(x, 0, true)
  const xp = nameOf(x.proc.starts[3])
  finish(x, 0, true)
  x.adds[0].done(false, "wrong-password")
  check("a wrong master password is named, and both names are forgotten",
    x.pinError === "That is not your master password." && x.forgotten.includes(xm) && x.forgotten.includes(xp) && !x.pinBusy, x.pinError)

  const y = makeSetupVault({ vaultHelperActive: false })
  y.submitPinSetup()
  check("without the helper the form waits for it", y.proc.starts.length === 0 && /vault helper/.test(y.pinError) && y.adds.length === 0, y.pinError)
}

{
  const v = makeSetupVault({ currentScreen: "fingerprint" })
  v.submitFingerprintSetup()
  check("fingerprint setup asks pinentry for the master password",
    v.proc.starts.length === 1 && /confirm.*master password/i.test(v.proc.starts[0].environment.QSBW_PE_DESC), "")
  const master = nameOf(v.proc.starts[0])
  finish(v, 0, true)
  check("and adds the wrap with it by name, nothing in the field",
    v.proc.starts.length === 1 && v.adds.length === 1 && v.adds[0].pw === Model.heldSecretRef(master) && v.adds[0].op.kind === "add-fingerprint"
      && v.adds[0].extraEnv === null && v.fpBusy && v.fpSetupMaster === "", JSON.stringify(v.adds[0] && v.adds[0].op))
  v.adds[0].done(true, "")
  check("the write's end forgets it", v.forgotten.includes(master) && !v.fpBusy && v.settings.fingerprintUnlock === true, v.forgotten.join())

  const w = makeSetupVault({ currentScreen: "fido" })
  w.submitFidoSetup()
  check("FIDO2 setup asks pinentry for the master password", w.proc.starts.length === 1 && /master password/i.test(w.proc.starts[0].environment.QSBW_PE_DESC), "")
  const wMaster = nameOf(w.proc.starts[0])
  finish(w, 0, true)
  eq("and hands the unlocker the name, not a value", w.fidoUnlocker.setups.join(), Model.heldSecretRef(wMaster))
  const x = makeSetupVault({ usePinentry: false, currentScreen: "fido" })
  x.submitFidoSetup()
  check("with pinentry off the unlocker takes its own field", x.proc.starts.length === 0 && x.fidoUnlocker.setups.length === 1 && x.fidoUnlocker.setups[0] === "", "")
  const y = makeSetupVault({ vaultHelperActive: false, currentScreen: "fido" })
  y.submitFidoSetup()
  check("without the helper it waits", y.fidoUnlocker.setups.length === 0 && /vault helper/.test(y.fidoUnlocker.error), y.fidoUnlocker.error)
}

// --- the wiring ------------------------------------------------------------------------------------

const flows = ["unlockWithPinentry", "unlockPinWithPinentry", "submitRepromptWithPinentry", "requestPinentry", "onPinentryExited",
  "submitLoginWithPinentry", "requestSetupSecrets"].map(body).join("\n")
check("no pinentry flow writes what was typed into the shell's fields",
  !/\b(masterPassword|pinEntry|loginPassword|pinSetupMaster|fpSetupMaster)\s*=[^=]/.test(flows), flows)
check("the run asks the helper to hold the answer",
  /pinentryProc\.capture = "pinentry:" \+ name/.test(body("requestPinentry"))
    && /Model\.pinentryCommand\(pinentryProgramName/.test(body("requestPinentry"))
    && /pinentryProc\.environment = Model\.pinentryEnvironment\(/.test(body("requestPinentry")), body("requestPinentry"))
check("the process is a VaultProcess with no session and no output collector",
  /VaultProcess \{\s*id: pinentryProc\s*vault: root\s*session: false\s*stderr: VaultCollector[^\n]*\n\s*onExited/.test(service)
    && !/id: pinentryProc[\s\S]{0,200}stdout:/.test(service), "")
check("the unlock hands the held name to the password flow",
  /unlockVaultWithPassword\(Model\.heldSecretRef\(r\.name\)\)/.test(body("unlockWithPinentry")), body("unlockWithPinentry"))
check("the PIN unlock takes a held PIN, in place of the field, for both its paths",
  /function submitPinUnlock\(heldPin\)/.test(service)
    && /env\[Model\.pinEnvVar\(\)\] = held \|\|/.test(body("submitPinUnlock"))
    && /if \(!held && String\(pinEntry \|\| ""\)\.length < Model\.pinUnlockMinLength\(\)\)/.test(body("submitPinUnlock"))
    && /heldPinName \? Model\.heldSecretRef\(root\.heldPinName\) : root\.pinEntry/.test(service), body("submitPinUnlock"))
check("a held PIN is forgotten when the envelope answers, and a held PIN for a migration after it",
  /releaseHeldPin\(\)/.test(body("onEnvelopePinResult")) && /forgetHeldPassword\(pin\)/.test(body("migrateLegacyPin"))
    && /forgetHeldPassword\(pendingPinForMigration\)/.test(body("onUnlockOutput")), "")
check("an accepted master password is forgotten once its stored copy has been dealt with",
  /storeAcceptedMasterPassword\(pendingUnlockPassword, forgetHeldAfter\(pendingUnlockPassword\)\)/.test(body("onUnlockSuccess")), "")
check("a failed delivery, an abandoned unlock and a dismissed SSH popup forget it too",
  /forgetHeldPassword\(pendingUnlockPassword\)/.test(body("onAuthPasswordWriterExited"))
    && /forgetHeldPassword\(pendingUnlockPassword\)/.test(body("abandonAuthSecrets"))
    && /forgetHeldPassword\(root\.pendingUnlockPassword\)/.test(body("clearSshPopupUnlockState"))
    && /cancelPinentry\(\)/.test(body("clearSshPopupUnlockState")), "")
check("a lock, another method's unlock and the panel being asked for end a pinentry",
  /cancelPinentry\(\)/.test(body("dropVaultState")) && /cancelPinentry\(\)/.test(body("onUnlockSuccess"))
    && /cancelPinentry\(\)/.test(body("open")), "")
check("hiding the panel for pinentry is not a close; coming back is a resume",
  /else if \(!pinentryActive\) \{\s*pinentryAutoAsked = false\s*clearRepromptGrant\(\)\s*resetPinentryChoice\(\)/.test(service) && /!resumeFromPinentry\(\)/.test(service), "")
check("the field picked after a failure lasts until the panel closes or the vault locks or unlocks",
  /resetPinentryChoice\(\)/.test(body("dropVaultState")) && /resetPinentryChoice\(\)/.test(body("onUnlockSuccess")), "")
check("a pinentry run never runs in the shell: without the helper it is refused",
  /capture\.indexOf\("pinentry:"\) === 0[\s\S]{0,200}proc\.finish\(/.test(body("vaultStart"))
    && body("vaultStart").indexOf("pinentry:") < body("vaultStart").indexOf("runLocally"), body("vaultStart"))
check("the verification of a held password is the existing one",
  /verifyMasterPassword\(pw, function\(ok\)/.test(body("submitReprompt")), "")
check("pinentry counts as an auth surface while it is up, and covers the SSH popup",
  /sshAuthSurfaceActive: opened \|\| sshApprovalPopupOpen \|\| pinentryActive/.test(service)
    && /!vault\.pinentryActive/.test(read("SshApprovalPopup.qml")), "")

// --- the screens --------------------------------------------------------------------------------------

const form = read("UnlockForm.qml")
// Drawn and typed into: tests/qml-kit/tst_unlock_form_pinentry.qml.
check("the unlock form shows its fields only where the vault says, and offers pinentry for both typed methods",
  /typesHere: form\.vault\.typedSecretEntry === "field"/.test(form)
    && /pinentryOffered: form\.vault\.typedSecretEntry === "pinentry"\s*&& \(method === "pin" \|\| method === "password"\)/.test(form)
    && /form\.method === "pin" && form\.typesHere/.test(form)
    && /form\.method === "password" && form\.typesHere/.test(form)
    && /form\.vault\.unlockPinWithPinentry\(\)/.test(form) && /form\.vault\.unlockWithPinentry\(\)/.test(form), "")
check("the fields stay as the fallback, with the reason when pinentry failed",
  /id: passwordField/.test(form) && /id: pinField/.test(form) && /form\.vault\.pinentryNotice/.test(form), "")
{
  const use = (form.match(/function useMethod\(name\) \{[\s\S]*?\n  \}/) || [""])[0]
  check("picking PIN or Password opens pinentry straight away",
    /if \(form\.pinentryOffered\) \{\s*form\.vault\.pinentryAutoAsked = true\s*form\.submitCurrentMethod\(\)\s*return\s*\}/.test(use)
      && use.indexOf("form.pinentryOffered") > use.indexOf("form.chosen = name"), use)
}
{
  const arm = (form.match(/function armOfferedMethod\(\) \{[\s\S]*?\n  \}/) || [""])[0]
  check("a default PIN or password method opens pinentry once when the form shows",
    /else if \(form\.pinentryOffered && !form\.vault\.pinentryAutoAsked && !form\.vault\.pinentryActive\) \{\s*form\.vault\.pinentryAutoAsked = true\s*form\.submitCurrentMethod\(\)/.test(arm), arm)
  const use = (form.match(/function useMethod\(name\) \{[\s\S]*?\n  \}/) || [""])[0]
  check("picking it counts as the ask, so it is not opened twice",
    /if \(form\.pinentryOffered\) \{\s*form\.vault\.pinentryAutoAsked = true\s*form\.submitCurrentMethod\(\)/.test(use), use)
  const opened = (service.match(/onOpenedChanged: \{[\s\S]*?\n  \}/) || [""])[0]
  check("a cancelled pinentry does not reopen when the panel comes back; a real close asks again next time",
    /\} else if \(!pinentryActive\) \{[\s\S]*pinentryAutoAsked = false/.test(opened)
      && !/if \(opened\) \{[^}]*pinentryAutoAsked = false/.test(opened), opened)
  check("an SSH unlock request that ends asks again for the next one",
    /onSshUnlockRequestChanged: \{\s*if \(sshUnlockRequest !== null \|\| pinentryActive\) return\s*pinentryAutoAsked = false\s*resetPinentryChoice\(\)/.test(service), "")
}
check("Enter on the locked screen opens pinentry",
  /status === "locked" && unlockForm\.pinentryOffered\) \{\s*unlockForm\.submitCurrentMethod\(\)/.test(read("Panel.qml")), "")
const confirm = read("RepromptConfirm.qml")
// Drawn and typed into: tests/qml-kit/tst_reprompt_confirm.qml.
check("the re-prompt question asks pinentry when it can, and shows its field only where the vault says",
  /usePinentry: vault\.typedSecretEntry === "pinentry"/.test(confirm)
    && /typesHere: vault\.typedSecretEntry === "field"/.test(confirm) && /visible: confirm\.typesHere\n/.test(confirm)
    && /vault\.submitRepromptWithPinentry\(\)/.test(confirm) && /id: passwordField/.test(confirm), "")

// --- settings -----------------------------------------------------------------------------------------

check("the setting defaults on and an override program is read from shell.json",
  Model.boolSetting("usePinentry", undefined) === true && Model.boolSetting("usePinentry", false) === false
    && /Model\.pinentryProgram\(setting\("pinentryProgram", ""\)\)/.test(service), "")

done()
