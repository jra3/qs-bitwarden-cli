import QtQuick
import Quickshell
import Quickshell.Io
import "FidoModel.js" as Fido
import "BitwardenModel.js" as Model

// Owns "unlock with FIDO2 key". A touch asks the key for the hmac-secret of
// Omarchy's existing pam-u2f credential, which opens the envelope's FIDO wrap
// (BitwardenModel.js), so unlocking needs the physical key. The vault only
// passes in the setting and takes back the password.
//
// The key is asked only when the user asks (startUnlock() from the unlock
// button), never because a screen appeared: a request left waiting on the
// key is answered by whatever touch comes next, including one meant for
// another prompt. A registration that asks for the key's PIN gets it from
// pinentry, under the vault helper, held by name and handed to the pipeline
// on its stdin; the shell never sees it.
Item {
  id: fido

  // No visuals; holds the key request, its processes and state.
  visible: false
  width: 0
  height: 0

  required property var vault
  // The fidoUnlock setting, pushed down by the vault.
  property bool armed: false

  // The last probe: which plugged-in key holds which registered credential.
  property var probe: Fido.parseFidoProbe("")
  // Tools installed, a credential registered, and a key holding a usable one
  // plugged in.
  property bool available: false
  // Any of those three present: worth drawing the option.
  property bool applicable: false
  // The legacy plaintext entry (account=fido_password), migrated by the first
  // touch that finds it.
  property bool legacyStored: false
  // Credentials the envelope has a FIDO wrap for.
  readonly property var envelopeCredentials: vault && vault.envelopeSummary
    && Array.isArray(vault.envelopeSummary.fido) ? vault.envelopeSummary.fido : []
  readonly property bool stored: legacyStored || envelopeCredentials.length > 0
  property bool scanning: false
  property bool authorized: false     // a live touch may consume one answer
  // Attempt progress, shown on the FIDO2 screen.
  property string message: ""
  // Why the last attempt failed; kept apart from `message` so it survives a
  // switch to another method.
  property string failure: ""

  // Setup form.
  property bool setupActive: false
  property string setupMaster: ""
  property string error: ""
  property bool busy: false
  property bool clearPending: false

  readonly property bool ready: armed && available && stored

  // "envelope" (a wrap exists) or "legacy" (migrating with the same touch).
  property string assertMode: ""
  property bool startAfterProbe: false

  // A key holds an abandoned request until its presence timeout; meanwhile
  // (~15 s on a YubiKey 5) new requests fail in <0.1 s with a misleading
  // error. A failure that fast, soon after abandoning one, is retried.
  property double abandonedAtMs: 0
  property double startedAtMs: 0
  property int busyRetries: 0
  readonly property int busyRetryMs: 2000
  // Outlasts the authenticator's presence timeout.
  readonly property int busyWindowMs: 40000
  // Faster than any real touch, so a failure inside it is the device refusing.
  readonly property int busyFailureMs: 1500
  readonly property int busyRetryLimit: 15
  // The key's own timeout for an unanswered request is ~28.6 s.
  readonly property int noTouchMs: 20000

  readonly property string touchMessage: "󰟵  Touch your FIDO2 key..."
  readonly property string busyMessage: "󰟵  Your key is finishing an earlier request -- touch it to clear it, or wait a moment..."

  // After a touch and a successful read; the vault decides what to do.
  signal unlocked(string password)

  // -------------------------------------------------------------------------
  // Readiness
  // -------------------------------------------------------------------------

  // The setting is usually true at construction, so onArmedChanged never
  // fires; probe now.
  Component.onCompleted: if (armed) refresh()

  function refresh() {
    // A probe would find the key busy with our own request.
    if (assertProc.running) return
    if (!probeProc.running) probeProc.running = true
  }

  function onProbe(raw) {
    var state = Fido.parseFidoProbe(raw)
    probe = state
    applicable = state.applicable
    available = state.ready
    if (available && armed) checkLegacy()
    if (startAfterProbe) {
      startAfterProbe = false
      if (scanning) launchAssert()
    }
  }

  // Which account the legacy check asked about; an answer for one no longer
  // active is dropped and asked again.
  property string hasSlot: ""
  property bool hasRecheck: false

  function checkLegacy() {
    if (hasProc.running) {
      hasRecheck = true
      return
    }
    hasRecheck = false
    hasSlot = vault ? vault.activeSlot : ""
    hasProc.running = true
  }

  function onHasChecked(raw) {
    if (vault && hasSlot !== vault.activeSlot) {
      if (armed) hasRecheck = true
      return
    }
    legacyStored = String(raw || "").trim() === "yes"
    // Readiness is all this changes: the key waits for the button.
  }

  // A credential with an envelope wrap on a plugged-in key; failing that,
  // while the legacy entry exists, any usable one (its touch migrates it).
  // `needsPin` follows the registration's options (+pin, +verification).
  function unlockTarget() {
    var usable = probe.usable || []
    for (var i = 0; i < usable.length; i++) {
      for (var j = 0; j < envelopeCredentials.length; j++) {
        var wrap = envelopeCredentials[j]
        if (wrap.cred === usable[i].cred) {
          return { mode: "envelope", device: usable[i].device, cred: wrap.cred, rp: wrap.rp, salt: wrap.salt,
            needsPin: usable[i].needsPin === true }
        }
      }
    }
    if (legacyStored && usable.length > 0 && probe.rp) {
      return { mode: "legacy", device: usable[0].device, cred: usable[0].cred, rp: probe.rp,
        needsPin: usable[0].needsPin === true }
    }
    return null
  }

  function unavailableReason() {
    if (!probe.usable || probe.usable.length === 0) return "No registered FIDO2 key is plugged in."
    return "This key is not set up for vault unlock. Set up FIDO2 unlock again."
  }

  // The key's PIN is typed into pinentry only: the panel's own field would
  // put it in the shell, and this unlock exists to keep secrets out of there.
  readonly property string pinUnavailableReason: "Your key's registration asks for its PIN, which is typed into "
    + "pinentry; pinentry is off, missing or waiting for the vault helper. Use your master password."

  // The held key PIN (Model.heldSecretRef()) across one attempt and its
  // busy retries; forgotten with the outcome.
  property string pinRef: ""

  function forgetPin() {
    if (pinRef && vault) vault.forgetHeldPassword(pinRef)
    pinRef = ""
  }

  // Asks for the key's PIN when the target needs it and none is held yet;
  // `then()` runs with pinRef set, or not at all (failure is shown).
  function withKeyPin(target, error, then) {
    if (!target.needsPin || pinRef) { then(); return }
    if (!vault.pinentryAvailable) {
      scanning = false
      message = ""
      failure = pinUnavailableReason
      return
    }
    message = "󰌋  Enter your key's PIN in pinentry..."
    vault.requestPinentry("fidoPin", error, function(r) {
      if (r.state === "ok") {
        pinRef = Model.heldSecretRef(r.name)
        if (scanning) then()
        else forgetPin()
        return
      }
      scanning = false
      message = ""
      failure = r.state === "cancelled" || r.state === "empty" || r.state === "short" ? ""
        : "Could not ask for your key's PIN. Use your master password."
    })
  }

  // -------------------------------------------------------------------------
  // Unlock
  // -------------------------------------------------------------------------

  function startUnlock() {
    if (!ready || !vault || vault.status !== "locked" || vault.isUnlocking) return
    if (!vault.quickUnlockAvailable || !vault.accountId) return
    // A request left by a closed panel is still waiting on the key: adopt it.
    if (assertProc.running) {
      scanning = true
      failure = ""
      if (message === "") message = touchMessage
      return
    }
    if (scanning) return
    authorized = false
    failure = ""
    scanning = true
    message = busyRetries > 0
      ? busyMessage
      : touchMessage
    // Re-probe first: a replugged key can move to another hidraw node.
    startAfterProbe = true
    if (!probeProc.running) probeProc.running = true
  }

  function launchAssert() {
    var target = unlockTarget()
    if (!target) {
      scanning = false
      message = ""
      failure = unavailableReason()
      return
    }
    withKeyPin(target, "", function() {
      if (!scanning || !vault || vault.status !== "locked") return
      message = busyRetries > 0 ? busyMessage : touchMessage
      assertMode = target.mode
      startedAtMs = Date.now()
      var tool = vault.envelopeTool()
      var account = vault.envelopeAccount()
      // The tool reads the account from the environment, not argv (this run is
      // outside Service's envelope queue, which sets it for the others).
      assertProc.environment = Model.envelopeAccountEnv(account)
      assertProc.command = target.mode === "envelope"
        ? Model.fidoUnlockCommand(tool, account, target)
        : Model.fidoLegacyUnlockCommand(tool, account, target)
      // The key's PIN, when needed, goes to the pipeline's stdin by name.
      var secrets = {}
      if (target.needsPin) secrets[Model.fidoPinEnvVar()] = pinRef
      assertProc.secrets = secrets
      // The password it prints stays in the vault helper (vault.heldOutput()).
      assertProc.capture = "secret:" + vault.newHeldName()
      assertProc.running = true
    })
  }

  // Leave the screen but keep the key's request running: stopping our side
  // would not free the key. A touch with no surface up is discarded; reopening
  // the panel just keeps waiting.
  function releaseSurface() {
    busyRetryTimer.stop()
    busyRetries = 0
    startAfterProbe = false
    if (!assertProc.running) {
      cancelUnlock()
      return
    }
    scanning = false
    authorized = false
    message = ""
  }

  function cancelUnlock() {
    busyRetryTimer.stop()
    startAfterProbe = false
    // Only an abandoned request leaves the key holding one.
    if (assertProc.running) {
      abandonedAtMs = Date.now()
      assertProc.running = false
    }
    scanning = false
    authorized = false
    forgetPin()
  }

  // Failed too fast to be an answer, soon after this panel abandoned a request.
  function deviceStillBusy() {
    var now = Date.now()
    return busyRetries < busyRetryLimit
      && (now - startedAtMs) < busyFailureMs
      && (now - abandonedAtMs) < busyWindowMs
  }

  function retryAfterBusy() {
    busyRetries += 1
    failure = ""
    message = busyMessage
    busyRetryTimer.restart()
  }

  function onAssertExited(exitCode) {
    if (vault && vault.finishScrubRun(assertProc)) return
    // Read, then scrubbed: on success this holds the password.
    var out = vault ? vault.heldOutput(assertProc, assertStdout.text) : ""
    if (vault) vault.clearProcessCollectorSoon(assertProc)
    var mode = assertMode
    assertMode = ""
    var accepting = scanning && vault && vault.sshAuthSurfaceActive && vault.status === "locked"
    scanning = false
    var codes = Model.fidoExitCodes()
    var migrated = exitCode === 0 && mode === "legacy"
    if (migrated) {
      // The legacy entry was migrated and deleted, even if nobody is looking.
      legacyStored = false
      if (vault) vault.refreshEnvelope()
    }
    if (!accepting) {
      if (vault) vault.forgetHeldPassword(out)
      out = ""
      return
    }

    if (exitCode === 0 || exitCode === codes.legacyUsed) {
      forgetPin()
      busyRetries = 0
      abandonedAtMs = 0
      authorized = false
      // The button shows "Unlocking..." by itself.
      message = "󰟵  Key verified"
      if (exitCode === codes.legacyUsed) {
        console.log("qs-bitwarden envelope: FIDO2 unlocked from the legacy entry; migration did not finish")
      }
      if (!out) {
        message = ""
        failure = "The key answered but no password came back. Use your master password."
        return
      }
      vault.fidoFromEnvelope = exitCode === 0
      unlocked(out)
      out = ""
      return
    }
    if (exitCode === codes.assert || exitCode === codes.noSecret) {
      if (deviceStillBusy()) {
        retryAfterBusy()
        return
      }
      var withPin = pinRef !== ""
      forgetPin()
      message = ""
      failure = (Date.now() - startedAtMs) > noTouchMs
        ? "No touch received. Touch your key again or use your master password."
        // A wrong PIN is refused by the key at once, and costs one of its
        // tries; the user has to know which it was.
        : (withPin ? "The key refused: a wrong PIN, or no touch. Each wrong PIN uses one of the key's tries."
          : "Key not recognised. Touch it again or use your master password.")
      return
    }
    forgetPin()
    if (exitCode === codes.noPin) {
      message = ""
      failure = pinUnavailableReason
      return
    }
    if (exitCode === Model.legacyMigrationExitCodes().none) {
      legacyStored = false
      message = ""
      failure = unavailableReason()
      return
    }
    message = ""
    failure = "Could not read the stored password. Use your master password."
    if (vault) vault.refreshEnvelope()
  }

  // -------------------------------------------------------------------------
  // Stored credentials
  // -------------------------------------------------------------------------

  // Processes whose output can hold the master password, for the lock scrub.
  function secretProcesses() { return [assertProc] }

  function dropSecrets() { setupMaster = ""; forgetPin() }

  // Clears the legacy entry, if any.
  function requestClear() {
    if (clearProc.running) {
      clearPending = true
      return
    }
    clearProc.running = true
  }

  // Remove every FIDO2 way in (envelope wraps and legacy entry). `notify`
  // false skips the confirmation.
  function forget(reasonMessage, notify) {
    cancelUnlock()
    var creds = envelopeCredentials.slice()
    for (var i = 0; i < creds.length; i++) {
      if (vault) vault.removeQuickUnlockMethod({ kind: "remove", method: "fido", cred: creds[i].cred })
    }
    legacyStored = false
    message = ""
    failure = String(reasonMessage === undefined || reasonMessage === null ? "" : reasonMessage)
    requestClear()
    if (notify !== false && vault) vault.flashNotification("FIDO2 unlock forgotten")
  }

  // State only: logout already cleared the keyring.
  function reset() {
    cancelUnlock()
    forgetPin()
    busyRetries = 0
    abandonedAtMs = 0
    legacyStored = false
    message = ""
    failure = ""
    setupActive = false
    busy = false
    setupMaster = ""
  }

  onArmedChanged: {
    if (!armed) {
      cancelUnlock()
      message = ""
      failure = ""
      // Unconditional, not `if (stored)`: that flag also goes false when the
      // key or packages are missing, and a way in may still be stored.
      if (!vault || !vault.started || !vault.accountsLoaded) {
        forget("")
        return
      }
      // Every account's keys and legacy copy, not only this account's: the
      // setting is shared (purgeQuickUnlockMethod() in Service.qml).
      legacyStored = false
      vault.purgeQuickUnlockMethod("fido")
      vault.flashNotification("FIDO2 unlock forgotten")
    } else {
      refresh()
    }
  }

  // -------------------------------------------------------------------------
  // Setup
  // -------------------------------------------------------------------------

  function beginSetup() {
    setupMaster = ""
    error = ""
    downgradeConfirmed = false
    setupActive = true
    // Probe even if the setting is off: the form needs to know whether a key
    // is registered.
    refresh()
    if (vault) vault.currentScreen = "fido"
  }

  // Omarchy's enrolment, in a floating terminal (it prompts for sudo and a touch).
  function runOmarchySetup() {
    Quickshell.execDetached(Fido.fidoSetupCommand())
    if (vault) vault.flashNotification("FIDO2 setup opened -- this screen updates itself")
  }

  function abandonSetup() {
    // A wrap still being written is removed when it lands (see submitSetup()).
    if (busy && vault) vault.invalidateEpochOperation("fidoAdd")
    setupActive = false
    busy = false
    setupMaster = ""
  }

  // The typed master password is checked against the stored one; one touch
  // adds this key's wrap. Nothing typed is stored.
  function submitSetup() {
    if (busy || !vault) return
    if (!vault.quickUnlockAvailable) {
      error = vault.quickUnlockUnavailableReason
      return
    }
    if (!setupMaster) {
      error = "Confirm your master password to enable FIDO2 unlock"
      return
    }
    var usable = probe.usable || []
    if (usable.length === 0 || !probe.rp) {
      error = unavailableReason()
      return
    }
    // A weaker method already in the envelope makes the key pointless; the
    // form says so and asks for a second press (quickUnlockDowngradeWarning()).
    if (vault.fidoDowngradeWarning && !downgradeConfirmed) {
      downgradeConfirmed = true
      error = Model.downgradeConfirmText(vault.fidoDowngradeWarning)
      return
    }
    var target = { device: usable[0].device, cred: usable[0].cred, rp: probe.rp,
      needsPin: usable[0].needsPin === true }
    if (target.needsPin && !vault.pinentryAvailable) {
      error = pinUnavailableReason
      return
    }
    var typed = setupMaster
    setupMaster = ""
    error = ""
    busy = true
    setupActive = true
    if (!target.needsPin) {
      enroll(typed, target, null)
      return
    }
    // The key's PIN first, so the touch prompt follows it as on unlock.
    message = "󰌋  Enter your key's PIN in pinentry..."
    vault.requestPinentry("fidoPin", "", function(r) {
      if (r.state !== "ok" || !setupActive || !busy) {
        if (r.state === "ok") vault.forgetVaultSecret(r.name)
        typed = ""
        busy = false
        message = ""
        if (setupActive && r.state !== "cancelled" && r.state !== "empty" && r.state !== "short") {
          error = "Could not ask for your key's PIN."
        }
        return
      }
      var extra = {}
      extra[Model.fidoPinEnvVar()] = Model.heldSecretRef(r.name)
      enroll(typed, target, extra)
      typed = ""
    })
  }

  property bool downgradeConfirmed: false

  // The typed master password checked against the stored one, one touch
  // adding this key's wrap; `extra` carries the held key PIN when needed.
  function enroll(typed, target, extra) {
    message = "󰟵  Touch your FIDO2 key to finish..."
    startedAtMs = Date.now()
    vault.beginEpochOperation("fidoAdd")
    vault.addQuickUnlockMethodWith(typed, function(tool, account) {
      return Model.fidoEnrollCommand(tool, account, target)
    }, extra, function(ok, why, code) {
      if (extra) for (var k in extra) vault.forgetHeldPassword(extra[k])
      typed = ""
      busy = false
      message = ""
      // Stale by the time it landed: remove the wrap again.
      if (vault.epochOperationIsStale("fidoAdd") || !setupActive) {
        setupActive = false
        if (ok) vault.removeQuickUnlockMethod({ kind: "remove", method: "fido", cred: target.cred })
        return
      }
      setupActive = false
      if (!ok) {
        var codes = Model.fidoExitCodes()
        if (why === "wrong-password" || why === "stale") error = vault.quickUnlockErrorText(why, "")
        else if (code === codes.assert || code === codes.noSecret) {
          error = target.needsPin ? "The key refused: a wrong PIN, or no touch. Try again."
            : "No touch received. Try again."
        } else if (code === codes.noPin) error = pinUnavailableReason
        else error = "Could not enable FIDO2 unlock. Is the OS keyring available?"
        setupActive = true
        return
      }
      vault.noteQuickUnlockEnabled("fido")
      // Supersedes any legacy entry.
      legacyStored = false
      requestClear()
      vault.writeSetting("fidoUnlock", true, "bool")
      vault.flashNotification("FIDO2 unlock enabled")
      vault.currentScreen = "settings"
    })
  }

  // -------------------------------------------------------------------------

  Process {
    id: probeProc
    command: Fido.fidoProbeCommand()
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: fido.onProbe(text)
    }
  }

  Process {
    id: hasProc
    command: Model.keyringHasFidoPasswordCommand(fido.vault ? fido.vault.activeSlot : "")
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: fido.onHasChecked(text)
    }
  }

  // One touch; the password is the only output. See Model.fidoUnlockCommand().
  VaultProcess {
    id: assertProc
    vault: fido.vault
    session: false
    stdout: VaultCollector {
      id: assertStdout
      waitForEnd: true
    }
    onExited: function(exitCode) { fido.onAssertExited(exitCode) }
  }

  Process {
    id: clearProc
    command: Model.keyringClearFidoPasswordCommand(fido.vault ? fido.vault.activeSlot : "")
    onExited: function(exitCode) {
      if (fido.clearPending) {
        fido.clearPending = false
        clearProc.running = true
      }
    }
  }

  // Asks the legacy check again once its process is free (the Process can
  // still read as running inside its own exit handler).
  Timer {
    id: hasRecheckTimer
    interval: 150
    repeat: true
    running: fido.hasRecheck
    onTriggered: fido.checkLegacy()
  }

  // Retry after the key had a moment, only while the conditions still hold.
  Timer {
    id: busyRetryTimer
    interval: fido.busyRetryMs
    repeat: false
    onTriggered: {
      if (!fido.ready || !fido.vault || fido.vault.status !== "locked"
          || !fido.vault.sshAuthSurfaceActive) {
        fido.busyRetries = 0
        return
      }
      fido.startUnlock()
    }
  }
}
