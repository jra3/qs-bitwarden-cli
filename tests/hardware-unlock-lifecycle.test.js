#!/usr/bin/env node
// Execute the production PAM/FIDO lifecycle functions. Only the physical
// device boundary is simulated; this is not a claim of real hardware coverage.
const { read, loadModule, functionBody, createSuite } = require('./harness')
const { eq, check, done } = createSuite('hardware-unlock-lifecycle')
const Model = loadModule()
const bind = (scope, file, names) => {
  for (const name of names) scope[name] = new Function('scope', 'with(scope){' + functionBody(read(file), name)
    + '\nreturn ' + name + '}')(scope)
}
function fingerprint() {
  const v = { Model, PamResult: { Success: 0, MaxTries: 1 }, fingerprintReady: true, status: 'locked',
    isUnlocking: false, fingerprintScanning: false, fingerprintAuthorized: false, sshAuthSurfaceActive: true,
    userName: 'synthetic-user', errorMessage: '', fingerprintError: '', fingerprintMessage: '',
    quickUnlockAvailable: true, accountId: 'synthetic-id', envelopeSummary: { fingerprint: true }, opens: 0,
    fidoUnlocker: { releases: 0, releaseSurface() { this.releases++ } },
    fingerprintPam: { active: false, starts: 0, aborts: 0, succeeds: true,
      start() { this.starts++; this.active = this.succeeds; return this.succeeds }, abort() { this.aborts++; this.active = false } },
    keyringLookupMasterProc: { running: false }, activeSlot: 'default', newHeldName() { return 'fixture' },
    openEnvelopeForFingerprint() { this.opens++ } }
  bind(v, 'Service.qml', ['startFingerprintUnlock', 'cancelFingerprintUnlock', 'onFingerprintResult'])
  return v
}
for (const blocked of ['unavailable', 'unlocked', 'unlocking']) {
  const v = fingerprint()
  if (blocked === 'unavailable') v.fingerprintReady = false
  if (blocked === 'unlocked') v.status = 'unlocked'
  if (blocked === 'unlocking') v.isUnlocking = true
  v.startFingerprintUnlock(); eq(blocked + ' never starts PAM', v.fingerprintPam.starts, 0)
}
{
  const v = fingerprint(); v.startFingerprintUnlock(); v.startFingerprintUnlock()
  eq('one PAM request while scanning', v.fingerprintPam.starts, 1)
  eq('fingerprint releases an outstanding FIDO surface', v.fidoUnlocker.releases, 1)
  v.onFingerprintResult(v.PamResult.Success)
  eq('success opens the fingerprint envelope once', v.opens, 1)
  eq('success is authorized', v.fingerprintAuthorized, true)
}
for (const result of [1, 2]) {
  const v = fingerprint(); v.startFingerprintUnlock(); v.onFingerprintResult(result)
  eq('PAM failure ' + result + ' never reads an envelope', v.opens, 0)
  check('PAM failure ' + result + ' has a useful error', v.fingerprintError.length > 0, '')
  eq('PAM failure ' + result + ' remains unauthorized', v.fingerprintAuthorized, false)
}
for (const abandoned of ['cancel', 'closed', 'locked elsewhere']) {
  const v = fingerprint(); v.startFingerprintUnlock()
  if (abandoned === 'cancel') v.cancelFingerprintUnlock()
  if (abandoned === 'closed') v.sshAuthSurfaceActive = false
  if (abandoned === 'locked elsewhere') v.status = 'unlocked'
  v.onFingerprintResult(v.PamResult.Success)
  eq(abandoned + ': late PAM success never reads a password', v.opens, 0)
  eq(abandoned + ': late PAM success is unauthorized', v.fingerprintAuthorized, false)
}
{
  const v = fingerprint(); v.fingerprintPam.succeeds = false; v.startFingerprintUnlock()
  eq('PAM startup failure stops scanning', v.fingerprintScanning, false)
  check('PAM startup failure is reported', v.fingerprintError.length > 0, '')
}
function fido() {
  const f = { Model, ready: true, vault: { status: 'locked', isUnlocking: false, quickUnlockAvailable: true,
      accountId: 'synthetic-id', sshAuthSurfaceActive: true, forgotten: [],
      finishScrubRun() { return false }, heldOutput() { return Model.heldSecretRef('device-answer') },
      clearProcessCollectorSoon() {}, forgetHeldPassword(v) { this.forgotten.push(v) },
      refreshEnvelope() {}, newHeldName() { return 'fixture' },
      envelopeTool() { return '/synthetic/tool' }, envelopeAccount() { return { id: 'synthetic-id', server: 'https://synthetic.invalid' } } },
    scanning: false, authorized: false, failure: '', message: '', busyRetries: 0, startAfterProbe: false,
    startedAtMs: 0, abandonedAtMs: 0, busyRetryLimit: 15, busyFailureMs: 1500, busyWindowMs: 40000,
    noTouchMs: 20000, touchMessage: 'Touch', busyMessage: 'Busy', assertMode: 'envelope',
    assertProc: { running: false }, probeProc: { running: false }, assertStdout: { text: '' },
    busyRetryTimer: { restarts: 0, restart() { this.restarts++ }, stop() {} },
    legacyStored: false, target: null, unavailableReason() { return 'No usable key' },
    pinRef: '', pinUnavailableReason: 'PIN needs pinentry',
    unlockTarget() { return this.target }, answers: [], unlocked(value) { this.answers.push(value) } }
  // The key's PIN, when the registration asks for it, comes from pinentry.
  f.vault.pinentryAvailable = true
  f.vault.pinentryAsks = []
  f.vault.pinentryAnswer = { state: 'ok', name: 'keypin' }
  f.vault.requestPinentry = function(purpose, error, done) { this.pinentryAsks.push(purpose); done(this.pinentryAnswer) }
  bind(f, 'FidoUnlock.qml', ['startUnlock', 'launchAssert', 'releaseSurface', 'cancelUnlock',
    'deviceStillBusy', 'retryAfterBusy', 'onAssertExited', 'forgetPin', 'withKeyPin'])
  return f
}
const touchOnly = { mode: 'envelope', device: '/dev/hidraw1', cred: 'QUJD', rp: 'pam://h', salt: 'QUJD', needsPin: false }
const withPin = Object.assign({}, touchOnly, { needsPin: true })
{
  const f = fido(); f.target = touchOnly; f.scanning = true; f.launchAssert()
  eq('a touch-only registration asks pinentry for nothing', f.vault.pinentryAsks.length, 0)
  eq('and runs the assertion with an empty secrets block', JSON.stringify(f.assertProc.secrets), '{}')
  eq('which the device is asked for', f.assertProc.running, true)
}
{
  const f = fido(); f.target = withPin; f.scanning = true; f.launchAssert()
  eq('a PIN registration asks pinentry for the key PIN first', f.vault.pinentryAsks.join(), 'fidoPin')
  eq('the held PIN goes to the pipeline by name, on its stdin',
    f.assertProc.secrets && f.assertProc.secrets[Model.fidoPinEnvVar()], Model.heldSecretRef('keypin'))
  eq('and the device is then asked', f.assertProc.running, true)
  f.onAssertExited(0)
  eq('a success forgets the held PIN', f.vault.forgotten.includes(Model.heldSecretRef('keypin')), true)
  eq('and unlocks', f.answers.length, 1)
}
{
  const f = fido(); f.target = withPin; f.scanning = true; f.vault.pinentryAnswer = { state: 'cancelled', name: 'x' }
  f.launchAssert()
  eq('a cancelled PIN prompt asks the device for nothing', f.assertProc.running, false)
  eq('stops scanning', f.scanning, false)
  eq('and is not an error', f.failure, '')
}
{
  const f = fido(); f.target = withPin; f.scanning = true; f.vault.pinentryAvailable = false
  f.launchAssert()
  eq('without pinentry the PIN is not collected anywhere', f.vault.pinentryAsks.length, 0)
  eq('the device is not asked', f.assertProc.running, false)
  eq('and the reason is shown', f.failure, 'PIN needs pinentry')
}
{
  const f = fido(); f.target = withPin; f.scanning = true; f.launchAssert()
  f.startedAtMs = Date.now()
  f.onAssertExited(Model.fidoExitCodes().assert)
  check('a refusal with a PIN in hand names the wrong PIN and its cost', /wrong PIN/.test(f.failure) && /tries/.test(f.failure), f.failure)
  eq('and forgets the PIN', f.vault.forgotten.includes(Model.heldSecretRef('keypin')), true)
  const g = fido(); g.target = withPin; g.scanning = true; g.launchAssert(); g.cancelUnlock()
  eq('cancelling forgets a held PIN too', g.vault.forgotten.includes(Model.heldSecretRef('keypin')), true)
}
{
  const f = fido(); f.startUnlock()
  eq('FIDO re-probes before signing after a replug', f.probeProc.running, true)
  eq('no assertion before the fresh probe', f.assertProc.running, false)
  f.launchAssert(); eq('missing key stops scanning', f.scanning, false)
  check('missing key is reported', f.failure.length > 0, '')
}
{
  const f = fido(); f.assertProc.running = true; f.scanning = true
  f.releaseSurface(); eq('closing retains the pending physical request', f.assertProc.running, true)
  eq('closing revokes its acceptance', f.scanning, false)
  f.onAssertExited(0); eq('late FIDO answer never unlocks', f.answers.length, 0)
  eq('late FIDO answer is forgotten', f.vault.forgotten.length, 1)
}
{
  const f = fido(); f.assertProc.running = true; f.startUnlock()
  eq('returning adopts the existing request', f.scanning, true)
  eq('returning does not start another probe', f.probeProc.running, false)
  f.onAssertExited(0); eq('an adopted successful request unlocks once', f.answers.length, 1)
}
{
  const f = fido(); f.scanning = true; f.assertProc.running = true; f.cancelUnlock()
  eq('cancelling stops assertion', f.assertProc.running, false)
  check('cancelling records the abandoned request', f.abandonedAtMs > 0, '')
  f.onAssertExited(0); eq('cancelled FIDO answer is discarded', f.answers.length, 0)
}
{
  const f = fido(); f.scanning = true; f.startedAtMs = Date.now(); f.abandonedAtMs = Date.now()
  f.onAssertExited(Model.fidoExitCodes().assert)
  eq('a busy device schedules retry', f.busyRetryTimer.restarts, 1)
  eq('busy retry is counted', f.busyRetries, 1)
  f.scanning = true; f.busyRetries = f.busyRetryLimit; f.onAssertExited(Model.fidoExitCodes().assert)
  eq('busy retries are bounded', f.busyRetryTimer.restarts, 1)
  check('exhausted retry reports a failure', f.failure.length > 0, '')
}
{
  const f = fido(); f.scanning = true; f.startedAtMs = Date.now() - 30000
  f.onAssertExited(Model.fidoExitCodes().assert)
  check('no touch has a specific error', f.failure.includes('No touch'), '')
  eq('no touch never unlocks', f.answers.length, 0)
}
done()
