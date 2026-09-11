import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { spawn, spawnSync } from 'node:child_process'
import { once } from 'node:events'
import { sha256Bytes } from '../control-plane/canonical.mjs'
import { assertD931AdmissionResolver } from './admission.mjs'
import { assertD931CustodyAdapterResult } from './adapter.mjs'
import { canonicalRecord, validateD930Record } from './contracts.mjs'
import { persistSupportingRecord } from './coordinator.mjs'
import { failD931 } from './errors.mjs'
import { assertProtectedJournalBroker } from './journal.mjs'

const source = fileURLToPath(new URL('./native/d9_integrity_relay.c', import.meta.url))
const relays = new WeakSet()
const lifecycleResults = new WeakSet()
const runtimeBuilds = new WeakSet()
const grantSinks = new WeakSet()
const custodyDescriptorResults = new WeakMap()
const registeredAdapterResults = new WeakSet()

export function createOneShotIntegrityGrantSink() {
  const sink = Object.freeze({})
  grantSinks.add(sink)
  return sink
}

export function assertOneShotIntegrityGrantSink(value) {
  if (!grantSinks.has(value)) failD931('D931_CUSTODY_DESCRIPTOR_UNAVAILABLE', 'integrity-only descriptor sink is not trusted')
  return value
}

export function registerOneShotCustodyDescriptor({ grantSink, adapterResult, descriptor, lifecycleContext }) {
  assertD931CustodyAdapterResult(adapterResult)
  if (!grantSinks.has(grantSink) || registeredAdapterResults.has(adapterResult) || custodyDescriptorResults.has(adapterResult) || adapterResult.response.operation_code !== 'open_custody' || adapterResult.response.payload.outcome_code !== 'available' || !Number.isInteger(descriptor) || descriptor < 0 || !Object.isFrozen(lifecycleContext)) failD931('D931_CUSTODY_DESCRIPTOR_UNAVAILABLE', 'integrity-only descriptor registration is invalid')
  registeredAdapterResults.add(adapterResult)
  custodyDescriptorResults.set(adapterResult, { consumed: false, descriptor, lifecycleContext, grantSink })
}

export function revokeOneShotCustodyDescriptor({ grantSink, adapterResult }) {
  if (!grantSinks.has(grantSink)) failD931('D931_CUSTODY_DESCRIPTOR_UNAVAILABLE', 'integrity-only descriptor authority is invalid')
  const state = custodyDescriptorResults.get(adapterResult)
  if (state && state.grantSink !== grantSink) failD931('D931_CUSTODY_DESCRIPTOR_UNAVAILABLE', 'integrity-only descriptor belongs to another grant sink')
  if (!state || state.consumed) return false
  state.consumed = true
  custodyDescriptorResults.delete(adapterResult)
  fs.closeSync(state.descriptor)
  return true
}

function takeOneShotCustodyDescriptor({ grantSink, adapterResult }) {
  if (!grantSinks.has(grantSink)) failD931('D931_CUSTODY_DESCRIPTOR_UNAVAILABLE', 'integrity-only descriptor authority is invalid')
  const state = custodyDescriptorResults.get(adapterResult)
  if (!state || state.grantSink !== grantSink || state.consumed || adapterResult.response.operation_code !== 'open_custody' || adapterResult.response.payload.outcome_code !== 'available') failD931('D931_CUSTODY_DESCRIPTOR_UNAVAILABLE', 'one-shot adapter descriptor does not match the exact sink and open exchange')
  state.consumed = true
  custodyDescriptorResults.delete(adapterResult)
  return Object.freeze({ descriptor: state.descriptor, lifecycleContext: state.lifecycleContext })
}

export function compileOneShotIntegrityRuntime() {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'jedi-d931-integrity-'))
  const executable = path.join(directory, 'integrity-relay')
  const result = spawnSync('/usr/bin/cc', ['-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-pedantic', source, '-o', executable, '-lcrypto'], { encoding: 'utf8', env: { LANG: 'C', LC_ALL: 'C', PATH: '/usr/bin:/bin' }, shell: false })
  if (result.error || result.status !== 0) { fs.rmSync(directory, { force: true, recursive: true }); failD931('D931_INTEGRITY_PLATFORM_UNAVAILABLE', result.stderr || result.error?.message || 'compile failed') }
  fs.chmodSync(executable, 0o500)
  const build = Object.freeze({ directory, executable, sha256: sha256Bytes(fs.readFileSync(executable)), dispose() { if (runtimeBuilds.delete(build)) fs.rmSync(directory, { force: true, recursive: true }) } })
  runtimeBuilds.add(build)
  return build
}

function lines(child) {
  let buffer = ''
  const queue = []
  const waiters = []
  child.stdout.setEncoding('utf8')
  child.stdout.on('data', (chunk) => {
    buffer += chunk
    for (;;) {
      const index = buffer.indexOf('\n')
      if (index < 0) break
      const line = JSON.parse(buffer.slice(0, index))
      buffer = buffer.slice(index + 1)
      const waiter = waiters.shift()
      if (waiter) waiter(line); else queue.push(line)
    }
  })
  return () => queue.length ? Promise.resolve(queue.shift()) : new Promise((resolve) => waiters.push(resolve))
}

async function boundedLine(next, child, timeoutMs) {
  let timer
  try {
    return await Promise.race([
      next(),
      new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('D931_INTEGRITY_TIMEOUT')), timeoutMs) }),
      once(child, 'exit').then(([code, signal]) => { throw new Error(`D931_INTEGRITY_PROCESS_DIED:${code ?? signal}`) }),
    ])
  } finally {
    clearTimeout(timer)
  }
}

async function terminateChild(child) {
  if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL')
  if (child.exitCode === null && child.signalCode === null) await once(child, 'exit').catch(() => {})
}

function lifecycleBase(context, processRecord, eventAt) {
  return {
    format: 'jedi-atlas-integrity-access-lifecycle-record', format_version: '1.0.0', record_kind_code: null, record_code: null,
    operation_id: context.operationId, operation_nonce: context.operationNonce, bundle: context.bundle,
    artifact: context.artifact, copy_code: context.copyCode, backend_code: 'pilot_local_cas_v1', backend_reference: context.backendReference,
    purpose_code: 'integrity', runtime_profile_record_digest_sha256: context.runtimeProfileDigest,
    identity_bindings_record_digest_sha256: context.identityBindingsDigest,
    d930_operational_profile_record_digest_sha256: context.custodyProfileDigest,
    open_custody_request_record_digest_sha256: context.openRequestDigest,
    open_custody_response_record_digest_sha256: context.openResponseDigest,
    sealed_capability_record_digest_sha256: context.sealedCapabilityDigest,
    sealed_capability_consumed_transition_digest_sha256: context.sealedCapabilityTransitionDigest,
    producer_binding_code: null, sender_binding_code: context.importerBindingCode, receiver_binding_code: context.verifierBindingCode,
    verifier_binding_code: context.verifierBindingCode, verifier_executable_sha256: context.verifierExecutableSha256,
    receiver_process: processRecord, descriptor_delivery_record_digest_sha256: null, verifier_result_record_digest_sha256: null,
    transport_code: null, descriptor_role_code: null, access_code: null, file_type_code: null, peer_credentials_verified: null,
    pidfd_supervision_active: null, verification_outcome_code: null, recomputed_artifact: null, sender_close_state_code: null,
    sender_closed_at: null, receiver_termination_state_code: null, receiver_terminated_at: null, termination_disposition_code: null,
    receiver_descriptor_closed_by_termination: null, lifecycle_outcome_code: null, event_at: eventAt, record_digest_sha256: null,
  }
}

export function createOneShotIntegrityRelay({ admissionResolver, journalBroker, journalPeerProvider, contractSet, bindingRoleResolver, journalBindingCode, journalProfileDigest, launcherBindingCode, clock, runtimeBuild, grantSink, timeoutMs = 5_000, faultInjector = null }) {
  assertD931AdmissionResolver(admissionResolver)
  assertProtectedJournalBroker(journalBroker)
  if (!runtimeBuilds.has(runtimeBuild) || !grantSinks.has(grantSink)) failD931('D931_INTEGRITY_BUILD_UNTRUSTED', 'integrity relay build or descriptor sink is not trusted')
  const build = runtimeBuild
  let disposed = false
  let recoveryRequired = false
  const relay = Object.freeze({
    executableSha256: build.sha256,
    async verify(context) {
      if (disposed || !relays.has(relay)) failD931('D931_INTEGRITY_RELAY_CLOSED', 'integrity relay is closed')
      if (recoveryRequired) failD931('D931_INTEGRITY_RECOVERY_REQUIRED', 'integrity relay has an incomplete protected lifecycle')
      if (context.purposeCode !== 'integrity' || context.processingAccessRequested === true || typeof journalPeerProvider !== 'function') failD931('D931_PROCESSING_ACCESS_FORBIDDEN', 'integrity relay never grants processing access and requires authenticated journal IPC')
      const verifierBinding = admissionResolver.resolveBinding(context.verifierBindingCode)
      const verificationStartedAt = clock('integrity_verification_started')
      if (verifierBinding.runtime_role_code !== 'independent_verifier' || verifierBinding.principal_kind_code !== 'service' || verifierBinding.unix_uid === 0 || verifierBinding.executable_sha256 !== build.sha256 || !(verifierBinding.valid_from <= verificationStartedAt && verificationStartedAt < verifierBinding.valid_until)) failD931('D931_INTEGRITY_BUILD_MISMATCH', 'verified active non-root verifier binding does not pin the running relay build')
      const executableDescriptor = fs.openSync(build.executable, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_CLOEXEC)
      try {
        const executableBefore = fs.fstatSync(executableDescriptor, { bigint: true })
        const executableBytes = fs.readFileSync(executableDescriptor)
        const executableAfter = fs.fstatSync(executableDescriptor, { bigint: true })
        if (!executableBefore.isFile() || executableBefore.nlink !== 1n || (executableBefore.mode & 0o277n) !== 0n || ['dev', 'ino', 'size', 'mtimeNs', 'ctimeNs'].some((key) => executableBefore[key] !== executableAfter[key]) || sha256Bytes(executableBytes) !== build.sha256) {
          failD931('D931_INTEGRITY_BUILD_MISMATCH', 'opened integrity executable differs from its verified build')
        }
      } catch (error) {
        fs.closeSync(executableDescriptor)
        throw error
      }
      let grant
      try { grant = takeOneShotCustodyDescriptor({ grantSink, adapterResult: context.adapterOpenResult }) } catch (error) { fs.closeSync(executableDescriptor); throw error }
      const bound = grant.lifecycleContext
      const descriptor = grant.descriptor
      const lifecycleContext = { ...bound, verifierBindingCode: verifierBinding.binding_code, verifierExecutableSha256: build.sha256, journalCode: `journal.${bound.operationId}` }
      let child
      try {
        child = spawn('/proc/self/fd/4', [String(bound.artifact.byte_length), String(verifierBinding.unix_uid), String(verifierBinding.unix_uid)], { env: { LANG: 'C', LC_ALL: 'C', PATH: '/usr/bin:/bin' }, shell: false, stdio: ['pipe', 'pipe', 'pipe', descriptor, executableDescriptor] })
      } catch (error) {
        recoveryRequired = true
        throw error
      } finally {
        fs.closeSync(descriptor)
        fs.closeSync(executableDescriptor)
      }
      const next = lines(child)
      try {
      let deliveryEvent
      try { deliveryEvent = await boundedLine(next, child, timeoutMs) } catch (error) { failD931('D931_INTEGRITY_RECOVERY_REQUIRED', error.message) }
      if (deliveryEvent.event !== 'descriptor_delivered' || deliveryEvent.peer_credentials_verified !== true || deliveryEvent.pidfd_supervision_active !== true) failD931('D931_INTEGRITY_PEER_REJECTED', 'native relay did not establish kernel peer guarantees')
      const processRecord = { process_instance_code: `process.integrity.${bound.operationId}`, pid: deliveryEvent.pid, uid: deliveryEvent.uid, gid: deliveryEvent.gid, start_time_ticks: deliveryEvent.start_time_ticks, executable_device: deliveryEvent.executable_device, executable_inode: deliveryEvent.executable_inode }
      let delivery = lifecycleBase(lifecycleContext, processRecord, clock('integrity_delivery'))
      Object.assign(delivery, { record_kind_code: 'descriptor_delivery', record_code: `integrity.delivery.${bound.operationId}`, producer_binding_code: launcherBindingCode, transport_code: 'launcher_supervised_scm_rights', descriptor_role_code: 'custody_source', access_code: 'read_only', file_type_code: 'regular_file', peer_credentials_verified: true, pidfd_supervision_active: true })
      delivery = canonicalRecord(delivery)
      validateD930Record({ contractSet, record: delivery, bindingRoleResolver })
      const deliveryAck = await persistSupportingRecord({ journalPeerProvider, journalBroker, record: delivery, kindCode: 'integrity_access_lifecycle_record', journalCode: lifecycleContext.journalCode, journalBindingCode, journalProfileDigest, createdAt: clock('integrity_delivery_request') })

      let verifierEvent
      try { verifierEvent = await boundedLine(next, child, timeoutMs) } catch (error) { failD931('D931_INTEGRITY_RECOVERY_REQUIRED', error.message) }
      const passed = verifierEvent.event === 'verifier_result' && verifierEvent.descriptor_alias_count === 1 && verifierEvent.sha256 === bound.artifact.sha256 && verifierEvent.byte_length === bound.artifact.byte_length
      let verifier = lifecycleBase(lifecycleContext, processRecord, clock('integrity_result'))
      Object.assign(verifier, { record_kind_code: 'verifier_result', record_code: `integrity.result.${bound.operationId}`, producer_binding_code: verifierBinding.binding_code, descriptor_delivery_record_digest_sha256: delivery.record_digest_sha256, verification_outcome_code: passed ? 'passed' : 'identity_mismatch', recomputed_artifact: passed ? bound.artifact : null })
      verifier = canonicalRecord(verifier)
      validateD930Record({ contractSet, record: verifier, bindingRoleResolver })
      const verifierAck = await persistSupportingRecord({ journalPeerProvider, journalBroker, record: verifier, kindCode: 'integrity_access_lifecycle_record', journalCode: lifecycleContext.journalCode, journalBindingCode, journalProfileDigest, createdAt: clock('integrity_result_request') })
      try { faultInjector?.('after_verifier_result_persist_before_receiver_termination') } catch (error) { failD931('D931_INTEGRITY_RECOVERY_REQUIRED', error.message) }
      child.stdin.write('A')
      child.stdin.end()
      let terminalEvent
      try { terminalEvent = await boundedLine(next, child, timeoutMs) } catch (error) { failD931('D931_INTEGRITY_RECOVERY_REQUIRED', error.message) }
      const exitCode = child.exitCode ?? (await once(child, 'exit'))[0]
      const terminated = terminalEvent.event === 'receiver_terminated' && terminalEvent.receiver_descriptor_closed === true && exitCode === 0
      let terminal = lifecycleBase(lifecycleContext, processRecord, clock('integrity_terminal'))
      Object.assign(terminal, { record_kind_code: 'access_closed_and_receiver_terminated', record_code: `integrity.terminal.${bound.operationId}`, producer_binding_code: launcherBindingCode, descriptor_delivery_record_digest_sha256: delivery.record_digest_sha256, verifier_result_record_digest_sha256: verifier.record_digest_sha256, sender_close_state_code: 'confirmed', sender_closed_at: delivery.event_at, receiver_termination_state_code: terminated ? 'confirmed' : 'unknown', receiver_terminated_at: terminal.event_at, termination_disposition_code: terminated ? terminalEvent.status : 'unknown', receiver_descriptor_closed_by_termination: terminated, lifecycle_outcome_code: passed && terminated ? 'completed_verified' : 'recovery_required' })
      terminal = canonicalRecord(terminal)
      validateD930Record({ contractSet, record: terminal, bindingRoleResolver })
      const terminalAck = await persistSupportingRecord({ journalPeerProvider, journalBroker, record: terminal, kindCode: 'integrity_access_lifecycle_record', journalCode: lifecycleContext.journalCode, journalBindingCode, journalProfileDigest, createdAt: clock('integrity_terminal_request') })
      const result = Object.freeze({ delivery, deliveryAck, verifier, verifierAck, terminal, terminalAck, descriptorFreeCoordinatorRequired: true, processingAccessGranted: false })
      lifecycleResults.add(result)
      if (terminal.lifecycle_outcome_code !== 'completed_verified') recoveryRequired = true
      return result
      } catch (error) {
        recoveryRequired = true
        await terminateChild(child)
        throw error
      }
    },
    dispose() { if (!disposed) { disposed = true; relays.delete(relay) } },
  })
  relays.add(relay)
  return relay
}

export function assertCompletedIntegrityLifecycle(value) {
  if (!lifecycleResults.has(value) || value.terminal.lifecycle_outcome_code !== 'completed_verified' || value.processingAccessGranted !== false) failD931('D931_INTEGRITY_LIFECYCLE_INCOMPLETE', 'integrity lifecycle is not complete')
  return value
}
