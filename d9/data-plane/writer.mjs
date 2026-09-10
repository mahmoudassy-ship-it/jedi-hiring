import fs from 'node:fs'
import { spawnSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import { assertImportPlan, serializeImportPlan } from './plan.mjs'
import { openDisposableCandidateDescriptor } from './candidate.mjs'
import { failD92 } from './errors.mjs'

const workerPath = fileURLToPath(new URL('./writer-worker.mjs', import.meta.url))
const syntheticFaults = new WeakSet()
const WRITER_REQUEST_BYTES_MAX = 65_536

export function createSyntheticWriterFault(code = 'after_all_rows') {
  if (!['after_all_rows', 'integrity_corruption', 'projection_extra_row'].includes(code)) failD92('WRITER_TEST_FAULT_INVALID', 'unknown synthetic writer fault')
  const fault = Object.freeze({ code })
  syntheticFaults.add(fault)
  return fault
}

export function applyImportPlanToCandidate({ candidate, plan, syntheticFault = undefined }) {
  assertImportPlan(plan)
  if (syntheticFault !== undefined && !syntheticFaults.has(syntheticFault)) failD92('WRITER_TEST_FAULT_INVALID', 'unbranded fault injection rejected')
  const descriptor = openDisposableCandidateDescriptor(candidate, { writable: true })
  try {
    const request = Buffer.from(JSON.stringify({
      plan_base64: serializeImportPlan(plan).toString('base64'),
      synthetic_fault_code: syntheticFault?.code ?? null,
    }), 'utf8')
    if (request.length > WRITER_REQUEST_BYTES_MAX) failD92('WRITER_REQUEST_TOO_LARGE', 'writer request exceeds the frozen IPC packet ceiling')
    const child = spawnSync(process.execPath, ['--disable-warning=ExperimentalWarning', workerPath], {
      encoding: 'utf8',
      env: syntheticFault ? { PATH: process.env.PATH ?? '', D9_SYNTHETIC_TEST_ONLY: '1' } : { PATH: process.env.PATH ?? '' },
      input: request,
      maxBuffer: 2 * 1024 * 1024,
      stdio: ['pipe', 'pipe', 'pipe', descriptor],
      timeout: 30_000,
    })
    let result
    try { result = JSON.parse(child.stdout || '{}') } catch (error) {
      failD92('WRITER_PROTOCOL_INVALID', 'writer returned malformed JSON', { cause: error })
    }
    if (child.error) failD92('WRITER_PROCESS_FAILED', 'fixed writer process could not execute', { cause: child.error })
    if (child.signal) failD92('WRITER_PROCESS_FAILED', `fixed writer terminated by ${child.signal}`)
    if (child.status !== 0 || result.outcome !== 'written') {
      failD92(result.error_code ?? 'WRITER_FAILED', result.message ?? child.stderr ?? 'fixed writer rejected the plan')
    }
    return Object.freeze(result)
  } finally {
    fs.closeSync(descriptor)
  }
}
