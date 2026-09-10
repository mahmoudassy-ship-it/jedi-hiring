import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import test, { after, before } from 'node:test'
import { canonicalSha256 } from '../d9/control-plane/canonical.mjs'
import {
  compileReviewedManifestReader,
  D9_EVIDENCE_MANIFEST_BYTES_MAX,
  openApprovedEvidenceManifest,
  parseApprovedEvidenceManifest,
} from '../d9/data-plane/manifest.mjs'

let reader
const frozenGolden = JSON.parse(fs.readFileSync(new URL('../docs/schema/d9-0/fixtures/golden-vectors-v1.json', import.meta.url), 'utf8'))

before(() => {
  reader = compileReviewedManifestReader()
})

after(() => {
  reader?.dispose()
})

function temporaryRoot(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'jedi-d9-2-manifest-'))
  t.after(() => fs.rmSync(root, { force: true, recursive: true }))
  fs.mkdirSync(path.join(root, 'manifests'))
  return root
}

function rootDescriptor(t, root) {
  const descriptor = fs.openSync(
    root,
    fs.constants.O_RDONLY | fs.constants.O_DIRECTORY | fs.constants.O_NOFOLLOW | (fs.constants.O_CLOEXEC ?? 0),
  )
  t.after(() => fs.closeSync(descriptor))
  return descriptor
}

function bootstrapManifest(manifestPath = 'manifests/synthetic-bootstrap.json') {
  const manifest = {
    format: 'jedi-atlas-evidence-bundle',
    format_version: '1.0.0',
    bundle_id: 'synthetic.bootstrap-bundle',
    bundle_sequence: 1,
    required_bundles: [],
    bundle_created_at: '2030-01-01T00:06:00.000Z',
    bundle_digest_sha256: '0'.repeat(64),
    manifest_path: manifestPath,
    submitter_principal_code: 'synthetic.human',
    expected_importer_principal_code: 'synthetic.importer',
    expected_importer_software_code: 'synthetic-importer',
    expected_importer_version: '1.0.0',
    bundle_declarations: {
      contains_credentials: false,
      contains_personal_data: false,
      hostile_input_acknowledged: true,
    },
    principal_bootstrap: {
      trust_root: {
        id: 1,
        principal_code: 'system.bootstrap',
        principal_kind_code: 'service',
        created_by_principal_code: 'system.bootstrap',
        created_at: '2030-01-01T00:05:10.000Z',
      },
      principals: [
        {
          id: 2,
          principal_code: 'synthetic.human',
          principal_kind_code: 'human',
          created_by_principal_code: 'system.bootstrap',
          created_at: '2030-01-01T00:05:11.000Z',
          runtime_role_code: 'manifest_submitter',
        },
        {
          id: 3,
          principal_code: 'synthetic.collector',
          principal_kind_code: 'service',
          created_by_principal_code: 'synthetic.human',
          created_at: '2030-01-01T00:05:12.000Z',
          runtime_role_code: 'collector',
        },
        {
          id: 4,
          principal_code: 'synthetic.importer',
          principal_kind_code: 'service',
          created_by_principal_code: 'synthetic.human',
          created_at: '2030-01-01T00:05:12.000Z',
          runtime_role_code: 'bundle_importer',
        },
      ],
    },
    retrieval_locations: [],
    artifacts: [],
    retrieval_events: [],
    custody_events: [],
    processing_runs: [],
    candidate_occurrences: [],
  }
  manifest.bundle_digest_sha256 = canonicalSha256(manifest, { excludedTopLevelField: 'bundle_digest_sha256' })
  return manifest
}

function writeManifest(root, relativePath, manifest, { bytes } = {}) {
  const destination = path.join(root, relativePath)
  fs.mkdirSync(path.dirname(destination), { recursive: true })
  fs.writeFileSync(destination, bytes ?? `${JSON.stringify(manifest, null, 2)}\n`)
  return destination
}

function assertCode(code) {
  return (error) => {
    assert.equal(error.code, code)
    return true
  }
}

test('securely opens and validates an approved v1 manifest beneath a reviewed descriptor', (t) => {
  const root = temporaryRoot(t)
  const manifest = bootstrapManifest()
  writeManifest(root, manifest.manifest_path, manifest)
  const descriptor = rootDescriptor(t, root)

  const opened = openApprovedEvidenceManifest({
    manifestRelativePath: manifest.manifest_path,
    reader,
    reviewedRootDescriptor: descriptor,
  })

  assert.deepEqual(opened.manifest, manifest)
  assert.equal(opened.bundleDigestSha256, manifest.bundle_digest_sha256)
  assert.equal(opened.manifestRelativePath, manifest.manifest_path)
  assert.ok(opened.manifestBytes.length > opened.canonicalPayloadBytes.length)
  assert.match(opened.manifestBytesSha256, /^[0-9a-f]{64}$/u)
})

test('approved parser reproduces the independently fixed complete-manifest canonical bytes and digest', () => {
  const vector = frozenGolden.complete_manifest_vector
  const parsed = parseApprovedEvidenceManifest(Buffer.from(`${JSON.stringify(vector.value)}\n`, 'utf8'))
  assert.equal(parsed.canonicalPayloadBytes.toString('utf8'), vector.canonical_utf8)
  assert.equal(parsed.bundleDigestSha256, vector.sha256)
})

test('rejects traversal, absolute paths, symlinks, hard links, and non-regular inputs', (t) => {
  const root = temporaryRoot(t)
  const manifest = bootstrapManifest()
  const validPath = writeManifest(root, manifest.manifest_path, manifest)
  const descriptor = rootDescriptor(t, root)
  fs.symlinkSync(path.basename(validPath), path.join(root, 'manifests/link.json'))
  fs.linkSync(validPath, path.join(root, 'manifests/hard-link.json'))
  fs.mkdirSync(path.join(root, 'manifests/directory.json'))
  assert.equal(spawnSync('/usr/bin/mkfifo', [path.join(root, 'manifests/pipe.json')]).status, 0)

  for (const manifestRelativePath of ['../outside.json', '/tmp/outside.json', 'manifests/../outside.json', 'manifests\\outside.json']) {
    assert.throws(
      () => openApprovedEvidenceManifest({ manifestRelativePath, reader, reviewedRootDescriptor: descriptor }),
      assertCode('INPUT_PATH_INVALID'),
    )
  }
  assert.throws(
    () => openApprovedEvidenceManifest({ manifestRelativePath: 'manifests/link.json', reader, reviewedRootDescriptor: descriptor }),
    assertCode('INPUT_SYMLINK_REJECTED'),
  )
  assert.throws(
    () => openApprovedEvidenceManifest({ manifestRelativePath: manifest.manifest_path, reader, reviewedRootDescriptor: descriptor }),
    assertCode('INPUT_TYPE_REJECTED'),
  )
  assert.throws(
    () => openApprovedEvidenceManifest({ manifestRelativePath: 'manifests/directory.json', reader, reviewedRootDescriptor: descriptor }),
    assertCode('INPUT_TYPE_REJECTED'),
  )
  const startedAt = Date.now()
  assert.throws(
    () => openApprovedEvidenceManifest({ manifestRelativePath: 'manifests/pipe.json', reader, reviewedRootDescriptor: descriptor }),
    assertCode('INPUT_TYPE_REJECTED'),
  )
  assert.ok(Date.now() - startedAt < 2_000, 'FIFO rejection must not wait for a writer')
})

test('binds the manifest declaration to the exact descriptor-relative input path', (t) => {
  const root = temporaryRoot(t)
  const manifest = bootstrapManifest('manifests/declared.json')
  writeManifest(root, 'manifests/actual.json', manifest)
  const descriptor = rootDescriptor(t, root)

  assert.throws(
    () => openApprovedEvidenceManifest({
      manifestRelativePath: 'manifests/actual.json',
      reader,
      reviewedRootDescriptor: descriptor,
    }),
    assertCode('MANIFEST_PATH_MISMATCH'),
  )
})

test('strict parsing rejects duplicate keys and unknown manifest members', () => {
  const manifest = bootstrapManifest()
  const duplicate = Buffer.from(JSON.stringify(manifest).replace('{', '{"format":"jedi-atlas-evidence-bundle",'))
  assert.throws(() => parseApprovedEvidenceManifest(duplicate), assertCode('MANIFEST_SCHEMA_INVALID'))

  const unknown = { ...manifest, caller_override: true }
  unknown.bundle_digest_sha256 = canonicalSha256(unknown, { excludedTopLevelField: 'bundle_digest_sha256' })
  assert.throws(
    () => parseApprovedEvidenceManifest(Buffer.from(JSON.stringify(unknown))),
    assertCode('MANIFEST_SCHEMA_INVALID'),
  )
})

test('rejects digest mutations and incompatible schema versions', () => {
  const manifest = bootstrapManifest()
  const digestMutation = structuredClone(manifest)
  digestMutation.bundle_created_at = '2030-01-01T00:06:01.000Z'
  assert.throws(
    () => parseApprovedEvidenceManifest(Buffer.from(JSON.stringify(digestMutation))),
    assertCode('MANIFEST_DIGEST_MISMATCH'),
  )

  const wrongVersion = structuredClone(manifest)
  wrongVersion.format_version = '1.0.1'
  wrongVersion.bundle_digest_sha256 = canonicalSha256(wrongVersion, { excludedTopLevelField: 'bundle_digest_sha256' })
  assert.throws(
    () => parseApprovedEvidenceManifest(Buffer.from(JSON.stringify(wrongVersion))),
    assertCode('INCOMPATIBLE_CONTRACT_VERSION'),
  )
})

test('enforces the approved manifest byte ceiling before parsing', () => {
  const oversized = Buffer.alloc(D9_EVIDENCE_MANIFEST_BYTES_MAX + 1, 0x20)
  assert.throws(() => parseApprovedEvidenceManifest(oversized), assertCode('MANIFEST_TOO_LARGE'))
})

test('fails closed when Linux openat2 confinement is unavailable', (t) => {
  const unavailableReader = compileReviewedManifestReader({ forceOpenat2Unavailable: true })
  t.after(() => unavailableReader.dispose())
  const root = temporaryRoot(t)
  const manifest = bootstrapManifest()
  writeManifest(root, manifest.manifest_path, manifest)
  const descriptor = rootDescriptor(t, root)

  assert.throws(
    () => openApprovedEvidenceManifest({
      manifestRelativePath: manifest.manifest_path,
      reader: unavailableReader,
      reviewedRootDescriptor: descriptor,
    }),
    assertCode('D9_PLATFORM_UNAVAILABLE'),
  )
})
