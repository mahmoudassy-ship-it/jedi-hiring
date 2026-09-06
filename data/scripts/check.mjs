import { DatabaseSync } from 'node:sqlite'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const dataDirectory = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const databasePath = path.resolve(process.env.DATABASE_PATH || path.join(dataDirectory, 'jedi-hiring.sqlite'))
const database = new DatabaseSync(databasePath, { readOnly: true })

try {
  const integrity = database.prepare('PRAGMA integrity_check').get().integrity_check
  const foreignKeyViolations = database.prepare('PRAGMA foreign_key_check').all()
  const counts = {
    jurisdictions: database.prepare('SELECT COUNT(*) AS count FROM jurisdictions').get().count,
    instruments: database.prepare('SELECT COUNT(*) AS count FROM legal_instruments').get().count,
    requirements: database.prepare('SELECT COUNT(*) AS count FROM requirements').get().count,
    hiringStages: database.prepare('SELECT COUNT(*) AS count FROM hiring_stages').get().count,
    legalLenses: database.prepare('SELECT COUNT(*) AS count FROM legal_lenses').get().count,
    atlasPrincipals: database.prepare('SELECT COUNT(*) AS count FROM atlas_principals').get().count,
    atlasLanguages: database.prepare('SELECT COUNT(*) AS count FROM atlas_languages').get().count,
    atlasJurisdictions: database.prepare('SELECT COUNT(*) AS count FROM atlas_jurisdictions').get().count,
    atlasJurisdictionVersions: database.prepare('SELECT COUNT(*) AS count FROM atlas_jurisdiction_versions').get().count,
    atlasEvidenceBundleReceipts: database.prepare('SELECT COUNT(*) AS count FROM atlas_evidence_bundle_receipts').get().count,
    atlasRetrievalLocations: database.prepare('SELECT COUNT(*) AS count FROM atlas_retrieval_locations').get().count,
    atlasArtifacts: database.prepare('SELECT COUNT(*) AS count FROM atlas_artifacts').get().count,
    atlasRetrievalEvents: database.prepare('SELECT COUNT(*) AS count FROM atlas_retrieval_events').get().count,
    atlasRetrievalRedirects: database.prepare('SELECT COUNT(*) AS count FROM atlas_retrieval_redirects').get().count,
    atlasArtifactCustodyEvents: database.prepare('SELECT COUNT(*) AS count FROM atlas_artifact_custody_events').get().count,
    atlasProcessingRuns: database.prepare('SELECT COUNT(*) AS count FROM atlas_processing_runs').get().count,
    atlasProcessingOutputs: database.prepare('SELECT COUNT(*) AS count FROM atlas_processing_outputs').get().count,
    atlasUnverifiedCandidateOccurrences: database.prepare('SELECT COUNT(*) AS count FROM atlas_unverified_candidate_occurrences').get().count,
  }

  if (integrity !== 'ok') throw new Error(`SQLite integrity check failed: ${integrity}`)
  if (foreignKeyViolations.length > 0) throw new Error('SQLite foreign-key check failed')
  if (counts.instruments < 10 || counts.requirements < 15) throw new Error('Seed dataset is incomplete')
  if (Object.entries(counts).some(([name, count]) => name.startsWith('atlas') && count !== 0)) {
    throw new Error('Atlas foundation and source-quarantine tables must remain empty until the importer and operational controls are approved and implemented')
  }

  console.log('Database checks passed.')
  console.table(counts)
} finally {
  database.close()
}
