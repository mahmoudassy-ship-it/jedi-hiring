#!/usr/bin/env node

import path from 'node:path'
import { buildResearchDatabase, repositoryPaths } from '../lib/research-track.mjs'

const projectRoot = path.resolve(import.meta.dirname, '../..')
const paths = repositoryPaths(projectRoot)

if (process.argv.length > 2) {
  throw new Error('This fixed-function builder accepts no caller-selected paths')
}

const result = buildResearchDatabase({
  manifestDirectory: paths.manifestRoot,
  outputPath: paths.defaultOutput,
  allowedManifestRoot: paths.researchRoot,
  allowedOutputRoot: paths.generatedRoot,
})

console.log(JSON.stringify({
  boundary: 'noncanonical_single_operator_research',
  authority: 'none',
  publication_eligible: false,
  ...result,
}, null, 2))
