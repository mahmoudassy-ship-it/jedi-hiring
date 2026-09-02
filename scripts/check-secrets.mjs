import fs from 'node:fs'
import { execFileSync } from 'node:child_process'

const sensitiveName = /(^|\/)(?:\.env(?:\..+)?|.*(?:secret|credential).*)$/i
let tracked = []

try {
  tracked = execFileSync('git', ['ls-files'], { encoding: 'utf8' }).trim().split('\n').filter(Boolean)
} catch {
  console.warn('Git is not initialized; tracked-file secret check skipped.')
}

const allowedSensitiveNames = new Set(['.env.example', 'scripts/check-secrets.mjs'])
const unsafeTracked = tracked.filter((file) => sensitiveName.test(file) && !allowedSensitiveNames.has(file))
if (unsafeTracked.length > 0) {
  throw new Error(`Sensitive files are tracked: ${unsafeTracked.join(', ')}`)
}

if (fs.existsSync('.env')) {
  const mode = fs.statSync('.env').mode & 0o777
  if (mode !== 0o600) throw new Error(`.env permissions must be 0600; found ${mode.toString(8)}`)
}

console.log('Secret-file checks passed.')
