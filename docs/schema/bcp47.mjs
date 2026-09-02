const asciiTag = /^[A-Za-z]{2,8}(?:-[A-Za-z0-9]{1,8})*$/

export function canonicalizeBcp47(input) {
  if (typeof input !== 'string') throw new TypeError('language tag must be a string')
  if (input.includes('\0')) throw new Error('language tag contains NUL')
  if (Buffer.byteLength(input, 'utf8') > 35) throw new Error('language tag exceeds 35-byte storage limit')
  if (input.trim() !== input || !asciiTag.test(input) || input.includes('--')) {
    throw new Error(`invalid BCP 47 language tag: ${JSON.stringify(input)}`)
  }
  let canonical
  try {
    canonical = Intl.getCanonicalLocales(input)[0]
  } catch {
    throw new Error(`invalid BCP 47 language tag: ${JSON.stringify(input)}`)
  }
  if (canonical !== input) throw new Error(`noncanonical BCP 47 language tag; use ${canonical}`)
  return canonical
}

export function assertCanonicalBcp47(input) {
  return canonicalizeBcp47(input)
}
