import crypto from 'node:crypto'
import fs from 'node:fs'

const DEFAULT_MAXIMUM_BYTES = 4 * 1024 * 1024
const DEFAULT_MAXIMUM_DEPTH = 32
const DEFAULT_MAXIMUM_MEMBERS = 4096

export class D9JsonError extends Error {
  constructor(code, message) {
    super(`${code}: ${message}`)
    this.name = 'D9JsonError'
    this.code = code
  }
}

function fail(code, message) {
  throw new D9JsonError(code, message)
}

function inputBytes(input) {
  if (Buffer.isBuffer(input)) return input
  if (input instanceof Uint8Array) return Buffer.from(input.buffer, input.byteOffset, input.byteLength)
  if (typeof input === 'string') return Buffer.from(input, 'utf8')
  fail('INVALID_JSON_INPUT', 'JSON input must be a string, Buffer, or Uint8Array')
}

function assertBound(value, name, { minimum = 1 } = {}) {
  if (!Number.isSafeInteger(value) || value < minimum) fail('INVALID_JSON_LIMIT', `${name} must be a safe integer of at least ${minimum}`)
}

function scanJsonLexically(text, { contractNumbers }) {
  const stack = []

  for (let index = 0; index < text.length; index += 1) {
    const character = text[index]
    if (character === '"') {
      const start = index
      for (index += 1; index < text.length; index += 1) {
        if (text[index] === '\\') {
          index += 1
          continue
        }
        if (text[index] === '"') break
      }
      if (index >= text.length) fail('INVALID_JSON', 'unterminated JSON string')

      const raw = text.slice(start, index + 1)
      let next = index + 1
      while (/\s/u.test(text[next] || '')) next += 1
      if (stack.at(-1)?.type === 'object' && text[next] === ':') {
        let key
        try {
          key = JSON.parse(raw)
        } catch {
          fail('INVALID_JSON', 'invalid object key')
        }
        if (stack.at(-1).keys.has(key)) fail('DUPLICATE_KEY', `duplicate object key ${key}`)
        stack.at(-1).keys.add(key)
      }
      continue
    }

    if (character === '{') stack.push({ type: 'object', keys: new Set() })
    else if (character === '[') stack.push({ type: 'array' })
    else if (character === '}' || character === ']') stack.pop()
    else if (character === '-' || /[0-9]/u.test(character)) {
      const token = text.slice(index).match(/^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/u)?.[0]
      if (!token) fail('INVALID_JSON', 'invalid number token')
      if (contractNumbers && !/^(?:0|[1-9][0-9]*)$/u.test(token)) {
        fail('INVALID_NUMBER', `number token is outside the D9 canonical profile: ${token}`)
      }
      index += token.length - 1
    }
  }
}

function graphStats(value) {
  let maximumDepth = 0
  let members = 0
  const rootDepth = Array.isArray(value) || (value && typeof value === 'object') ? 1 : 0
  const pending = [[value, rootDepth]]

  while (pending.length > 0) {
    const [child, depth] = pending.pop()
    if (Array.isArray(child)) {
      maximumDepth = Math.max(maximumDepth, depth)
      for (const item of child) {
        const nested = Array.isArray(item) || (item && typeof item === 'object')
        pending.push([item, nested ? depth + 1 : depth])
      }
    } else if (child && typeof child === 'object') {
      maximumDepth = Math.max(maximumDepth, depth)
      members += Object.keys(child).length
      for (const item of Object.values(child)) {
        const nested = Array.isArray(item) || (item && typeof item === 'object')
        pending.push([item, nested ? depth + 1 : depth])
      }
    }
  }

  return { maximumDepth, members }
}

function assertUnicodeScalarString(value) {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index)
    if (code >= 0xd800 && code <= 0xdbff) {
      if (index + 1 >= value.length) fail('INVALID_UNICODE', 'lone high surrogate')
      const next = value.charCodeAt(index + 1)
      if (next < 0xdc00 || next > 0xdfff) fail('INVALID_UNICODE', 'lone high surrogate')
      index += 1
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      fail('INVALID_UNICODE', 'lone low surrogate')
    }
  }
}

export function canonicalize(value) {
  if (value === null) return 'null'
  if (typeof value === 'string') {
    assertUnicodeScalarString(value)
    return JSON.stringify(value)
  }
  if (typeof value === 'boolean') return value ? 'true' : 'false'
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value) || value < 0 || Object.is(value, -0)) {
      fail('INVALID_NUMBER', 'numbers must be nonnegative safe integers')
    }
    return String(value)
  }
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(',')}]`
  if (!value || Object.getPrototypeOf(value) !== Object.prototype) {
    fail('INVALID_CANONICAL_VALUE', 'canonical JSON accepts only null, scalars, arrays, and plain objects')
  }

  return `{${Object.keys(value).sort().map((key) => `${canonicalize(key)}:${canonicalize(value[key])}`).join(',')}}`
}

export function sha256Bytes(input) {
  if (typeof input === 'string' || Buffer.isBuffer(input) || input instanceof Uint8Array) {
    return crypto.createHash('sha256').update(input).digest('hex')
  }
  fail('INVALID_HASH_INPUT', 'SHA-256 input must be a string, Buffer, or Uint8Array')
}

export function canonicalSha256(value, { excludedTopLevelField = null } = {}) {
  let payload = value
  if (excludedTopLevelField !== null) {
    if (typeof excludedTopLevelField !== 'string' || !value || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) {
      fail('INVALID_CANONICAL_VALUE', 'a top-level field can be excluded only from a plain object')
    }
    payload = Object.fromEntries(Object.entries(value).filter(([key]) => key !== excludedTopLevelField))
  }
  return sha256Bytes(Buffer.from(canonicalize(payload), 'utf8'))
}

export function parseStrictJson(input, {
  maximumBytes = DEFAULT_MAXIMUM_BYTES,
  maximumDepth = DEFAULT_MAXIMUM_DEPTH,
  maximumMembers = DEFAULT_MAXIMUM_MEMBERS,
  contractNumbers = true,
} = {}) {
  assertBound(maximumBytes, 'maximumBytes')
  assertBound(maximumDepth, 'maximumDepth', { minimum: 0 })
  assertBound(maximumMembers, 'maximumMembers', { minimum: 0 })
  if (typeof contractNumbers !== 'boolean') fail('INVALID_JSON_LIMIT', 'contractNumbers must be boolean')

  const bytes = inputBytes(input)
  if (bytes.length === 0 || bytes.length > maximumBytes) fail('INVALID_SIZE', 'JSON input byte length is outside its fixed bound')
  if (bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf) fail('INVALID_ENCODING', 'UTF-8 BOM is prohibited')

  let text
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(bytes)
  } catch {
    fail('INVALID_ENCODING', 'input is not valid UTF-8')
  }

  scanJsonLexically(text, { contractNumbers })
  let value
  try {
    value = JSON.parse(text)
  } catch {
    fail('INVALID_JSON', 'input is not valid JSON')
  }

  const { maximumDepth: actualDepth, members } = graphStats(value)
  if (actualDepth > maximumDepth || members > maximumMembers) {
    fail('RESOURCE_LIMIT_EXCEEDED', 'JSON graph exceeds its fixed depth or member limit')
  }
  canonicalize(value)
  return value
}

export function readFileBytes(filePath, { maximumBytes = DEFAULT_MAXIMUM_BYTES, allowEmpty = false } = {}) {
  if (typeof filePath !== 'string' || filePath.length === 0) fail('INVALID_FILE', 'file path must be a nonempty string')
  assertBound(maximumBytes, 'maximumBytes')
  if (typeof allowEmpty !== 'boolean') fail('INVALID_JSON_LIMIT', 'allowEmpty must be boolean')
  let descriptor
  try {
    descriptor = fs.openSync(filePath, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW)
    const stats = fs.fstatSync(descriptor)
    const identity = fs.fstatSync(descriptor, { bigint: true })
    if (!stats.isFile()) fail('INVALID_FILE', 'file source is not a regular file')
    if ((!allowEmpty && stats.size === 0) || stats.size > maximumBytes) fail('INVALID_SIZE', 'file byte length is outside its fixed bound')
    const bytes = Buffer.allocUnsafe(stats.size)
    let offset = 0
    while (offset < bytes.length) {
      const count = fs.readSync(descriptor, bytes, offset, bytes.length - offset, offset)
      if (count === 0) fail('INVALID_FILE', 'file ended before its recorded length')
      offset += count
    }
    const afterIdentity = fs.fstatSync(descriptor, { bigint: true })
    if (afterIdentity.dev !== identity.dev || afterIdentity.ino !== identity.ino || afterIdentity.size !== identity.size || afterIdentity.mtimeNs !== identity.mtimeNs || afterIdentity.ctimeNs !== identity.ctimeNs) {
      fail('INPUT_CHANGED', 'file changed while it was being read')
    }
    return bytes
  } catch (error) {
    if (error instanceof D9JsonError) throw error
    fail('INVALID_FILE', `cannot open or read regular file: ${error.code || 'unknown error'}`)
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor)
  }
}

export function readStrictJson(filePath, options = {}) {
  const maximumBytes = options.maximumBytes ?? DEFAULT_MAXIMUM_BYTES
  return parseStrictJson(readFileBytes(filePath, { maximumBytes }), options)
}

export function sha256File(filePath) {
  if (typeof filePath !== 'string' || filePath.length === 0) fail('INVALID_FILE', 'file path must be a nonempty string')
  let descriptor
  try {
    descriptor = fs.openSync(filePath, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW)
    const before = fs.fstatSync(descriptor)
    const identity = fs.fstatSync(descriptor, { bigint: true })
    if (!before.isFile()) fail('INVALID_FILE', 'hash source is not a regular file')
    const hash = crypto.createHash('sha256')
    const chunk = Buffer.allocUnsafe(64 * 1024)
    let position = 0
    while (position < before.size) {
      const count = fs.readSync(descriptor, chunk, 0, Math.min(chunk.length, before.size - position), position)
      if (count === 0) fail('INVALID_FILE', 'file ended before its recorded length')
      hash.update(chunk.subarray(0, count))
      position += count
    }
    const afterIdentity = fs.fstatSync(descriptor, { bigint: true })
    if (afterIdentity.dev !== identity.dev || afterIdentity.ino !== identity.ino || afterIdentity.size !== identity.size || afterIdentity.mtimeNs !== identity.mtimeNs || afterIdentity.ctimeNs !== identity.ctimeNs) {
      fail('INPUT_CHANGED', 'file changed while it was hashed')
    }
    return hash.digest('hex')
  } catch (error) {
    if (error instanceof D9JsonError) throw error
    fail('INVALID_FILE', `cannot open or hash regular file: ${error.code || 'unknown error'}`)
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor)
  }
}
