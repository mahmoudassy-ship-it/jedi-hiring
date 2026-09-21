export class D941Error extends Error {
  constructor(code, message, options = {}) {
    super(`${code}: ${message}`, options)
    this.name = 'D941Error'
    this.code = code
    this.details = options.details ?? null
  }
}

export function failD941(code, message, options) {
  throw new D941Error(code, message, options)
}
