export class D931Error extends Error {
  constructor(code, message, options = {}) {
    super(`${code}: ${message}`, options)
    this.name = 'D931Error'
    this.code = code
    this.details = options.details ?? null
  }
}

export function failD931(code, message, options) {
  throw new D931Error(code, message, options)
}
