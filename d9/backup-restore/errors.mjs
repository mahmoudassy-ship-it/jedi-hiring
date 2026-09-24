export class D951Error extends Error {
  constructor(code, message, options = {}) {
    super(message, options)
    this.name = 'D951Error'
    this.code = code
  }
}

export function failD951(code, message, options) {
  throw new D951Error(code, message, options)
}
