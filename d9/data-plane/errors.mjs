export class D92Error extends Error {
  constructor(code, message, options) {
    super(`${code}: ${message}`, options)
    this.name = 'D92Error'
    this.code = code
  }
}

export function failD92(code, message, options) {
  throw new D92Error(code, message, options)
}
