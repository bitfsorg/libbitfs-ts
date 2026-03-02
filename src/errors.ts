export class BitfsError extends Error {
  constructor(message: string, public readonly code: string) {
    super(message)
    this.name = 'BitfsError'
  }
}
