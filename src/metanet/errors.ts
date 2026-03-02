import { BitfsError } from '../errors.js'

export class MetanetError extends BitfsError {
  constructor(message: string, code: string) {
    super(message, code)
    this.name = 'MetanetError'
  }
}

export const ErrNotDirectory = () => new MetanetError('node is not a directory', 'ERR_NOT_DIRECTORY')
export const ErrNotFile = () => new MetanetError('node is not a file', 'ERR_NOT_FILE')
export const ErrNotLink = () => new MetanetError('node is not a link', 'ERR_NOT_LINK')
export const ErrChildNotFound = () => new MetanetError('child not found', 'ERR_CHILD_NOT_FOUND')
export const ErrChildExists = () => new MetanetError('child already exists', 'ERR_CHILD_EXISTS')
export const ErrLinkDepthExceeded = () => new MetanetError('link depth exceeded', 'ERR_LINK_DEPTH_EXCEEDED')
export const ErrRemoteLinkNotSupported = () => new MetanetError('remote link not supported', 'ERR_REMOTE_LINK_NOT_SUPPORTED')
export const ErrInvalidPath = () => new MetanetError('invalid path', 'ERR_INVALID_PATH')
export const ErrNodeNotFound = () => new MetanetError('node not found', 'ERR_NODE_NOT_FOUND')
export const ErrInvalidPayload = () => new MetanetError('invalid payload', 'ERR_INVALID_PAYLOAD')
export const ErrHardLinkToDirectory = () => new MetanetError('hard links to directories not allowed', 'ERR_HARD_LINK_TO_DIRECTORY')
export const ErrNilParam = () => new MetanetError('required parameter is nil', 'ERR_NIL_PARAM')
export const ErrInvalidName = () => new MetanetError('invalid name', 'ERR_INVALID_NAME')
export const ErrAboveRoot = () => new MetanetError('cannot navigate above root', 'ERR_ABOVE_ROOT')
export const ErrInvalidPubKey = () => new MetanetError('invalid public key length', 'ERR_INVALID_PUBKEY')
export const ErrInvalidOPReturn = () => new MetanetError('invalid OP_RETURN data', 'ERR_INVALID_OP_RETURN')
export const ErrTotalLinkBudgetExceeded = () => new MetanetError(
  'total link follow budget exceeded',
  'ERR_TOTAL_LINK_BUDGET_EXCEEDED',
)
