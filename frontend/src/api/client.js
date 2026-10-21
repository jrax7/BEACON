import {
  getCsrfToken,
  notifyAuthExpired,
  refreshSessionMetadata,
  setCsrfToken,
} from '../auth/session-state.js'
import {
  getActiveOrganizationId,
} from '../auth/organization-state.js'
import { beginRequestActivity, endRequestActivity } from '../system/requestActivity.js'


const API_BASE_URL =
  '/api/v1'

const SAFE_METHODS =
  new Set([
    'GET',
    'HEAD',
    'OPTIONS',
  ])

const SESSION_401_CODES =
  new Set([
    'AUTH_REQUIRED',
    'SESSION_INVALID',
    'SESSION_EXPIRED',
    'SESSION_REVOKED',
    'AUTH_SESSION_INVALID',
    'AUTH_SESSION_EXPIRED',
    'AUTH_SESSION_REVOKED',
  ])


export class ApiError extends Error {
  constructor(
    message,
    status,
    data = null,
  ) {
    super(message)

    this.name = 'ApiError'
    this.status = status
    this.data = data
    this.code =
      getErrorCode(data)
  }
}


async function parseResponse(
  response,
) {
  if (
    response.status === 204 ||
    response.status === 205
  ) {
    return null
  }

  const contentType =
    response.headers.get(
      'content-type',
    ) || ''

  if (
    contentType.includes(
      'application/json',
    )
  ) {
    return response.json()
  }

  return response.text()
}


function getErrorCode(
  data,
) {
  if (
    data &&
    typeof data === 'object' &&
    data.detail &&
    typeof data.detail === 'object' &&
    typeof data.detail.code ===
      'string'
  ) {
    return data.detail.code
  }

  return null
}


function getErrorMessage(
  data,
  status,
) {
  if (
    data &&
    typeof data === 'object' &&
    data.detail &&
    typeof data.detail === 'object' &&
    typeof data.detail.message ===
      'string'
  ) {
    return data.detail.message
  }

  if (
    data &&
    typeof data === 'object' &&
    typeof data.detail ===
      'string'
  ) {
    return data.detail
  }

  if (
    data &&
    typeof data === 'object' &&
    Array.isArray(
      data.detail,
    )
  ) {
    const messages =
      data.detail
        .map(
          (item) =>
            item?.msg,
        )
        .filter(Boolean)

    if (
      messages.length > 0
    ) {
      return messages.join(
        ' ',
      )
    }
  }

  return (
    `Request failed with HTTP ${status}`
  )
}


function captureCsrf(
  response,
) {
  const candidate =
    response.headers.get(
      'X-CSRF-Token',
    )

  if (candidate) {
    setCsrfToken(
      candidate,
    )
  }
}


function isUnsafeMethod(
  method,
) {
  return !SAFE_METHODS.has(
    method.toUpperCase(),
  )
}


function isSessionExpiryError(
  status,
  code,
) {
  return (
    status === 401 &&
    (
      code === null ||
      SESSION_401_CODES.has(
        code,
      )
    )
  )
}


async function handleFailure(
  response,
  data,
  method,
) {
  const error =
    new ApiError(
      getErrorMessage(
        data,
        response.status,
      ),
      response.status,
      data,
    )

  if (
    isSessionExpiryError(
      response.status,
      error.code,
    )
  ) {
    notifyAuthExpired(
      error,
    )
  }

  if (
    response.status === 403 &&
    error.code ===
      'CSRF_INVALID' &&
    isUnsafeMethod(
      method,
    )
  ) {
    try {
      await refreshSessionMetadata()
    } catch {
      // Metadata refresh is best-effort here.
      // Never replay the rejected unsafe request.
    }
  }

  throw error
}


export async function apiRequest(
  path,
  {
    method = 'GET',
    headers = {},
    body = null,
  } = {},
) {
  const normalizedMethod =
    method.toUpperCase()

  const requestHeaders = {
    ...headers,
  }

  const activeOrganizationId =
    getActiveOrganizationId()

  if (
    activeOrganizationId &&
    !requestHeaders['X-Organization-ID']
  ) {
    requestHeaders['X-Organization-ID'] =
      activeOrganizationId
  }

  if (
    isUnsafeMethod(
      normalizedMethod,
    )
  ) {
    const csrf =
      getCsrfToken()

    if (
      csrf &&
      !requestHeaders[
        'X-CSRF-Token'
      ]
    ) {
      requestHeaders[
        'X-CSRF-Token'
      ] = csrf
    }
  }

  if (
    body !== null &&
    !(body instanceof FormData) &&
    !(body instanceof URLSearchParams) &&
    !requestHeaders[
      'Content-Type'
    ]
  ) {
    requestHeaders[
      'Content-Type'
    ] = 'application/json'
  }

  let requestBody =
    body

  if (
    body !== null &&
    requestHeaders[
      'Content-Type'
    ] === 'application/json' &&
    typeof body !== 'string'
  ) {
    requestBody =
      JSON.stringify(
        body,
      )
  }

  beginRequestActivity()
  let response
  try {
    response = await fetch(
      `${API_BASE_URL}${path}`,
      {
        method:
          normalizedMethod,
        credentials:
          'same-origin',
        headers:
          requestHeaders,
        body:
          requestBody,
      },
    )
  } finally {
    endRequestActivity()
  }

  captureCsrf(
    response,
  )

  const data =
    await parseResponse(
      response,
    )

  if (!response.ok) {
    await handleFailure(
      response,
      data,
      normalizedMethod,
    )
  }

  return data
}


export async function getHealth() {
  const response =
    await fetch(
      '/health',
      {
        credentials:
          'same-origin',
      },
    )

  const data =
    await parseResponse(
      response,
    )

  if (!response.ok) {
    throw new ApiError(
      'BEACON backend health check failed.',
      response.status,
      data,
    )
  }

  return data
}


export async function downloadApiFile(
  path,
) {
  beginRequestActivity()
  let response
  try {
    response = await fetch(
      `${API_BASE_URL}${path}`,
      {
        credentials:
          'same-origin',
      },
    )
  } finally {
    endRequestActivity()
  }

  captureCsrf(
    response,
  )

  if (!response.ok) {
    const data =
      await parseResponse(
        response,
      )

    await handleFailure(
      response,
      data,
      'GET',
    )
  }

  const disposition =
    response.headers.get(
      'content-disposition',
    ) || ''

  const filenameMatch =
    disposition.match(
      /filename="?([^";]+)"?/i,
    )

  return {
    blob:
      await response.blob(),
    filename:
      filenameMatch?.[1] ||
      'beacon-report',
  }
}
