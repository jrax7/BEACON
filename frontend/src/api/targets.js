import {
  apiRequest,
} from './client'


export function listTargets() {
  return apiRequest(
    '/targets',
  )
}


export function getTarget(
  targetId,
) {
  return apiRequest(
    `/targets/${encodeURIComponent(
      targetId,
    )}`,
  )
}


export function createTarget(
  {
    url,
    verificationMethod,
  },
) {
  return apiRequest(
    '/targets',
    {
      method: 'POST',
      body: {
        url,
        verification_method:
          verificationMethod,
      },
    },
  )
}


export function regenerateVerificationToken(
  targetId,
) {
  return apiRequest(
    `/targets/${encodeURIComponent(
      targetId,
    )}/verification-token`,
    {
      method: 'POST',
    },
  )
}


export function verifyTarget(
  targetId,
  verificationMethod,
) {
  if (
    verificationMethod !==
      'file' &&
    verificationMethod !==
      'dns'
  ) {
    throw new Error(
      'Unsupported verification method.',
    )
  }

  return apiRequest(
    `/targets/${encodeURIComponent(
      targetId,
    )}/verify/${verificationMethod}`,
    {
      method: 'POST',
    },
  )
}


export function deleteTarget(
  targetId,
) {
  return apiRequest(
    `/targets/${encodeURIComponent(
      targetId,
    )}`,
    {
      method: 'DELETE',
    },
  )
}
