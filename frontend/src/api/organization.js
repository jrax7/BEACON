import {
  apiRequest,
} from './client'


function encodeId(value) {
  return encodeURIComponent(
    value,
  )
}


export function listOrganizations() {
  return apiRequest(
    '/organizations',
  )
}


export function setActiveOrganizationPreference(
  organizationId,
) {
  return apiRequest(
    '/organization/active',
    {
      method: 'POST',
      body: {
        organization_id:
          organizationId,
      },
    },
  )
}


export function getOrganization() {
  return apiRequest(
    '/organization',
  )
}


export function updateOrganization(
  name,
) {
  return apiRequest(
    '/organization',
    {
      method: 'PATCH',
      body: {
        name,
      },
    },
  )
}


export function listOrganizationMembers() {
  return apiRequest(
    '/organization/members',
  )
}


export function updateOrganizationMember(
  membershipId,
  role,
) {
  return apiRequest(
    `/organization/members/${encodeId(
      membershipId,
    )}`,
    {
      method: 'PATCH',
      body: {
        role,
      },
    },
  )
}


export function deleteOrganizationMember(
  membershipId,
) {
  return apiRequest(
    `/organization/members/${encodeId(
      membershipId,
    )}`,
    {
      method: 'DELETE',
    },
  )
}


export function listOrganizationInvitations() {
  return apiRequest(
    '/organization/invitations',
  )
}


export function createOrganizationInvitation({
  email,
  role,
}) {
  return apiRequest(
    '/organization/invitations',
    {
      method: 'POST',
      body: {
        email,
        role,
      },
    },
  )
}


export function resendOrganizationInvitation(
  invitationId,
) {
  return apiRequest(
    `/organization/invitations/${encodeId(
      invitationId,
    )}/resend`,
    {
      method: 'POST',
    },
  )
}


export function revokeOrganizationInvitation(
  invitationId,
) {
  return apiRequest(
    `/organization/invitations/${encodeId(
      invitationId,
    )}`,
    {
      method: 'DELETE',
    },
  )
}


export function acceptOrganizationInvitation(
  invitationToken,
) {
  return apiRequest(
    '/organization/invitations/accept',
    {
      method: 'POST',
      body: {
        token:
          invitationToken,
      },
    },
  )
}


export function resolveOrganizationInvitation(
  invitationToken,
) {
  const parameters =
    new URLSearchParams({
      token:
        invitationToken,
    })

  return apiRequest(
    `/organization/invitations/resolve?${parameters}`,
  )
}
