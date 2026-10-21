import { apiRequest } from './client'


export function listFindings(
  filters = {},
) {
  const parameters =
    new URLSearchParams()

  for (
    const [key, value]
    of Object.entries(
      filters,
    )
  ) {
    if (
      value !== undefined &&
      value !== null &&
      value !== ''
    ) {
      parameters.set(
        key,
        String(
          value,
        ),
      )
    }
  }

  const query =
    parameters.toString()

  return apiRequest(
    `/findings${
      query
        ? `?${query}`
        : ''
    }`,
  )
}


export async function listFindingSourceTools() {
  const toolNames = []

  let offset = 0
  let total = 0

  do {
    const page =
      await listFindings(
        {
          offset,
          limit: 100,
        },
      )

    const items =
      page?.items ||
      []

    total =
      Number(
        page?.total,
      ) || 0

    for (
      const item
      of items
    ) {
      for (
        const source
        of item.sources ||
        []
      ) {
        if (
          source &&
          source.tool_name
        ) {
          toolNames.push(
            source.tool_name,
          )
        }
      }
    }

    if (
      items.length === 0
    ) {
      break
    }

    offset +=
      items.length

  } while (
    offset < total
  )

  return toolNames
}


export function getFinding(
  findingId,
) {
  return apiRequest(
    `/findings/${encodeURIComponent(
      findingId,
    )}`,
  )
}


export function updateFindingLifecycle(
  findingId,
  nextState,
  reason = null,
) {
  return apiRequest(
    `/findings/${encodeURIComponent(
      findingId,
    )}/lifecycle`,
    {
      method: 'PATCH',
      body: {
        next_state:
          nextState,
        reason:
          reason || null,
      },
    },
  )
}


export function setFindingDisposition(
  findingId,
  disposition,
  reason,
  duplicateOfFindingId = null,
) {
  return apiRequest(
    `/findings/${encodeURIComponent(
      findingId,
    )}/disposition`,
    {
      method: 'PATCH',
      body: {
        disposition,
        reason,
        duplicate_of_finding_id:
          duplicateOfFindingId || null,
      },
    },
  )
}


export function clearFindingDisposition(
  findingId,
  reason,
) {
  return apiRequest(
    `/findings/${encodeURIComponent(
      findingId,
    )}/disposition`,
    {
      method: 'DELETE',
      body: {
        reason,
      },
    },
  )
}


export function updateFindingAssignee(
  findingId,
  assigneeUserId,
) {
  return apiRequest(
    `/findings/${encodeURIComponent(
      findingId,
    )}/assignee`,
    {
      method: 'PATCH',
      body: {
        assignee_user_id:
          assigneeUserId || null,
      },
    },
  )
}


export function updateFindingRemediationOwner(
  findingId,
  remediationOwnerUserId,
) {
  return apiRequest(
    `/findings/${encodeURIComponent(
      findingId,
    )}/remediation-owner`,
    {
      method: 'PATCH',
      body: {
        remediation_owner_user_id:
          remediationOwnerUserId || null,
      },
    },
  )
}


export function getFindingHistory(
  findingId,
) {
  return apiRequest(
    `/findings/${encodeURIComponent(
      findingId,
    )}/history`,
  )
}


export function createFindingRetest(
  findingId,
) {
  return apiRequest(
    `/findings/${encodeURIComponent(
      findingId,
    )}/retests`,
    {
      method: 'POST',
      body: {
        scan_id: null,
      },
    },
  )
}


export function listFindingRetests(
  findingId,
) {
  return apiRequest(
    `/findings/${encodeURIComponent(
      findingId,
    )}/retests`,
  )
}


export function getFindingPosture() {
  return apiRequest(
    '/findings/posture',
  )
}



export function linkFindingRetest(
  retestId,
  scanId,
) {
  return apiRequest(
    `/findings/retests/${encodeURIComponent(
      retestId,
    )}/scan`,
    {
      method: 'PATCH',
      body: {
        scan_id:
          scanId,
      },
    },
  )
}
