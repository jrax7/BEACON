export const FILTERS = ['all', 'running', 'completed', 'failed']

export const ACTIVE_SCAN_STATUSES = ['pending', 'verifying', 'queued', 'running', 'processing']

export function matchesFilter(scan, filter) {
  if (filter === 'all') return true
  if (filter === 'running') return ACTIVE_SCAN_STATUSES.includes(scan.status)
  return scan.status === filter
}

export function canArchive(scan) {
  return ['completed', 'failed'].includes(scan.status)
}

export function matchesAssessmentSearch(
  scan,
  target,
  search,
) {
  const query = String(search || '')
    .trim()
    .toLowerCase()

  if (!query) {
    return true
  }

  const searchable = [
    scan?.id,
    scan?.target_id,
    scan?.scan_level,
    scan?.status,
    target?.hostname,
    target?.normalized_url,
  ]
    .filter(Boolean)
    .join(' ')
    .toLowerCase()

  return searchable.includes(query)
}

const ASSESSMENT_PROFILE_LABELS = {
  quick: 'Quick',
  standard: 'Standard',
  deep: 'Deep',
}


export function assessmentProfileLabel(
  assessment,
) {
  const profile = String(
    assessment?.profile
    || assessment?.scan_level
    || '',
  )
    .trim()
    .toLowerCase()

  if (
    !profile
    || profile === 'basic'
  ) {
    return 'Legacy'
  }

  if (
    ASSESSMENT_PROFILE_LABELS[
      profile
    ]
  ) {
    return (
      ASSESSMENT_PROFILE_LABELS[
        profile
      ]
    )
  }

  return (
    profile.charAt(0).toUpperCase()
    + profile.slice(1)
  )
}
