export const FINDING_SEVERITIES = [
  'critical',
  'high',
  'medium',
  'low',
  'informational',
]

export const FINDING_CLASSIFICATIONS = [
  'security_issue',
  'attack_surface',
  'observation',
  'limitation',
]


export const FINDING_LIFECYCLE_STATES = [
  'NEW',
  'TRIAGED',
  'ASSIGNED',
  'IN_REMEDIATION',
  'READY_FOR_RETEST',
  'RESOLVED',
]


export const FINDING_OBSERVATION_STATES = [
  'NEW',
  'PERSISTING',
  'RESOLVED',
  'REGRESSED',
]


export const FINDING_DISPOSITIONS = [
  'FALSE_POSITIVE',
  'RISK_ACCEPTED',
  'DUPLICATE',
]

const FINDING_FILTER_KEYS = [
  'severity',
  'confidence',
  'target_id',
  'scan_id',
  'tool',
  'classification',
  'lifecycle_state',
  'observation_state',
  'disposition',
  'assignee_user_id',
  'remediation_owner_user_id',
  'q',
  'offset',
  'limit',
]


export function parseFindingFilters(
  searchParams,
) {
  const filters = {}

  for (const key of FINDING_FILTER_KEYS) {
    const value = searchParams.get(key)

    if (
      value !== null &&
      value !== ''
    ) {
      filters[key] = value
    }
  }

  if (
    filters.severity &&
    !FINDING_SEVERITIES.includes(
      filters.severity,
    )
  ) {
    delete filters.severity
  }

  if (
    filters.classification &&
    !FINDING_CLASSIFICATIONS.includes(
      filters.classification,
    )
  ) {
    delete filters.classification
  }

  if (
    filters.lifecycle_state &&
    !FINDING_LIFECYCLE_STATES.includes(
      filters.lifecycle_state,
    )
  ) {
    delete filters.lifecycle_state
  }

  if (
    filters.observation_state &&
    !FINDING_OBSERVATION_STATES.includes(
      filters.observation_state,
    )
  ) {
    delete filters.observation_state
  }

  if (
    filters.disposition &&
    !FINDING_DISPOSITIONS.includes(
      filters.disposition,
    )
  ) {
    delete filters.disposition
  }

  return filters
}


export function buildFindingSearch(
  filters = {},
) {
  const parameters = new URLSearchParams()

  for (const key of FINDING_FILTER_KEYS) {
    const value = filters[key]

    if (
      value !== undefined &&
      value !== null &&
      value !== ''
    ) {
      parameters.set(
        key,
        String(value),
      )
    }
  }

  return parameters
}


export function buildFindingsPath(
  filters = {},
) {
  const parameters =
    buildFindingSearch(filters)

  const query =
    parameters.toString()

  return query
    ? `/findings?${query}`
    : '/findings'
}


export function findingDetailPath(
  findingId,
) {
  return `/findings/${encodeURIComponent(findingId)}`
}


const TOOL_LABELS = {
  nmap: 'Nmap',
  nikto: 'Nikto',
  zap: 'ZAP',
}

const ASSESSMENT_DATE_FORMATTER =
  new Intl.DateTimeFormat(
    'en-US',
    {
      month: 'short',
      day: 'numeric',
      year: 'numeric',
      timeZone: 'UTC',
    },
  )


export function buildTargetOptions(
  targets = [],
) {
  return targets.map(
    (target) => ({
      value: target.id,
      label:
        target.hostname ||
        target.normalized_url ||
        'Registered target',
    }),
  )
}


export function buildAssessmentOptions(
  scans = [],
  targets = [],
  targetId = '',
) {
  const targetById =
    new Map(
      targets.map(
        (target) => [
          target.id,
          target,
        ],
      ),
    )

  return [...scans]
    .filter(
      (scan) =>
        !targetId ||
        scan.target_id === targetId,
    )
    .sort(
      (left, right) =>
        new Date(
          right.created_at,
        ).getTime() -
        new Date(
          left.created_at,
        ).getTime(),
    )
    .map((scan) => {
      const target =
        targetById.get(
          scan.target_id,
        )

      const targetLabel =
        target?.hostname ||
        target?.normalized_url ||
        scan.target_id

      const dateLabel =
        ASSESSMENT_DATE_FORMATTER.format(
          new Date(
            scan.created_at,
          ),
        )

      return {
        value: scan.id,
        label:
          `${targetLabel} · ${scan.id.slice(0, 8)} · ${dateLabel}`,
      }
    })
}


export function buildSourceToolOptions(
  toolNames = [],
) {
  const options = []
  const seen = new Set()

  for (const toolName of toolNames) {
    const trimmed =
      String(toolName || '').trim()

    if (!trimmed) {
      continue
    }

    const value =
      trimmed.toLowerCase()

    if (seen.has(value)) {
      continue
    }

    seen.add(value)

    options.push({
      value,
      label:
        TOOL_LABELS[value] ||
        trimmed,
    })
  }

  return options
}


export function resolveFindingOptionValue(
  value,
  options = [],
  caseInsensitive = false,
) {
  if (!value) {
    return ''
  }

  const candidate =
    String(value)

  const option = options.find(
    (item) => {
      if (caseInsensitive) {
        return (
          String(
            item.value,
          ).toLowerCase() ===
          candidate.toLowerCase()
        )
      }

      return (
        String(item.value) ===
        candidate
      )
    },
  )

  return option
    ? option.value
    : ''
}


export function reconcileAssessmentForTarget(
  filters = {},
  targetId = '',
  scans = [],
) {
  const nextFilters = {
    ...filters,
  }

  if (targetId) {
    nextFilters.target_id =
      targetId
  } else {
    delete nextFilters.target_id
  }

  if (
    !targetId ||
    !nextFilters.scan_id
  ) {
    return nextFilters
  }

  const selectedScan =
    scans.find(
      (scan) =>
        scan.id ===
        nextFilters.scan_id,
    )

  if (
    !selectedScan ||
    selectedScan.target_id !==
      targetId
  ) {
    delete nextFilters.scan_id
  }

  return nextFilters
}
