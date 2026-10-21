// Pure helpers extracted from ScanDetailPage. No React, no side effects —
// safe to unit test and reuse across the scan-detail tab components.

export const ACTIVE_SCAN_STATUSES = [
  'pending',
  'verifying',
  'queued',
  'running',
  'processing',
]

export const VALID_TABS = ['overview', 'findings', 'telemetry', 'reports']

export const ISSUES_PER_PAGE = 10

export const FINDING_CLASSIFICATIONS = [
  ['security_issue', 'Security Issues'],
  ['attack_surface', 'Attack Surface'],
  ['observation', 'Observations'],
  ['limitation', 'Limitations'],
]

export function getOutcomeLabel(outcome) {
  const labels = {
    queued: 'Queued',
    running: 'Processing',
    completed: 'Completed',
    completed_with_warnings: 'Completed with warnings',
    failed: 'Failed',
  }

  return labels[outcome] || outcome
}

export function displayToolName(name) {
  const names = {
    nmap: 'Nmap',
    zap: 'OWASP ZAP',
    nikto: 'Nikto',
  }

  return names[name] || name || 'Scanner'
}

export function normalize(value) {
  return String(value || '').trim().toLowerCase()
}

export function classificationLabel(value) {
  const normalizedValue = normalize(value)

  return (
    FINDING_CLASSIFICATIONS.find(
      ([classification]) => classification === normalizedValue,
    )?.[1] || 'Security Issue'
  )
}

export function issueSources(issue) {
  if (Array.isArray(issue.sources) && issue.sources.length > 0) {
    return issue.sources
  }

  const fallbackTool = normalize(issue.tool_name)

  if (!fallbackTool || fallbackTool === 'multiple') {
    return []
  }

  return [
    {
      tool_name: issue.tool_name,
      external_finding_ids: issue.external_finding_id
        ? [issue.external_finding_id]
        : [],
      occurrence_count: issue.occurrence_count || 0,
    },
  ]
}

export function issueSourceToolNames(issue) {
  return issueSources(issue)
    .map((source) => normalize(source.tool_name))
    .filter(Boolean)
}

export function issueHasTool(issue, toolName) {
  const normalizedTool = normalize(toolName)

  return issueSourceToolNames(issue).includes(normalizedTool)
}

export function requiresManualValidation(issue) {
  if (issue.requires_manual_validation === true) {
    return true
  }

  const text = normalize(
    [
      issue.title,
      issue.description,
      issue.remediation,
      ...(issue.sample_affected_urls || []),
    ].join(' '),
  )

  return [
    'manual validation',
    'manually validate',
    'requires manual',
    'soft-404',
    'spa/soft-404',
  ].some((marker) => text.includes(marker))
}

export function issueMatchesSearch(issue, search) {
  const needle = normalize(search)
  if (!needle) return true

  const sourceSearchValues = issueSources(issue).flatMap((source) => [
    source.tool_name,
    ...(source.external_finding_ids || []),
  ])

  const haystack = normalize(
    [
      issue.title,
      issue.description,
      issue.remediation,
      issue.classification,
      issue.tool_name,
      issue.severity,
      issue.confidence,
      issue.cwe_id,
      ...sourceSearchValues,
      ...(issue.sample_affected_urls || []),
    ].join(' '),
  )

  return haystack.includes(needle)
}

export function getToolOutcome(tool) {
  if (tool.status === 'failed') return 'failed'
  if (tool.warning || tool.status === 'skipped') return 'warning'
  if (tool.status === 'completed') return 'completed'
  if (tool.status === 'running') return 'running'
  return 'pending'
}
