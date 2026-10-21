export const REPORT_FORMATS = [
  'all',
  'html',
  'pdf',
]

export function matchesReportSearch(
  report,
  search,
) {
  const query = String(search || '')
    .trim()
    .toLowerCase()

  if (!query) {
    return true
  }

  const searchable = [
    report?.id,
    report?.target_id,
    report?.target_hostname,
    report?.target_url,
    report?.scan_id,
    report?.scan_level,
    report?.scan_status,
    report?.format,
    report?.checksum_sha256,
  ]
    .filter(Boolean)
    .join(' ')
    .toLowerCase()

  return searchable.includes(query)
}

export function matchesReportFormat(
  report,
  format,
) {
  if (format === 'all') {
    return true
  }

  return report?.format === format
}
