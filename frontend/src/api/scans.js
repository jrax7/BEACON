import {
  apiRequest,
  downloadApiFile,
} from './client'


export function listScans(
  archived = 'active',
) {
  const parameters =
    new URLSearchParams({
      archived,
    })

  return apiRequest(
    `/scans?${parameters}`,
  )
}


export function getScan(
  scanId,
) {
  return apiRequest(
    `/scans/${encodeURIComponent(
      scanId,
    )}`,
  )
}


export function createScan(
  targetId,
) {
  return apiRequest(
    '/scans',
    {
      method: 'POST',
      body: {
        target_id:
          targetId,
        scan_level:
          'basic',
      },
    },
  )
}


export function getScanTelemetry(
  scanId,
) {
  return apiRequest(
    `/scans/${encodeURIComponent(
      scanId,
    )}/telemetry`,
  )
}


export function getScanSummary(
  scanId,
) {
  return apiRequest(
    `/scans/${encodeURIComponent(
      scanId,
    )}/summary`,
  )
}


export function getScanIssues(
  scanId,
  {
    limit = 50,
    offset = 0,
  } = {},
) {
  const parameters =
    new URLSearchParams({
      limit:
        String(
          limit,
        ),
      offset:
        String(
          offset,
        ),
    })

  return apiRequest(
    `/scans/${encodeURIComponent(
      scanId,
    )}/issues?${parameters}`,
  )
}


export function listScanReports(
  scanId,
  archived = 'active',
) {
  const parameters =
    new URLSearchParams({
      archived,
    })

  return apiRequest(
    `/scans/${encodeURIComponent(
      scanId,
    )}/reports?${parameters}`,
  )
}


export function requestScanReports(
  scanId,
  formats = [
    'html',
    'pdf',
  ],
) {
  return apiRequest(
    `/scans/${encodeURIComponent(
      scanId,
    )}/reports`,
    {
      method: 'POST',
      body: {
        formats,
      },
    },
  )
}


export function downloadReport(
  reportId,
) {
  return downloadApiFile(
    `/reports/${encodeURIComponent(
      reportId,
    )}/download`,
  )
}


export function archiveScan(
  scanId,
) {
  return apiRequest(
    `/scans/${encodeURIComponent(
      scanId,
    )}/archive`,
    {
      method: 'POST',
    },
  )
}


export function restoreScan(
  scanId,
) {
  return apiRequest(
    `/scans/${encodeURIComponent(
      scanId,
    )}/restore`,
    {
      method: 'POST',
    },
  )
}


export function archiveScans(
  scanIds,
) {
  return apiRequest(
    '/scans/bulk/archive',
    {
      method: 'POST',
      body: {
        scan_ids:
          scanIds,
      },
    },
  )
}


export function restoreScans(
  scanIds,
) {
  return apiRequest(
    '/scans/bulk/restore',
    {
      method: 'POST',
      body: {
        scan_ids:
          scanIds,
      },
    },
  )
}


export function deleteScan(
  scanId,
) {
  return apiRequest(
    `/scans/${encodeURIComponent(
      scanId,
    )}`,
    {
      method: 'DELETE',
    },
  )
}


export function deleteScans(
  scanIds,
) {
  return apiRequest(
    '/scans/bulk/delete',
    {
      method: 'POST',
      body: {
        scan_ids:
          scanIds,
      },
    },
  )
}


export function archiveReports(
  reportIds,
) {
  return apiRequest(
    '/reports/bulk/archive',
    {
      method: 'POST',
      body: {
        report_ids:
          reportIds,
      },
    },
  )
}


export function restoreReports(
  reportIds,
) {
  return apiRequest(
    '/reports/bulk/restore',
    {
      method: 'POST',
      body: {
        report_ids:
          reportIds,
      },
    },
  )
}


export function deleteReports(
  reportIds,
) {
  return apiRequest(
    '/reports/bulk/delete',
    {
      method: 'POST',
      body: {
        report_ids:
          reportIds,
      },
    },
  )
}
