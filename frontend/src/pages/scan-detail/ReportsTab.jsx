import { useEffect, useState } from 'react'

import {
  archiveReports,
  deleteReports,
  downloadReport,
  requestScanReports,
  restoreReports,
} from '../../api/scans'
import { ConfirmDialog, EmptyState, ErrorAlert, SuccessAlert } from '../../components/ui'
import { formatDate, pluralize } from '../../lib/format'
import { UnavailablePanel } from './parts'

export default function ReportsTab({
  scan,
  scanId,
  reports,
  onReportsChanged,
  canGenerateReports = false,
  canLifecycleReports = false,
  canDeleteReports = false,
}) {
  const [reportView, setReportView] = useState('active')
  const [selectedReportIds, setSelectedReportIds] = useState([])
  const [busy, setBusy] = useState(false)
  const [generating, setGenerating] = useState(false)
  const [message, setMessage] = useState('')
  const [error, setError] = useState('')
  const [pendingDelete, setPendingDelete] = useState(false)

  useEffect(() => {
    setSelectedReportIds([])
  }, [reportView])

  if (scan.status !== 'completed') {
    return (
      <div className="assessment-tab-panel">
        <UnavailablePanel
          kicker="REPORTING"
          title="Reports are not available yet"
          message="HTML and PDF artifacts can be generated after the assessment reaches a completed state."
        />
      </div>
    )
  }

  const activeReports = reports.filter((report) => !report.archived_at)
  const archivedReports = reports.filter((report) => Boolean(report.archived_at))
  const visibleReports = reportView === 'archived' ? archivedReports : activeReports
  const allVisibleSelected = Boolean(
    visibleReports.length > 0 &&
      visibleReports.every((report) => selectedReportIds.includes(report.id)),
  )

  function toggleReportSelection(reportId) {
    setSelectedReportIds((current) =>
      current.includes(reportId)
        ? current.filter((value) => value !== reportId)
        : [...current, reportId],
    )
  }

  function toggleVisibleReportSelection() {
    setSelectedReportIds(allVisibleSelected ? [] : visibleReports.map((report) => report.id))
  }

  async function handleGenerateReports() {
    if (!canGenerateReports) {
      return
    }

    if (scan.archived_at) {
      setError('Restore this assessment before generating new reports.')
      return
    }

    setGenerating(true)
    setMessage('')
    setError('')

    try {
      await requestScanReports( scanId, ['html', 'pdf'])
      setMessage('Report generation queued. Refresh reports in a few seconds.')
      window.setTimeout(() => onReportsChanged(), 3500)
    } catch (requestError) {
      setError(requestError.message || 'Unable to queue report generation.')
    } finally {
      setGenerating(false)
    }
  }

  async function runLifecycle(action) {
    if (
      selectedReportIds.length === 0
      || !canLifecycleReports
      || (
        action === 'delete'
        && !canDeleteReports
      )
    ) {
      return
    }

    setBusy(true)
    setMessage('')
    setError('')

    try {
      let response

      if (action === 'archive') {
        response = await archiveReports( selectedReportIds)
        setMessage(`${response.affected_count} report${pluralize(response.affected_count, '')} archived.`)
      } else if (action === 'restore') {
        response = await restoreReports( selectedReportIds)
        setMessage(`${response.affected_count} report${pluralize(response.affected_count, '')} restored.`)
      } else {
        response = await deleteReports( selectedReportIds)
        const warningSuffix = response.cleanup_warnings?.length
          ? ` ${response.cleanup_warnings.length} artifact cleanup warning${
              response.cleanup_warnings.length === 1 ? '' : 's'
            } recorded.`
          : ''
        setMessage(
          `${response.affected_count} report${pluralize(response.affected_count, '')} permanently deleted.${warningSuffix}`,
        )
      }

      setSelectedReportIds([])
      await onReportsChanged()
    } catch (requestError) {
      setError(requestError.message || 'Unable to update report lifecycle state.')
    } finally {
      setBusy(false)
      setPendingDelete(false)
    }
  }

  async function handleDownload(report) {
    setError('')

    try {
      const file = await downloadReport( report.id)
      const url = URL.createObjectURL(file.blob)
      const anchor = document.createElement('a')

      anchor.href = url
      anchor.download = file.filename
      document.body.append(anchor)
      anchor.click()
      anchor.remove()
      URL.revokeObjectURL(url)
    } catch (requestError) {
      setError(requestError.message || 'Unable to download report.')
    }
  }

  return (
    <div className="assessment-tab-panel">
      <section className="scan-console-card reports-card">
        <div className="console-card-heading">
          <div className="report-heading-copy">
            <p className="scan-kicker">REPORTING</p>
            <h2>Assessment reports</h2>
          </div>

          <div className="report-actions">
            <button type="button" className="secondary-button" onClick={onReportsChanged}>
              Refresh
            </button>
            <button
              type="button"
              className="primary-button inline-button"
              onClick={handleGenerateReports}
              disabled={
                !canGenerateReports
                || generating
                || Boolean(scan.archived_at)
              }
            >
              {generating
                ? 'Queueing...'
                : scan.archived_at
                  ? 'Restore to generate'
                  : 'Generate HTML + PDF'}
            </button>
          </div>
        </div>

        <div className="report-snapshot-card">
          <strong>Assessment snapshot</strong>
          <p>
            Active and archived reports remain integrity-checked and downloadable. Archive
            reports to remove them from the normal report list; permanent deletion is only
            available from the report archive.
          </p>
        </div>

        <SuccessAlert message={message} />
        <ErrorAlert message={error} />

        <div className="report-lifecycle-tabs" role="tablist" aria-label="Report lifecycle">
          <button
            type="button"
            role="tab"
            aria-selected={reportView === 'active'}
            className={reportView === 'active' ? 'active' : ''}
            onClick={() => setReportView('active')}
          >
            <span>Active</span>
            <strong>{activeReports.length}</strong>
          </button>
          <button
            type="button"
            role="tab"
            aria-selected={reportView === 'archived'}
            className={reportView === 'archived' ? 'active' : ''}
            onClick={() => setReportView('archived')}
          >
            <span>Archived</span>
            <strong>{archivedReports.length}</strong>
          </button>
        </div>

        {canLifecycleReports && visibleReports.length > 0 && (
          <div className="report-lifecycle-toolbar">
            <label>
              <input
                type="checkbox"
                checked={allVisibleSelected}
                onChange={toggleVisibleReportSelection}
              />
              Select shown
            </label>

            {selectedReportIds.length > 0 && (
              <div className="report-lifecycle-selection">
                <span>
                  <strong>{selectedReportIds.length}</strong> selected
                </span>
                {reportView === 'active' ? (
                  <button
                    type="button"
                    className="secondary-button compact-button"
                    disabled={busy}
                    onClick={() => runLifecycle('archive')}
                  >
                    Archive selected
                  </button>
                ) : (
                  <>
                    <button
                      type="button"
                      className="secondary-button compact-button"
                      disabled={busy}
                      onClick={() => runLifecycle('restore')}
                    >
                      Restore selected
                    </button>
                    <button
                      type="button"
                      className="danger-button compact-button"
                      disabled={
                        busy
                        || !canDeleteReports
                      }
                      onClick={() => setPendingDelete(true)}
                    >
                      Permanently delete
                    </button>
                  </>
                )}
              </div>
            )}
          </div>
        )}

        {visibleReports.length === 0 ? (
          <EmptyState
            className="compact-empty-state"
            title={reportView === 'active' ? 'No active reports yet' : 'No archived reports'}
            message={
              reportView === 'active'
                ? 'Generate an HTML and PDF assessment artifact from this completed run.'
                : 'Archived report artifacts will appear here until restored or permanently deleted.'
            }
          />
        ) : (
          <div className="report-list report-lifecycle-list">
            {visibleReports.map((report) => (
              <article
                className={
                  selectedReportIds.includes(report.id)
                    ? 'report-row selected'
                    : 'report-row'
                }
                key={report.id}
              >
                {canLifecycleReports && (
                  <input
                    className="report-select-checkbox"
                    type="checkbox"
                    checked={selectedReportIds.includes(report.id)}
                    onChange={() => toggleReportSelection(report.id)}
                    aria-label={`Select ${report.format.toUpperCase()} report`}
                  />
                )}
                <div className="report-format">{report.format.toUpperCase()}</div>
                <div className="report-row-details">
                  <strong className="report-title">BEACON Security Assessment</strong>
                  <span className="report-generated-at">Generated {formatDate(report.generated_at)}</span>
                  {report.archived_at && (
                    <span className="report-archived-time">
                      Archived {formatDate(report.archived_at)}
                    </span>
                  )}
                </div>
                <button
                  type="button"
                  className="report-download-action"
                  onClick={() => handleDownload(report)}
                >
                  Download ↓
                </button>
              </article>
            ))}
          </div>
        )}

        {canLifecycleReports && (
          <div className="report-lifecycle-guidance">
            <strong>Archive first, delete second.</strong>
            <p>
              Archiving hides a report from the active list without removing evidence. Permanent
              deletion removes the database record and stored HTML/PDF artifact, while a deletion
              audit event is retained.
            </p>
          </div>
        )}
      </section>

      {canDeleteReports && (
        <ConfirmDialog
          open={pendingDelete}
          title={`Permanently delete ${selectedReportIds.length} report${pluralize(selectedReportIds.length, '')}?`}
          description="This removes the stored report files and cannot be undone."
          confirmLabel="Permanently delete"
          busy={busy}
          onCancel={() => setPendingDelete(false)}
          onConfirm={() => runLifecycle('delete')}
        />
      )}
    </div>
  )
}
