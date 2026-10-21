import { assessmentProfileLabel } from '../scans/helpers'
import {
  useCallback,
  useEffect,
  useMemo,
  useState,
} from 'react'
import { Link } from 'react-router'

import { listReports } from '../../api/reports'
import {
  archiveReports,
  deleteReports,
  downloadReport,
  restoreReports,
} from '../../api/scans'
import { isDemoUser } from '../../auth/demo-access'
import { PERMISSIONS } from '../../auth/rbac'
import { useAuth } from '../../auth/useAuth'
import {
  Card,
  ConfirmDialog,
  CopyValue,
  EmptyState,
  ErrorAlert,
  Input,
  PageHeader,
  SkeletonList,
  SuccessAlert,
} from '../../components/ui'
import {
  formatDate,
  pluralize,
} from '../../lib/format'
import { pushToast } from '../../system/toasts'
import {
  REPORT_FORMATS,
  matchesReportFormat,
  matchesReportSearch,
} from './helpers'

function ReportRow({
  report,
  selected,
  actionBusy,
  downloadBusy,
  allowLifecycle,
  onToggleSelected,
  onDownload,
}) {
  return (
    <article
      className={
        selected
          ? 'global-report-row selected'
          : 'global-report-row'
      }
    >
      {allowLifecycle && (
        <label
          className="global-report-select"
          title="Select report"
        >
          <input
            type="checkbox"
            checked={selected}
            disabled={actionBusy}
            onChange={() =>
              onToggleSelected(report.id)
            }
            aria-label={`Select ${report.format.toUpperCase()} report`}
          />
          <span aria-hidden="true" />
        </label>
      )}

      <div className="global-report-target">
        <strong>
          {report.target_hostname}
        </strong>

        <span>
          {report.target_url}
        </span>

        <Link
          to={`/targets/${report.target_id}`}
          className="global-report-context-link"
        >
          View target
        </Link>
      </div>

      <div className="global-report-assessment">
        <span>Assessment</span>

        <Link
          to={`/scans/${report.scan_id}`}
        >
          <code>{report.scan_id}</code>
        </Link>

        <small>
          {assessmentProfileLabel(report)} · {report.scan_status}
        </small>
      </div>

      <div className="global-report-format">
        <span>Format</span>
        <strong>
          {report.format.toUpperCase()}
        </strong>
      </div>

      <div className="global-report-integrity">
        <span>Integrity metadata</span>

        <strong>
          {report.checksum_sha256
            ? 'Checksum recorded'
            : 'Checksum unavailable'}
        </strong>

        {report.checksum_sha256 && (
          <CopyValue
            value={report.checksum_sha256}
            displayValue={`${report.checksum_sha256.slice(0, 12)}…`}
            label="Copy report checksum"
          />
        )}
      </div>

      <div className="global-report-time">
        <span>
          {report.archived_at
            ? 'Archived'
            : 'Generated'}
        </span>

        <strong>
          {formatDate(
            report.archived_at
              || report.generated_at,
          )}
        </strong>

        {report.archived_at && (
          <small>
            Generated {formatDate(report.generated_at)}
          </small>
        )}
      </div>

      <button
        type="button"
        className="secondary-button global-report-download"
        disabled={
          actionBusy
          || downloadBusy
        }
        onClick={() => onDownload(report)}
      >
        {downloadBusy
          ? 'Downloading'
          : 'Download ↓'}
      </button>
    </article>
  )
}

export default function ReportsPage() {
  const { user, hasPermission } = useAuth()
  const isDemo = isDemoUser(user)

  const canLifecycleReports =
    !isDemo
    && hasPermission(
      PERMISSIONS.REPORT_LIFECYCLE,
    )

  const canDeleteReports =
    !isDemo
    && hasPermission(
      PERMISSIONS.REPORT_DELETE,
    )

  const [activeReports, setActiveReports] =
    useState([])
  const [archivedReports, setArchivedReports] =
    useState([])
  const [view, setView] =
    useState('active')
  const [search, setSearch] = useState('')
  const [formatFilter, setFormatFilter] =
    useState('all')
  const [
    selectedReportIds,
    setSelectedReportIds,
  ] = useState([])
  const [loading, setLoading] =
    useState(true)
  const [actionBusy, setActionBusy] =
    useState(false)
  const [downloadBusyId, setDownloadBusyId] =
    useState(null)
  const [pendingDelete, setPendingDelete] =
    useState(false)
  const [error, setError] =
    useState('')
  const [actionMessage, setActionMessage] =
    useState('')

  const loadReports = useCallback(async () => {
    setLoading(true)
    setError('')

    try {
      const [
        activeResult,
        archivedResult,
      ] = await Promise.all([
        listReports( 'active'),
        listReports( 'archived'),
      ])

      setActiveReports(activeResult)
      setArchivedReports(archivedResult)
    } catch (requestError) {
      setError(
        requestError.message
        || 'Unable to load reports.',
      )
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    loadReports()
  }, [loadReports])

  useEffect(() => {
    setSelectedReportIds([])
    setActionMessage('')
  }, [view])

  const reports =
    view === 'archived'
      ? archivedReports
      : activeReports

  const visibleReports = useMemo(
    () =>
      reports
        .filter((report) =>
          matchesReportSearch(
            report,
            search,
          ),
        )
        .filter((report) =>
          matchesReportFormat(
            report,
            formatFilter,
          ),
        )
        .sort(
          (left, right) =>
            new Date(
              right.generated_at,
            ).getTime()
            - new Date(
              left.generated_at,
            ).getTime(),
        ),
    [
      reports,
      search,
      formatFilter,
    ],
  )

  const allVisibleSelected =
    visibleReports.length > 0
    && visibleReports.every((report) =>
      selectedReportIds.includes(report.id),
    )

  function toggleReportSelection(
    reportId,
  ) {
    setSelectedReportIds((current) =>
      current.includes(reportId)
        ? current.filter(
            (value) => value !== reportId,
          )
        : [...current, reportId],
    )
  }

  function toggleVisibleSelection() {
    setSelectedReportIds(
      allVisibleSelected
        ? []
        : visibleReports.map(
            (report) => report.id,
          ),
    )
  }

  async function runLifecycleAction(
    action,
  ) {
    if (
      selectedReportIds.length === 0
      || actionBusy
      || !canLifecycleReports
      || (
        action === 'delete'
        && !canDeleteReports
      )
    ) {
      return
    }

    setActionBusy(true)
    setActionMessage('')
    setError('')

    try {
      let result

      if (action === 'archive') {
        result = await archiveReports(

          selectedReportIds,
        )

        setActionMessage(
          `${result.affected_count} report${pluralize(
            result.affected_count,
            '',
          )} archived.`,
        )
      } else if (action === 'restore') {
        result = await restoreReports(

          selectedReportIds,
        )

        setActionMessage(
          `${result.affected_count} report${pluralize(
            result.affected_count,
            '',
          )} restored.`,
        )
      } else {
        result = await deleteReports(

          selectedReportIds,
        )

        const warningSuffix =
          result.cleanup_warnings?.length
            ? ` ${result.cleanup_warnings.length} storage cleanup warning(s) recorded.`
            : ''

        setActionMessage(
          `${result.affected_count} report${pluralize(
            result.affected_count,
            '',
          )} permanently deleted.${warningSuffix}`,
        )
      }

      setSelectedReportIds([])
      await loadReports()
    } catch (requestError) {
      setError(
        requestError.message
        || 'Unable to update report lifecycle state.',
      )
    } finally {
      setActionBusy(false)
      setPendingDelete(false)
    }
  }

  async function handleDownload(report) {
    if (downloadBusyId) {
      return
    }

    setDownloadBusyId(report.id)
    setError('')

    try {
      const file = await downloadReport(

        report.id,
      )

      const objectUrl =
        URL.createObjectURL(file.blob)

      const anchor =
        document.createElement('a')

      anchor.href = objectUrl
      anchor.download = file.filename

      document.body.append(anchor)
      anchor.click()
      pushToast(
        'Report download started.',
        { type: 'success' },
      )
      anchor.remove()

      URL.revokeObjectURL(objectUrl)
    } catch (requestError) {
      setError(
        requestError.message
        || 'Unable to download report.',
      )
    } finally {
      setDownloadBusyId(null)
    }
  }

  return (
    <>
      <PageHeader
        eyebrow="REPORTS"
        title="Generated reports"
        description="Find assessment reports across your targets, review lifecycle state and integrity metadata, and download evidence from one workspace."
        actions={
          <button
            type="button"
            className="secondary-button"
            disabled={
              loading
              || actionBusy
            }
            onClick={loadReports}
          >
            {loading
              ? 'Refreshing'
              : 'Refresh'}
          </button>
        }
      />

      <ErrorAlert
        message={error}
        className="page-message"
      />

      <SuccessAlert
        message={actionMessage}
        className="page-message lifecycle-success"
      />

      <section
        className="global-report-view-switch"
        aria-label="Report lifecycle view"
      >
        <button
          type="button"
          className={
            view === 'active'
              ? 'active'
              : ''
          }
          onClick={() =>
            setView('active')
          }
        >
          <span>Active</span>
          <strong>
            {activeReports.length}
          </strong>
        </button>

        <button
          type="button"
          className={
            view === 'archived'
              ? 'active'
              : ''
          }
          onClick={() =>
            setView('archived')
          }
        >
          <span>Archived</span>
          <strong>
            {archivedReports.length}
          </strong>
        </button>
      </section>

      <section
        className="global-report-filters"
        aria-label="Report filters"
      >
        <label className="global-report-search">
          <span>Search</span>

          <Input
            type="search"
            value={search}
            placeholder="Search reports"
            onChange={(event) =>
              setSearch(event.target.value)
            }
          />
        </label>

        <div
          className="global-report-format-filters"
          aria-label="Report format"
        >
          {REPORT_FORMATS.map(
            (format) => (
              <button
                type="button"
                key={format}
                className={
                  formatFilter === format
                    ? 'active'
                    : ''
                }
                onClick={() =>
                  setFormatFilter(format)
                }
              >
                {format}
              </button>
            ),
          )}
        </div>

        {(search
          || formatFilter !== 'all') && (
          <button
            type="button"
            className="global-report-clear"
            onClick={() => {
              setSearch('')
              setFormatFilter('all')
            }}
          >
            Clear filters
          </button>
        )}
      </section>

      <Card
        className="global-reports-card"
        eyebrow={
          view === 'archived'
            ? 'ARCHIVE'
            : 'REPORT LIBRARY'
        }
        title={
          view === 'archived'
            ? 'Archived reports'
            : 'Available reports'
        }
        headingActions={
          <div className="global-report-heading-actions">
            <span className="section-count">
              {visibleReports.length} shown
            </span>

            {canLifecycleReports && visibleReports.length > 0 && (
              <label className="global-report-select-all">
                <input
                  type="checkbox"
                  checked={
                    allVisibleSelected
                  }
                  disabled={actionBusy}
                  onChange={
                    toggleVisibleSelection
                  }
                />

                <span>Select shown</span>
              </label>
            )}
          </div>
        }
      >
        {canLifecycleReports && selectedReportIds.length > 0 && (
          <div className="global-report-action-bar">
            <div>
              <strong>
                {selectedReportIds.length} selected
              </strong>

              <span>
                {view === 'active'
                  ? 'Archive selected reports without removing their stored evidence.'
                  : 'Restore selected reports or remove archived files permanently.'}
              </span>
            </div>

            <div className="global-report-action-buttons">
              {view === 'active' ? (
                <button
                  type="button"
                  className="secondary-button"
                  disabled={actionBusy}
                  onClick={() =>
                    runLifecycleAction(
                      'archive',
                    )
                  }
                >
                  {actionBusy
                    ? 'Working'
                    : 'Archive selected'}
                </button>
              ) : (
                <>
                  <button
                    type="button"
                    className="secondary-button"
                    disabled={actionBusy}
                    onClick={() =>
                      runLifecycleAction(
                        'restore',
                      )
                    }
                  >
                    Restore selected
                  </button>

                  <button
                    type="button"
                    className="danger-button"
                    disabled={
                      actionBusy
                      || !canDeleteReports
                    }
                    onClick={() =>
                      setPendingDelete(true)
                    }
                  >
                    Permanently delete
                  </button>
                </>
              )}
            </div>
          </div>
        )}

        {loading && (
          <SkeletonList
            rows={5}
            label="Loading reports"
          />
        )}

        {!loading
          && visibleReports.length === 0 && (
            <EmptyState
              title={
                view === 'archived'
                  ? 'No archived reports'
                  : 'No matching reports'
              }
              message={
                search
                || formatFilter !== 'all'
                  ? 'No reports match the current search and format filters.'
                  : view === 'archived'
                    ? 'Archived report artifacts will appear here until restored or permanently deleted.'
                    : 'Generate a report from a completed assessment to add it to this workspace.'
              }
            />
          )}

        {!loading
          && visibleReports.length > 0 && (
            <div className="global-report-list">
              {visibleReports.map(
                (report) => (
                  <ReportRow
                    key={report.id}
                    report={report}
                    selected={
                      selectedReportIds.includes(
                        report.id,
                      )
                    }
                    actionBusy={
                      actionBusy
                    }
                    downloadBusy={
                      downloadBusyId
                      === report.id
                    }
                    allowLifecycle={canLifecycleReports}
                    onToggleSelected={
                      toggleReportSelection
                    }
                    onDownload={
                      handleDownload
                    }
                  />
                ),
              )}
            </div>
          )}
      </Card>

      {canLifecycleReports && (
        <section className="global-report-safety-note">
          <strong>
            Report lifecycle
          </strong>

          <p>
            Archiving removes a report from the active library without deleting its artifact. Permanent deletion remains available only from the archive.
          </p>
        </section>
      )}

      <ConfirmDialog
        open={
          canDeleteReports
          && pendingDelete
        }
        title={`Permanently delete ${selectedReportIds.length} report${pluralize(
          selectedReportIds.length,
          '',
        )}?`}
        description="This removes the stored report files and cannot be undone."
        confirmLabel="Permanently delete"
        busy={actionBusy}
        onCancel={() =>
          setPendingDelete(false)
        }
        onConfirm={() =>
          runLifecycleAction('delete')
        }
      />
    </>
  )
}
