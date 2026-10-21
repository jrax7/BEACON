import { useCallback, useEffect, useMemo, useState } from 'react'
import { Link } from 'react-router'

import { archiveScans, deleteScans, listScans, restoreScans } from '../../api/scans'
import { listTargets } from '../../api/targets'
import { isDemoUser } from '../../auth/demo-access'
import { PERMISSIONS } from '../../auth/rbac'
import { useAuth } from '../../auth/useAuth'
import { Card, ConfirmDialog, EmptyState, ErrorAlert, Input, PageHeader, SkeletonList, SuccessAlert } from '../../components/ui'
import { pluralize } from '../../lib/format'
import {
  FILTERS,
  canArchive,
  matchesAssessmentSearch,
  matchesFilter,
} from './helpers'
import ScanRow from './ScanRow'

export default function ScansPage() {
  const { user, hasPermission } = useAuth()
  const isDemo = isDemoUser(user)

  const canCreateAssessments =
    isDemo
    || hasPermission(
      PERMISSIONS.ASSESSMENT_CREATE,
    )

  const canLifecycleAssessments =
    !isDemo
    && hasPermission(
      PERMISSIONS.ASSESSMENT_LIFECYCLE,
    )

  const canDeleteAssessments =
    !isDemo
    && hasPermission(
      PERMISSIONS.ASSESSMENT_DELETE,
    )
  const [activeScans, setActiveScans] = useState([])
  const [archivedScans, setArchivedScans] = useState([])
  const [targets, setTargets] = useState([])
  const [view, setView] = useState('history')
  const [filter, setFilter] = useState('all')
  const [search, setSearch] = useState('')
  const [selectedIds, setSelectedIds] = useState(new Set())
  const [loading, setLoading] = useState(true)
  const [actionBusy, setActionBusy] = useState(false)
  const [error, setError] = useState('')
  const [actionMessage, setActionMessage] = useState('')
  const [pendingDelete, setPendingDelete] = useState(false)

  const loadScans = useCallback(async () => {
    setError('')
    setLoading(true)

    try {
      const [activeResult, archivedResult, targetResult] = await Promise.all([
        listScans( 'active'),
        listScans( 'archived'),
        listTargets(),
      ])

      setActiveScans(activeResult)
      setArchivedScans(archivedResult)
      setTargets(targetResult)
    } catch (requestError) {
      setError(requestError.message || 'Unable to load assessments.')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    loadScans()
  }, [loadScans])

  useEffect(() => {
    setSelectedIds(new Set())
    setFilter('all')
    setActionMessage('')
  }, [view])

  const targetById = useMemo(() => new Map(targets.map((target) => [target.id, target])), [targets])

  const scans = view === 'archived' ? archivedScans : activeScans

  const visibleScans = useMemo(
    () =>
      [...scans]
        .filter((scan) => matchesFilter(scan, filter))
        .filter((scan) =>
          matchesAssessmentSearch(
            scan,
            targetById.get(scan.target_id),
            search,
          ),
        )
        .sort(
          (left, right) =>
            new Date(right.created_at).getTime()
            - new Date(left.created_at).getTime(),
        ),
    [scans, filter, search, targetById],
  )

  const counts = useMemo(
    () => ({
      all: scans.length,
      running: scans.filter((scan) => matchesFilter(scan, 'running')).length,
      completed: scans.filter((scan) => scan.status === 'completed').length,
      failed: scans.filter((scan) => scan.status === 'failed').length,
    }),
    [scans],
  )

  const selectableVisibleIds = useMemo(
    () => visibleScans.filter((scan) => view === 'archived' || canArchive(scan)).map((scan) => scan.id),
    [visibleScans, view],
  )

  const allVisibleSelected = Boolean(
    selectableVisibleIds.length > 0 && selectableVisibleIds.every((id) => selectedIds.has(id)),
  )

  function toggleSelected(scanId) {
    setSelectedIds((current) => {
      const next = new Set(current)
      if (next.has(scanId)) {
        next.delete(scanId)
      } else {
        next.add(scanId)
      }
      return next
    })
  }

  function toggleSelectAll() {
    setSelectedIds((current) => {
      const next = new Set(current)
      if (allVisibleSelected) {
        selectableVisibleIds.forEach((id) => next.delete(id))
      } else {
        selectableVisibleIds.forEach((id) => next.add(id))
      }
      return next
    })
  }

  async function runLifecycleAction(action) {
    const scanIds = [...selectedIds]

    if (
      scanIds.length === 0
      || actionBusy
      || !canLifecycleAssessments
      || (
        action === 'delete'
        && !canDeleteAssessments
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
        result = await archiveScans( scanIds)
        setActionMessage(`${result.affected_count} assessment${pluralize(result.affected_count, '')} archived.`)
      } else if (action === 'restore') {
        result = await restoreScans( scanIds)
        setActionMessage(`${result.affected_count} assessment${pluralize(result.affected_count, '')} restored.`)
      } else {
        result = await deleteScans( scanIds)
        const warningText = result.cleanup_warnings?.length
          ? ` ${result.cleanup_warnings.length} storage cleanup warning(s) were recorded for review.`
          : ''

        setActionMessage(
          `${result.affected_count} archived assessment${pluralize(result.affected_count, '')} permanently deleted.${warningText}`,
        )
      }

      setSelectedIds(new Set())
      await loadScans()
    } catch (requestError) {
      setError(requestError.message || `Unable to ${action} selected assessments.`)
    } finally {
      setActionBusy(false)
      setPendingDelete(false)
    }
  }

  return (
    <>
      <PageHeader
        eyebrow="ASSESSMENTS"
        title="Assessment lifecycle"
        description="Review current scan history, archive completed evidence, restore it when needed, or permanently remove archived assessment data."
        actions={
          <>
            <button type="button" className="secondary-button" onClick={loadScans} disabled={loading || actionBusy}>
              {loading ? 'Refreshing...' : 'Refresh'}
            </button>
            {canCreateAssessments && (
              <Link className="primary-button inline-button" to="/scans/new">
                + New Assessment
              </Link>
            )}
          </>
        }
      />

      <ErrorAlert message={error} className="page-message" />
      <SuccessAlert message={actionMessage} className="page-message lifecycle-success" />

      <section className="lifecycle-view-switch" aria-label="Assessment storage view">
        <button type="button" className={view === 'history' ? 'active' : ''} onClick={() => setView('history')}>
          <span>History</span>
          <strong>{activeScans.length}</strong>
        </button>
        <button type="button" className={view === 'archived' ? 'active' : ''} onClick={() => setView('archived')}>
          <span>Archived</span>
          <strong>{archivedScans.length}</strong>
        </button>
      </section>

      <section className="assessment-search-bar">
        <label className="assessment-search-field">
          <span>Search</span>

          <Input
            type="search"
            value={search}
            placeholder="Search assessments"
            onChange={(event) => setSearch(event.target.value)}
          />
        </label>

        {search && (
          <button
            type="button"
            className="assessment-search-clear"
            onClick={() => setSearch('')}
          >
            Clear
          </button>
        )}
      </section>

      <section className="scan-filter-row" aria-label="Assessment filters">
        {FILTERS.map((item) => (
          <button
            type="button"
            className={filter === item ? 'scan-filter active' : 'scan-filter'}
            key={item}
            onClick={() => setFilter(item)}
          >
            <span>{item}</span>
            <strong>{counts[item]}</strong>
          </button>
        ))}
      </section>

      <Card
        className="scans-list-card"
        eyebrow={view === 'archived' ? 'ARCHIVE' : 'HISTORY'}
        title={view === 'archived' ? 'Archived assessments' : 'Assessment runs'}
        headingActions={
          <div className="lifecycle-heading-actions">
            <span className="section-count">{visibleScans.length} shown</span>

            {canLifecycleAssessments && visibleScans.length > 0 && (
              <label className="scan-select-all">
                <input
                  type="checkbox"
                  checked={allVisibleSelected}
                  onChange={toggleSelectAll}
                  disabled={selectableVisibleIds.length === 0 || actionBusy}
                />
                <span>Select shown</span>
              </label>
            )}
          </div>
        }
      >
        {canLifecycleAssessments && selectedIds.size > 0 && (
          <div className="lifecycle-action-bar">
            <div>
              <strong>{selectedIds.size} selected</strong>
              <span>
                {view === 'archived'
                  ? 'Restore selected assessments or remove them permanently.'
                  : 'Only completed and failed assessments can be archived.'}
              </span>
            </div>

            <div className="lifecycle-action-buttons">
              {view === 'history' ? (
                <button
                  type="button"
                  className="secondary-button"
                  disabled={actionBusy}
                  onClick={() => runLifecycleAction('archive')}
                >
                  {actionBusy ? 'Working...' : 'Archive selected'}
                </button>
              ) : (
                <>
                  <button
                    type="button"
                    className="secondary-button"
                    disabled={actionBusy}
                    onClick={() => runLifecycleAction('restore')}
                  >
                    Restore selected
                  </button>
                  {canDeleteAssessments && (
                    <button
                      type="button"
                      className="danger-button"
                      disabled={actionBusy}
                      onClick={() => setPendingDelete(true)}
                    >
                      Permanently delete
                    </button>
                  )}
                </>
              )}
            </div>
          </div>
        )}

        {loading && <SkeletonList rows={5} label="Loading assessments" />}

        {!loading && visibleScans.length === 0 && (
          <EmptyState
            title={view === 'archived' ? 'Archive is empty' : 'No matching assessments'}
            message={
              view === 'archived'
                ? 'Archived assessments remain recoverable here until you restore or permanently delete them.'
                : search
                  ? 'No assessments match the current search and status filters.'
                  : 'Start a new assessment from the guided assessment workflow.'
            }
          />
        )}

        {!loading && visibleScans.length > 0 && (
          <div className="scan-list lifecycle-scan-list">
            {visibleScans.map((scan) => (
              <ScanRow
                key={scan.id}
                scan={scan}
                target={targetById.get(scan.target_id)}
                view={view}
                selected={selectedIds.has(scan.id)}
                actionBusy={actionBusy}
                onToggleSelected={toggleSelected}
                allowLifecycle={canLifecycleAssessments}
              />
            ))}
          </div>
        )}
      </Card>

      {canLifecycleAssessments && (
        <section className="lifecycle-safety-note">
          <strong>Archive first, delete second.</strong>
          <p>
            Archiving only hides an assessment from normal history. Permanent deletion is available
            from the archive and removes its database findings, scanner execution records,
            generated reports, and stored raw scanner artifacts while retaining a deletion audit
            event.
          </p>
        </section>
      )}

      {canDeleteAssessments && (
        <ConfirmDialog
          open={pendingDelete}
          title={`Permanently delete ${selectedIds.size} archived assessment${pluralize(selectedIds.size, '')}?`}
          description="This removes findings, tool runs, reports, and stored raw scanner artifacts. This action cannot be undone."
          confirmLabel="Permanently delete"
          busy={actionBusy}
          onCancel={() => setPendingDelete(false)}
          onConfirm={() => runLifecycleAction('delete')}
        />
      )}
    </>
  )
}
