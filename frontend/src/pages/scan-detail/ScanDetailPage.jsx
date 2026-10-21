import { progressWidthClass } from '../../utils/progressWidthClass'
import { useCallback, useEffect, useMemo, useState } from 'react'
import { Link, useParams, useSearchParams } from 'react-router'

import { getScan, getScanIssues, getScanSummary, getScanTelemetry, listScanReports } from '../../api/scans'
import {
  cancelAssessment,
  getAssessment,
} from '../../api/assessments'
import { getTarget } from '../../api/targets'
import { isDemoUser } from '../../auth/demo-access'
import { PERMISSIONS } from '../../auth/rbac'
import { useAuth } from '../../auth/useAuth'
import BrandMark from '../../components/BrandMark'
import { Breadcrumbs, ErrorAlert, SkeletonList, Spinner } from '../../components/ui'
import { formatDate, formatElapsed, statusBadgeClass } from '../../lib/format'
import FindingsTab from './FindingsTab'
import {
  ACTIVE_SCAN_STATUSES,
  ISSUES_PER_PAGE,
  VALID_TABS,
  getOutcomeLabel,
  issueHasTool,
  issueMatchesSearch,
  issueSourceToolNames,
  normalize,
  requiresManualValidation,
} from './helpers'
import OverviewTab from './OverviewTab'
import { AssessmentTab } from './parts'
import ReportsTab from './ReportsTab'
import TelemetryTab from './TelemetryTab'

export default function ScanDetailPage() {
  const { scanId } = useParams()
  const { user, hasPermission } = useAuth()
  const isDemo = isDemoUser(user)

  const canCancelAssessment =
    !isDemo
    && hasPermission(
      PERMISSIONS.ASSESSMENT_CANCEL,
    )

  const canGenerateReports =
    isDemo
    || hasPermission(
      PERMISSIONS.REPORT_GENERATE,
    )

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
  const [searchParams, setSearchParams] = useSearchParams()

  const [scan, setScan] = useState(null)
  const [telemetry, setTelemetry] = useState(null)
  const [assessmentRuntime, setAssessmentRuntime] = useState(null)
  const [target, setTarget] = useState(null)
  const [summary, setSummary] = useState(null)
  const [issues, setIssues] = useState(null)
  const [reports, setReports] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [supplementalError, setSupplementalError] = useState('')
  const [cancelBusy, setCancelBusy] = useState(false)
  const [clock, setClock] = useState(Date.now())

  const [issueSearch, setIssueSearch] = useState('')
  const [classificationFilter, setClassificationFilter] = useState('security_issue')
  const [severityFilter, setSeverityFilter] = useState('all')
  const [toolFilter, setToolFilter] = useState('all')
  const [confidenceFilter, setConfidenceFilter] = useState('all')
  const [validationFilter, setValidationFilter] = useState('all')
  const [issuePage, setIssuePage] = useState(1)

  const requestedTab = normalize(searchParams.get('tab'))
  const activeTab = VALID_TABS.includes(requestedTab) ? requestedTab : 'overview'

  const loadScan = useCallback(async () => {
    try {
      const [scanResult, telemetryResult] = await Promise.all([
        getScan( scanId),
        getScanTelemetry( scanId),
      ])

      setScan(scanResult)
      setTelemetry(telemetryResult)

      if (
        scanResult.engine_version === 'v2'
      ) {
        const assessmentResult = await getAssessment(

          scanId,
        )

        setAssessmentRuntime(
          assessmentResult,
        )
      } else {
        setAssessmentRuntime(
          null,
        )
      }

      setError('')

      if (!target || target.id !== scanResult.target_id) {
        const targetResult = await getTarget( scanResult.target_id)
        setTarget(targetResult)
      }
    } catch (requestError) {
      setError(requestError.message || 'Unable to load assessment.')
    } finally {
      setLoading(false)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [scanId, target])

  const loadCompletedData = useCallback(async () => {
    setSupplementalError('')

    try {
      const [summaryResult, issueResult, reportResult] = await Promise.all([
        getScanSummary( scanId),
        getScanIssues( scanId, { limit: 100 }),
        listScanReports( scanId, 'all'),
      ])

      setSummary(summaryResult)
      setIssues(issueResult)
      setReports(reportResult)
    } catch (requestError) {
      setSupplementalError(requestError.message || 'Unable to load findings and report metadata.')
    }
  }, [scanId])

  useEffect(() => {
    loadScan()
  }, [loadScan])

  const isLive = Boolean(scan && ACTIVE_SCAN_STATUSES.includes(scan.status))

  useEffect(() => {
    if (!isLive) return undefined

    const poller = window.setInterval(loadScan, 2000)
    return () => window.clearInterval(poller)
  }, [isLive, loadScan])

  useEffect(() => {
    if (!isLive) return undefined

    const timer = window.setInterval(() => setClock(Date.now()), 1000)
    return () => window.clearInterval(timer)
  }, [isLive])

  useEffect(() => {
    if (scan?.status === 'completed') {
      loadCompletedData()
    }
  }, [scan?.status, loadCompletedData])

  useEffect(() => {
    setIssuePage(1)
  }, [issueSearch, classificationFilter, severityFilter, toolFilter, confidenceFilter, validationFilter])

  const elapsedSeconds = useMemo(() => {
    if (!scan?.started_at) return 0

    const start = new Date(scan.started_at).getTime()
    const end = scan.completed_at ? new Date(scan.completed_at).getTime() : clock

    return Math.max(0, (end - start) / 1000)
  }, [scan, clock])

  const availableTools = useMemo(() => {
    const toolNames = new Set(
      (issues?.items || []).flatMap((issue) => issueSourceToolNames(issue)).filter(Boolean),
    )

    return [...toolNames].sort()
  }, [issues])

  const filteredIssues = useMemo(() => {
    const issueItems = issues?.items || []

    return issueItems.filter((issue) => {
      if (!issueMatchesSearch(issue, issueSearch)) return false

      if (classificationFilter !== 'all' && normalize(issue.classification) !== classificationFilter) {
        return false
      }

      if (severityFilter !== 'all' && normalize(issue.severity) !== severityFilter) {
        return false
      }

      if (toolFilter !== 'all' && !issueHasTool(issue, toolFilter)) {
        return false
      }

      if (confidenceFilter !== 'all' && normalize(issue.confidence) !== confidenceFilter) {
        return false
      }

      const needsValidation = requiresManualValidation(issue)

      if (validationFilter === 'required' && !needsValidation) return false
      if (validationFilter === 'standard' && needsValidation) return false

      return true
    })
  }, [issues, issueSearch, classificationFilter, severityFilter, toolFilter, confidenceFilter, validationFilter])

  const totalIssuePages = Math.max(1, Math.ceil(filteredIssues.length / ISSUES_PER_PAGE))

  const pagedIssues = useMemo(() => {
    const start = (issuePage - 1) * ISSUES_PER_PAGE
    return filteredIssues.slice(start, start + ISSUES_PER_PAGE)
  }, [filteredIssues, issuePage])

  useEffect(() => {
    if (issuePage > totalIssuePages) {
      setIssuePage(totalIssuePages)
    }
  }, [issuePage, totalIssuePages])

  async function handleCancelAssessment() {
    if (
      !canCancelAssessment
      || !isLive
      || cancelBusy
    ) {
      return
    }

    setCancelBusy(true)
    setSupplementalError('')

    try {
      await cancelAssessment(
        scanId,
      )

      await loadScan()
    } catch (requestError) {
      setSupplementalError(
        requestError.message
        || 'Unable to cancel assessment.',
      )
    } finally {
      setCancelBusy(false)
    }
  }


  function selectTab(tab) {
    setSearchParams({ tab })
  }

  if (loading) {
    return (
      <div
        className="assessment-loading"
        role="status"
        aria-label="Connecting to assessment telemetry"
      >
        <SkeletonList
          rows={4}
          label="Connecting to assessment telemetry"
        />
      </div>
    )
  }

  if (error || !scan || !telemetry) {
    return (
      <section className="content-card">
        <ErrorAlert message={error || 'Assessment telemetry is unavailable.'} />
        <Link to="/scans" className="back-link">
          ← Back to Assessments
        </Link>
      </section>
    )
  }

  const correlatedResultCount = issues?.total_groups ?? summary?.distinct_issues ?? 0
  const findingsCount = summary?.security_issue_count ?? correlatedResultCount

  const classificationCounts = {
    security_issue: summary?.security_issue_count ?? 0,
    attack_surface: summary?.attack_surface_count ?? 0,
    observation: summary?.observation_count ?? 0,
    limitation: summary?.limitation_count ?? 0,
  }

  const workspaceLabel =
    activeTab.charAt(0).toUpperCase()
    + activeTab.slice(1)

  const breadcrumbs = [
    {
      label: 'Assessments',
      to: '/scans',
    },
    {
      label:
        target?.hostname
        || 'Target',
      to: target?.id
        ? `/targets/${target.id}`
        : '/targets',
    },
    {
      label: scan.id.slice(0, 8),
      to:
        `/scans/${scan.id}?tab=overview`,
    },
    {
      label: workspaceLabel,
    },
  ]

  return (
    <div className="assessment-page">
      <div className="assessment-grid-bg" aria-hidden="true" />
      <div className="assessment-scanline" aria-hidden="true" />

      <div className="assessment-breadcrumbs">
        <Breadcrumbs
          items={breadcrumbs}
        />
      </div>

      <div className="assessment-nav">
        <Link to="/scans" className="back-link">
          ← Back to Assessments
        </Link>
        <span className={statusBadgeClass(scan.status)}>{scan.status}</span>

        {isLive
          && canCancelAssessment && (
            <button
              type="button"
              className="secondary-button compact-button"
              disabled={cancelBusy}
              aria-busy={cancelBusy}
              onClick={handleCancelAssessment}
            >
              {cancelBusy && (
                <Spinner label="Cancelling assessment" />
              )}
              <span>
                {cancelBusy
                  ? 'Cancelling...'
                  : 'Cancel assessment'}
              </span>
            </button>
          )}
      </div>

      {scan.archived_at && (
        <div className="archived-assessment-banner">
          <strong>Archived assessment</strong>
          <span>
            Archived {formatDate(scan.archived_at)}. Evidence remains readable, but new report generation is
            disabled until the assessment is restored.
          </span>
        </div>
      )}

      <section className="assessment-hero">
        <div className="assessment-hero-glow" />

        <div className="assessment-identity">
          <BrandMark size="md" showText={false} className="assessment-brand-mark" />

          <div>
            <p className="scan-kicker">{isLive ? 'LIVE ASSESSMENT' : 'ASSESSMENT RECORD'}</p>
            <h1>{target?.hostname || 'BEACON Target'}</h1>
            <p className="assessment-subtitle">
              {assessmentRuntime
                ? `${assessmentRuntime.profile || 'Engine v2'} ${assessmentRuntime.assessment_mode || 'web'} Assessment`
                : 'Legacy Web Assessment'}
              {' · '}
              <code>{scan.id}</code>
            </p>
          </div>
        </div>

        <div className="assessment-outcome">
          <span className={`outcome-badge outcome-${telemetry.outcome}`}>
            <span className="outcome-dot" />
            {getOutcomeLabel(telemetry.outcome)}
          </span>
          <span className="elapsed-time">{formatElapsed(elapsedSeconds)}</span>
        </div>

        <div className="workflow-summary">
          <div className="workflow-heading">
            <div>
              <span>
                {assessmentRuntime
                  ? 'Execution state'
                  : 'Workflow completion'}
              </span>
              <small>
                {assessmentRuntime
                  ?.current_stage_label
                  || telemetry.active_stage_label}
              </small>
            </div>
            <strong>
              {assessmentRuntime
                ? 'Stage-based'
                : `${telemetry.workflow_progress}%`}
            </strong>
          </div>

          <div className="workflow-track">
            <div
              className={[
                assessmentRuntime
                  ? 'workflow-fill engine-v2-workflow-fill'
                  : 'workflow-fill',
                progressWidthClass(
                  assessmentRuntime
                    ? 0
                    : telemetry.workflow_progress,
                ),
              ].join(' ')}
            />
          </div>
        </div>
      </section>

      <nav className="assessment-tabs" role="tablist" aria-label="Assessment workspace">
        <AssessmentTab active={activeTab === 'overview'} label="Overview" onClick={() => selectTab('overview')} />
        <AssessmentTab
          active={activeTab === 'findings'}
          label="Findings"
          count={findingsCount}
          onClick={() => selectTab('findings')}
        />
        <AssessmentTab
          active={activeTab === 'telemetry'}
          label="Telemetry"
          count={telemetry.tool_runs.length}
          live={isLive}
          onClick={() => selectTab('telemetry')}
        />
        <AssessmentTab
          active={activeTab === 'reports'}
          label="Reports"
          count={reports.length}
          onClick={() => selectTab('reports')}
        />
      </nav>

      <ErrorAlert message={supplementalError} className="page-message" />

      {activeTab === 'overview' && (
        <OverviewTab
              scan={scan}
              telemetry={telemetry}
              target={target}
              summary={summary}
              assessmentRuntime={assessmentRuntime}
            />
      )}

      {activeTab === 'findings' && (
        <FindingsTab
          scan={scan}
          issues={issues}
          correlatedResultCount={correlatedResultCount}
          classificationCounts={classificationCounts}
          availableTools={availableTools}
          filteredIssues={filteredIssues}
          pagedIssues={pagedIssues}
          issuePage={issuePage}
          totalIssuePages={totalIssuePages}
          setIssuePage={setIssuePage}
          filters={{
            issueSearch,
            setIssueSearch,
            classificationFilter,
            setClassificationFilter,
            severityFilter,
            setSeverityFilter,
            toolFilter,
            setToolFilter,
            confidenceFilter,
            setConfidenceFilter,
            validationFilter,
            setValidationFilter,
          }}
        />
      )}

      {activeTab === 'telemetry' && (
            <TelemetryTab
              scan={scan}
              telemetry={telemetry}
              isLive={isLive}
              assessmentRuntime={assessmentRuntime}
            />
          )}

      {activeTab === 'reports' && (
        <ReportsTab
          scan={scan}
          scanId={scanId}
          reports={reports}
          onReportsChanged={loadCompletedData}
          canGenerateReports={canGenerateReports}
          canLifecycleReports={canLifecycleReports}
          canDeleteReports={canDeleteReports}
        />
      )}
    </div>
  )
}
