import {
  useCallback,
  useEffect,
  useMemo,
  useState,
} from 'react'
import { Link } from 'react-router'

import { getFindingPosture } from '../../api/findings'
import { listReports } from '../../api/reports'
import { listScans } from '../../api/scans'
import { listTargets } from '../../api/targets'
import { useAuth } from '../../auth/useAuth'
import {
  Card,
  EmptyState,
  ErrorAlert,
  PageHeader,
  Skeleton,
  SkeletonList,
  StatusBadge,
} from '../../components/ui'
import { formatDate } from '../../lib/format'
import { buildFindingsPath } from '../findings/helpers'

const EMPTY_POSTURE = {
  active: 0,
  new: 0,
  persisting: 0,
  regressed: 0,
  resolved: 0,
  awaiting_triage: 0,
  awaiting_assignment: 0,
  in_remediation: 0,
  awaiting_retest: 0,
  risk_accepted: 0,
  false_positive: 0,
  severity_breakdown: {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    informational: 0,
  },
}


export default function DashboardPage() {
  const { user } = useAuth()

  const [targets, setTargets] =
    useState([])
  const [scans, setScans] =
    useState([])
  const [reports, setReports] =
    useState([])
  const [posture, setPosture] =
    useState(EMPTY_POSTURE)
  const [loading, setLoading] =
    useState(true)
  const [error, setError] =
    useState('')

  const loadDashboard =
    useCallback(async () => {
      setLoading(true)
      setError('')

      try {
        const [
          targetResult,
          scanResult,
          reportResult,
          postureResult,
        ] = await Promise.all([
          listTargets(),
          listScans(),
          listReports( 'all'),
          getFindingPosture(),
        ])

        setTargets(targetResult)
        setScans(scanResult)
        setReports(reportResult)
        setPosture(postureResult)
      } catch (requestError) {
        setError(
          requestError.message
          || 'Unable to load dashboard data.',
        )
      } finally {
        setLoading(false)
      }
    }, [])

  useEffect(() => {
    loadDashboard()
  }, [loadDashboard])

  const metrics = useMemo(() => {
    const active = scans.filter(
      (scan) =>
        [
          'pending',
          'queued',
          'running',
          'processing',
        ].includes(scan.status),
    ).length

    return {
      targets: targets.length,
      assessments: scans.length,
      active,
      reports: reports.length,
    }
  }, [
    targets,
    scans,
    reports,
  ])

  const recentScans = useMemo(
    () =>
      [...scans]
        .sort(
          (left, right) =>
            new Date(
              right.created_at,
            ).getTime()
            - new Date(
              left.created_at,
            ).getTime(),
        )
        .slice(0, 5),
    [scans],
  )

  const recentReports = useMemo(
    () =>
      [...reports]
        .sort(
          (left, right) =>
            new Date(
              right.generated_at,
            ).getTime()
            - new Date(
              left.generated_at,
            ).getTime(),
        )
        .slice(0, 4),
    [reports],
  )

  const targetById = useMemo(
    () =>
      new Map(
        targets.map(
          (target) => [
            target.id,
            target,
          ],
        ),
      ),
    [targets],
  )

  const unverifiedTargets =
    useMemo(
      () =>
        targets.filter(
          (target) =>
            target.verification_status
            !== 'verified',
        ),
      [targets],
    )

  const failedAssessments =
    useMemo(
      () =>
        scans.filter(
          (scan) =>
            scan.status === 'failed',
        ),
      [scans],
    )

  const attentionCount =
    unverifiedTargets.length
    + failedAssessments.length

  return (
    <>
      <PageHeader
        eyebrow="SECURITY OVERVIEW"
        title={`Welcome back, ${user?.full_name?.split(' ')[0] || 'operator'}.`}
        description="Current posture across registered targets, assessments, and generated evidence."
        actions={
          <>
            <Link
              className="secondary-button"
              to={buildFindingsPath()}
            >
              View findings
            </Link>

            <Link
              className="secondary-button"
              to="/reports"
            >
              View reports
            </Link>

            <Link
              className="primary-button inline-button"
              to="/scans/new"
            >
              + New Assessment
            </Link>
          </>
        }
      />

      <ErrorAlert
        message={error}
        className="page-message"
      />

      <section className="metric-grid dashboard-metrics">
        <Link
          className="metric-card metric-accent metric-card-link"
          to="/targets"
          aria-label="View targets"
        >
          <span>Targets</span>

          <strong>
            {loading
              ? <Skeleton variant="metric" />
              : metrics.targets}
          </strong>

          <p>
            Registered assessment targets
          </p>
        </Link>

        <Link
          className="metric-card metric-card-link"
          to="/scans"
          aria-label="View assessments"
        >
          <span>Assessments</span>

          <strong>
            {loading
              ? <Skeleton variant="metric" />
              : metrics.assessments}
          </strong>

          <p>
            Assessment history
          </p>
        </Link>

        <Link
          className="metric-card metric-card-link"
          to="/scans"
          aria-label="View active assessments"
        >
          <span>Active assessments</span>

          <strong>
            {loading
              ? <Skeleton variant="metric" />
              : metrics.active}
          </strong>

          <p>
            Queued or currently running
          </p>
        </Link>

        <Link
          className="metric-card metric-card-link"
          to="/reports"
          aria-label="View reports"
        >
          <span>Reports</span>

          <strong>
            {loading
              ? <Skeleton variant="metric" />
              : metrics.reports}
          </strong>

          <p>
            Generated report artifacts
          </p>
        </Link>
      </section>

      <Card
        className="dashboard-posture-card"
        eyebrow="VULNERABILITY POSTURE"
        title="Security posture"
        headingActions={
          <Link
            className="text-link"
            to={buildFindingsPath()}
          >
            Open Findings →
          </Link>
        }
      >
        <div className="posture-primary-grid">
          <Link
            className="posture-metric posture-metric-primary"
            to={buildFindingsPath()}
          >
            <span>
              Active findings
            </span>

            <strong>
              {loading
                ? <Skeleton variant="metric" />
                : posture.active}
            </strong>

            <small>
              Findings requiring vulnerability-management action
            </small>
          </Link>

          <Link
            className="posture-metric"
            to={buildFindingsPath({
              observation_state: 'NEW',
            })}
          >
            <span>
              New observations
            </span>

            <strong>
              {loading
                ? <Skeleton variant="metric" />
                : posture.new}
            </strong>

            <small>
              First valid observation
            </small>
          </Link>

          <Link
            className="posture-metric"
            to={buildFindingsPath({
              observation_state: 'PERSISTING',
            })}
          >
            <span>
              Persisting
            </span>

            <strong>
              {loading
                ? <Skeleton variant="metric" />
                : posture.persisting}
            </strong>

            <small>
              Still present across assessments
            </small>
          </Link>

          <Link
            className="posture-metric posture-metric-attention"
            to={buildFindingsPath({
              observation_state: 'REGRESSED',
            })}
          >
            <span>
              Regressed
            </span>

            <strong>
              {loading
                ? <Skeleton variant="metric" />
                : posture.regressed}
            </strong>

            <small>
              Resolved previously and observed again
            </small>
          </Link>

          <Link
            className="posture-metric"
            to={buildFindingsPath({
              observation_state: 'RESOLVED',
            })}
          >
            <span>
              Resolved
            </span>

            <strong>
              {loading
                ? <Skeleton variant="metric" />
                : posture.resolved}
            </strong>

            <small>
              Verified by valid assessment evidence
            </small>
          </Link>
        </div>

        <div className="posture-detail-grid">
          <section
            className="posture-queue"
            aria-labelledby="posture-queue-heading"
          >
            <div className="posture-section-heading">
              <p className="eyebrow">
                REMEDIATION QUEUES
              </p>

              <h3 id="posture-queue-heading">
                Workflow
              </h3>
            </div>

            <div className="posture-queue-list">
              <Link
                to={buildFindingsPath({
                  lifecycle_state: 'NEW',
                })}
              >
                <span>
                  Awaiting triage
                </span>

                <strong>
                  {loading
                    ? <Skeleton variant="metric" />
                    : posture.awaiting_triage}
                </strong>
              </Link>

              <Link
                to={buildFindingsPath({
                  lifecycle_state: 'TRIAGED',
                })}
              >
                <span>
                  Awaiting assignment
                </span>

                <strong>
                  {loading
                    ? <Skeleton variant="metric" />
                    : posture.awaiting_assignment}
                </strong>
              </Link>

              <Link
                to={buildFindingsPath({
                  lifecycle_state: 'IN_REMEDIATION',
                })}
              >
                <span>
                  In remediation
                </span>

                <strong>
                  {loading
                    ? <Skeleton variant="metric" />
                    : posture.in_remediation}
                </strong>
              </Link>

              <Link
                to={buildFindingsPath({
                  lifecycle_state: 'READY_FOR_RETEST',
                })}
              >
                <span>
                  Awaiting retest
                </span>

                <strong>
                  {loading
                    ? <Skeleton variant="metric" />
                    : posture.awaiting_retest}
                </strong>
              </Link>

              <Link
                to={buildFindingsPath({
                  disposition: 'RISK_ACCEPTED',
                })}
              >
                <span>
                  Risk accepted
                </span>

                <strong>
                  {loading
                    ? <Skeleton variant="metric" />
                    : posture.risk_accepted}
                </strong>
              </Link>

              <Link
                to={buildFindingsPath({
                  disposition: 'FALSE_POSITIVE',
                })}
              >
                <span>
                  False positive
                </span>

                <strong>
                  {loading
                    ? <Skeleton variant="metric" />
                    : posture.false_positive}
                </strong>
              </Link>
            </div>
          </section>

          <section
            className="posture-severity"
            aria-labelledby="posture-severity-heading"
          >
            <div className="posture-section-heading">
              <p className="eyebrow">
                ACTIVE EXPOSURE
              </p>

              <h3 id="posture-severity-heading">
                Severity breakdown
              </h3>
            </div>

            <div className="posture-severity-list">
              {[
                'critical',
                'high',
                'medium',
                'low',
                'informational',
              ].map(
                (severity) => (
                  <Link
                    key={severity}
                    to={buildFindingsPath({
                      severity,
                    })}
                  >
                    <StatusBadge
                      value={severity}
                      variant="severity"
                    />

                    <strong>
                      {loading
                        ? <Skeleton variant="metric" />
                        : (
                          posture
                            .severity_breakdown
                            ?.[severity]
                          ?? 0
                        )}
                    </strong>
                  </Link>
                ),
              )}
            </div>
          </section>
        </div>
      </Card>

      <section className="dashboard-grid">
        <Card
          as="article"
          className="recent-activity-card"
          eyebrow="RECENT ACTIVITY"
          title="Latest assessments"
          headingActions={
            <Link
              className="text-link"
              to="/scans"
            >
              View all →
            </Link>
          }
        >
          {loading && (
            <SkeletonList
              rows={3}
              label="Loading assessments"
              className="dashboard-skeleton-list"
            />
          )}

          {!loading
            && recentScans.length === 0 && (
              <EmptyState
                title="No assessments yet"
                message="Launch an assessment to populate this workspace."
              />
            )}

          {!loading
            && recentScans.length > 0 && (
              <div className="activity-list">
                {recentScans.map(
                  (scan) => {
                    const target =
                      targetById.get(
                        scan.target_id,
                      )

                    return (
                      <Link
                        className="activity-row"
                        key={scan.id}
                        to={`/scans/${scan.id}`}
                      >
                        <div className="activity-icon">
                          ↗
                        </div>

                        <div className="activity-main">
                          <strong>
                            {target?.hostname
                              || 'Unknown target'}
                          </strong>

                          <span>
                            {formatDate(
                              scan.created_at,
                            )}
                          </span>
                        </div>

                        <div className="activity-progress">
                          <StatusBadge
                            value={scan.status}
                          />

                          <small>
                            {scan.progress}%
                          </small>
                        </div>
                      </Link>
                    )
                  },
                )}
              </div>
            )}
        </Card>

        <Card
          as="aside"
          className="dashboard-attention-card"
          eyebrow="PRIORITY"
          title="Needs Attention"
          headingActions={
            <span className="section-count">
              {loading
                ? <Skeleton variant="metric" />
                : attentionCount}
            </span>
          }
        >
          {loading && (
            <SkeletonList
              rows={3}
              label="Checking workspace state"
              className="dashboard-skeleton-list"
            />
          )}

          {!loading
            && attentionCount === 0 && (
              <EmptyState
                title="Nothing requires attention"
                message="No unverified targets or failed assessments are currently visible."
              />
            )}

          {!loading
            && attentionCount > 0 && (
              <div className="attention-list">
                {unverifiedTargets.map(
                  (target) => (
                    <Link
                      key={target.id}
                      className="attention-row"
                      to={`/targets/${target.id}?tab=verification`}
                    >
                      <div>
                        <span>
                          TARGET
                        </span>

                        <strong>
                          {target.hostname}
                        </strong>

                        <small>
                          Ownership verification required
                        </small>
                      </div>

                      <span
                        className="attention-arrow"
                        aria-hidden="true"
                      >
                        →
                      </span>
                    </Link>
                  ),
                )}

                {failedAssessments.map(
                  (scan) => {
                    const target =
                      targetById.get(
                        scan.target_id,
                      )

                    return (
                      <Link
                        key={scan.id}
                        className="attention-row"
                        to={`/scans/${scan.id}`}
                      >
                        <div>
                          <span>
                            ASSESSMENT
                          </span>

                          <strong>
                            {target?.hostname
                              || 'Unknown target'}
                          </strong>

                          <small>
                            Assessment failed
                          </small>
                        </div>

                        <span
                          className="attention-arrow"
                          aria-hidden="true"
                        >
                          →
                        </span>
                      </Link>
                    )
                  },
                )}
              </div>
            )}
        </Card>
      </section>

      <Card
        className="dashboard-reports-card"
        eyebrow="RECENT REPORTS"
        title="Recent Reports"
        headingActions={
          <Link
            className="text-link"
            to="/reports"
          >
            View all →
          </Link>
        }
      >
        {loading && (
          <SkeletonList
            rows={3}
            label="Loading reports"
            className="dashboard-skeleton-list"
          />
        )}

        {!loading
          && recentReports.length === 0 && (
            <EmptyState
              title="No reports yet"
              message="Generated assessment reports will appear here."
            />
          )}

        {!loading
          && recentReports.length > 0 && (
            <div className="dashboard-report-list">
              {recentReports.map(
                (report) => (
                  <Link
                    className="dashboard-report-row"
                    key={report.id}
                    to={`/scans/${report.scan_id}?tab=reports`}
                  >
                    <div className="dashboard-report-format">
                      {report.format.toUpperCase()}
                    </div>

                    <div className="dashboard-report-main">
                      <strong>
                        {report.target_hostname}
                      </strong>

                      <span>
                        Assessment{' '}
                        {String(
                          report.scan_id,
                        ).slice(0, 8)}
                      </span>
                    </div>

                    <div className="dashboard-report-meta">
                      <span>
                        {formatDate(
                          report.generated_at,
                        )}
                      </span>

                      {report.archived_at && (
                        <small>
                          Archived
                        </small>
                      )}
                    </div>

                    <span
                      className="dashboard-report-arrow"
                      aria-hidden="true"
                    >
                      →
                    </span>
                  </Link>
                ),
              )}
            </div>
          )}
      </Card>
    </>
  )
}
