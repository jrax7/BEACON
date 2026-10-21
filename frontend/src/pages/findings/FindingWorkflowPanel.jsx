import {
  useCallback,
  useEffect,
  useMemo,
  useState,
} from 'react'

import { useNavigate } from 'react-router'

import {
  clearFindingDisposition,
  createFindingRetest,
  getFindingHistory,
  listFindingRetests,
  listFindings,
  setFindingDisposition,
  updateFindingAssignee,
  updateFindingLifecycle,
  updateFindingRemediationOwner,
} from '../../api/findings'
import {
  listOrganizationMembers,
} from '../../api/organization'
import {
  isDemoUser,
} from '../../auth/demo-access'
import {
  PERMISSIONS,
  hasPermission,
} from '../../auth/rbac'
import {
  useAuth,
} from '../../auth/useAuth'
import {
  ErrorAlert,
  Select,
  SkeletonList,
  Spinner,
  StatusBadge,
  SuccessAlert,
  Textarea,
} from '../../components/ui'
import FindingLifecycleRail from './FindingLifecycleRail'
import {
  formatDate,
} from '../../lib/format'


const TRANSITIONS = {
  NEW: [
    'TRIAGED',
  ],
  TRIAGED: [
    'NEW',
    'ASSIGNED',
  ],
  ASSIGNED: [
    'TRIAGED',
    'IN_REMEDIATION',
  ],
  IN_REMEDIATION: [
    'ASSIGNED',
    'READY_FOR_RETEST',
  ],
  READY_FOR_RETEST: [
    'IN_REMEDIATION',
  ],
  RESOLVED: [
    'IN_REMEDIATION',
  ],
}


const DISPOSITIONS = [
  'FALSE_POSITIVE',
  'RISK_ACCEPTED',
  'DUPLICATE',
]


function humanize(value) {
  return String(
    value || '',
  )
    .toLowerCase()
    .split('_')
    .map(
      (part) =>
        part
          ? (
              part[0].toUpperCase()
              + part.slice(1)
            )
          : part,
    )
    .join(' ')
}


function memberLabel(member) {
  const name =
    member?.full_name?.trim()

  const email =
    member?.email?.trim()

  if (name && email) {
    return `${name} · ${email}`
  }

  return (
    name
    || email
    || member?.user_id
    || 'Unknown member'
  )
}


export default function FindingWorkflowPanel({
  finding,
  findingId,
  onFindingChange,
}) {
  const {
    user,
  } = useAuth()

  const navigate =
    useNavigate()

  const canManage =
    !isDemoUser(user)
    && hasPermission(
      user,
      PERMISSIONS.FINDING_MANAGE,
    )

  const [
    members,
    setMembers,
  ] = useState([])

  const [
    history,
    setHistory,
  ] = useState([])

  const [
    retests,
    setRetests,
  ] = useState([])

  const [
    duplicateCandidates,
    setDuplicateCandidates,
  ] = useState([])

  const [
    loading,
    setLoading,
  ] = useState(true)

  const [
    busy,
    setBusy,
  ] = useState(false)

  const [
    retestBusy,
    setRetestBusy,
  ] = useState(false)

  const [
    error,
    setError,
  ] = useState('')

  const [
    success,
    setSuccess,
  ] = useState('')

  const [
    nextLifecycle,
    setNextLifecycle,
  ] = useState('')

  const [
    lifecycleReason,
    setLifecycleReason,
  ] = useState('')

  const [
    assignee,
    setAssignee,
  ] = useState(
    finding.assignee_user_id
    || '',
  )

  const [
    remediationOwner,
    setRemediationOwner,
  ] = useState(
    finding.remediation_owner_user_id
    || '',
  )

  const [
    disposition,
    setDisposition,
  ] = useState(
    finding.disposition
    || '',
  )

  const [
    dispositionReason,
    setDispositionReason,
  ] = useState(
    finding.disposition_reason
    || '',
  )

  const [
    duplicateFindingId,
    setDuplicateFindingId,
  ] = useState(
    finding.duplicate_of_finding_id
    || '',
  )

  const allowedTransitions =
    TRANSITIONS[
      finding.lifecycle_state
      || 'NEW'
    ] || []

  const memberById = useMemo(
    () =>
      new Map(
        members.map(
          (member) => [
            member.user_id,
            member,
          ],
        ),
      ),
    [
      members,
    ],
  )

  const loadWorkflow =
    useCallback(
      async () => {
        setLoading(true)
        setError('')

        try {
          const [
            historyResult,
            retestResult,
            memberResult,
            candidateResult,
          ] = await Promise.all([
            getFindingHistory(
              findingId,
            ),
            listFindingRetests(
              findingId,
            ),
            listOrganizationMembers(),
            listFindings({
              limit: 100,
            }),
          ])

          setHistory(
            historyResult?.events
            || [],
          )

          setRetests(
            retestResult?.items
            || [],
          )

          setMembers(
            Array.isArray(
              memberResult,
            )
              ? memberResult
              : [],
          )

          setDuplicateCandidates(
            (
              candidateResult?.items
              || []
            ).filter(
              (item) =>
                item.id !== findingId
                && item.primary_finding_id,
            ),
          )
        } catch (requestError) {
          setError(
            requestError.message
            || 'Unable to load finding workflow.',
          )
        } finally {
          setLoading(false)
        }
      },
      [
        findingId,
      ],
    )

  useEffect(() => {
    loadWorkflow()
  }, [
    loadWorkflow,
  ])

  useEffect(() => {
    setAssignee(
      finding.assignee_user_id
      || '',
    )

    setRemediationOwner(
      finding.remediation_owner_user_id
      || '',
    )

    setDisposition(
      finding.disposition
      || '',
    )

    setDispositionReason(
      finding.disposition_reason
      || '',
    )

    setDuplicateFindingId(
      finding.duplicate_of_finding_id
      || '',
    )

    setNextLifecycle('')
  }, [
    finding.assignee_user_id,
    finding.remediation_owner_user_id,
    finding.disposition,
    finding.disposition_reason,
    finding.duplicate_of_finding_id,
    finding.lifecycle_state,
  ])

  async function mutate(
    action,
    message,
  ) {
    setBusy(true)
    setError('')
    setSuccess('')

    try {
      const updated =
        await action()

      if (updated) {
        onFindingChange(
          updated,
        )
      }

      setSuccess(
        message,
      )

      await loadWorkflow()
    } catch (requestError) {
      setError(
        requestError.message
        || 'Unable to update finding workflow.',
      )
    } finally {
      setBusy(false)
    }
  }

  function handleLifecycleSubmit(event) {
    event.preventDefault()

    if (!nextLifecycle) {
      return
    }

    mutate(
      () =>
        updateFindingLifecycle(
          findingId,
          nextLifecycle,
          lifecycleReason,
        ),
      `Lifecycle moved to ${humanize(
        nextLifecycle,
      )}.`,
    )
  }

  function handleAssigneeSubmit(event) {
    event.preventDefault()

    mutate(
      () =>
        updateFindingAssignee(
          findingId,
          assignee,
        ),
      assignee
        ? 'Assignee updated.'
        : 'Assignee cleared.',
    )
  }

  function handleOwnerSubmit(event) {
    event.preventDefault()

    mutate(
      () =>
        updateFindingRemediationOwner(
          findingId,
          remediationOwner,
        ),
      remediationOwner
        ? 'Remediation owner updated.'
        : 'Remediation owner cleared.',
    )
  }

  function handleDispositionSubmit(event) {
    event.preventDefault()

    if (
      !disposition
      || !dispositionReason.trim()
    ) {
      setError(
        'Disposition and reason are required.',
      )
      return
    }

    if (
      disposition === 'DUPLICATE'
      && !duplicateFindingId
    ) {
      setError(
        'Select the canonical finding for a duplicate disposition.',
      )
      return
    }

    mutate(
      () =>
        setFindingDisposition(
          findingId,
          disposition,
          dispositionReason,
          disposition === 'DUPLICATE'
            ? duplicateFindingId
            : null,
        ),
      'Disposition updated.',
    )
  }

  function handleDispositionClear() {
    if (!dispositionReason.trim()) {
      setError(
        'Enter a reason before clearing the disposition.',
      )
      return
    }

    mutate(
      () =>
        clearFindingDisposition(
          findingId,
          dispositionReason,
        ),
      'Disposition cleared.',
    )
  }

  async function handleRetest() {
    setBusy(true)
    setRetestBusy(true)
    setError('')
    setSuccess('')

    try {
      if (!finding.target_id) {
        throw new Error(
          'Finding target context is unavailable.',
        )
      }

      const retest =
        await createFindingRetest(
          findingId,
        )

      const parameters =
        new URLSearchParams({
          retest_id:
            retest.id,
          finding_id:
            findingId,
          target_id:
            finding.target_id,
        })

      navigate(
        `/scans/new?${parameters.toString()}`,
      )
    } catch (requestError) {
      setError(
        requestError.message
        || 'Unable to start finding retest.',
      )

      setBusy(false)
      setRetestBusy(false)
    }
  }

  return (
    <section
      className="finding-detail-card finding-workflow-panel"
    >
      <div className="finding-section-heading">
        <div>
          <p className="eyebrow">
            REMEDIATION CONTROL
          </p>

          <h2>
            Workflow
          </h2>
        </div>

        <div className="finding-workflow-statuses">
          <StatusBadge
            value={
              finding.lifecycle_state
              || 'NEW'
            }
          />

          <StatusBadge
            value={
              finding.observation_state
              || 'NEW'
            }
          />
        </div>
      </div>

      <FindingLifecycleRail
        currentState={
          finding.lifecycle_state
          || 'NEW'
        }
      />

      {finding.observation_state === 'REGRESSED' && (
        <div
          className="finding-regressed-signal"
          role="status"
        >
          <span
            className="finding-regressed-marker"
            aria-hidden="true"
          >
            ↶
          </span>

          <div>
            <strong>Regression detected</strong>
            <p>
              This finding was previously resolved and has been observed again.
              It is back on the active remediation path for fresh validation.
            </p>
          </div>
        </div>
      )}

      {loading && (
        <div className="finding-workflow-loading">
          <SkeletonList
            rows={3}
            label="Loading workflow"
          />
        </div>
      )}

      {error && (
        <ErrorAlert
          message={error}
        />
      )}

      {success && (
        <SuccessAlert
          message={success}
        />
      )}

      {!canManage && (
        <p className="finding-muted">
          Your workspace role has read-only access to finding workflow.
        </p>
      )}

      {canManage && (
        <div className="finding-workflow-grid">
          <form
            className="finding-workflow-form"
            onSubmit={handleLifecycleSubmit}
          >
            <h3>
              Lifecycle
            </h3>

            <p className="finding-muted">
              Current:{' '}
              {humanize(
                finding.lifecycle_state
                || 'NEW',
              )}
            </p>

            <label>
              <span>
                Next state
              </span>

              <Select
                value={nextLifecycle}
                disabled={
                  busy
                  || allowedTransitions.length
                    === 0
                }
                onChange={(event) =>
                  setNextLifecycle(
                    event.target.value,
                  )
                }
              >
                <option value="">
                  Select transition
                </option>

                {allowedTransitions.map(
                  (state) => (
                    <option
                      key={state}
                      value={state}
                    >
                      {humanize(state)}
                    </option>
                  ),
                )}
              </Select>
            </label>

            <label>
              <span>
                Reason
              </span>

              <Textarea
                value={lifecycleReason}
                disabled={busy}
                placeholder="Optional lifecycle note"
                onChange={(event) =>
                  setLifecycleReason(
                    event.target.value,
                  )
                }
              />
            </label>

            <button
              type="submit"
              className="primary-button"
              disabled={
                busy
                || !nextLifecycle
              }
            >
              Update lifecycle
            </button>
          </form>

          <form
            className="finding-workflow-form"
            onSubmit={handleAssigneeSubmit}
          >
            <h3>
              Assignee
            </h3>

            <label>
              <span>
                Assigned analyst
              </span>

              <Select
                value={assignee}
                disabled={busy}
                onChange={(event) =>
                  setAssignee(
                    event.target.value,
                  )
                }
              >
                <option value="">
                  Unassigned
                </option>

                {members.map(
                  (member) => (
                    <option
                      key={member.user_id}
                      value={member.user_id}
                    >
                      {memberLabel(member)}
                    </option>
                  ),
                )}
              </Select>
            </label>

            <button
              type="submit"
              className="secondary-button"
              disabled={busy}
            >
              Save assignee
            </button>
          </form>

          <form
            className="finding-workflow-form"
            onSubmit={handleOwnerSubmit}
          >
            <h3>
              Remediation owner
            </h3>

            <label>
              <span>
                Owner
              </span>

              <Select
                value={remediationOwner}
                disabled={busy}
                onChange={(event) =>
                  setRemediationOwner(
                    event.target.value,
                  )
                }
              >
                <option value="">
                  No remediation owner
                </option>

                {members.map(
                  (member) => (
                    <option
                      key={member.user_id}
                      value={member.user_id}
                    >
                      {memberLabel(member)}
                    </option>
                  ),
                )}
              </Select>
            </label>

            <button
              type="submit"
              className="secondary-button"
              disabled={busy}
            >
              Save remediation owner
            </button>
          </form>

          <form
            className="finding-workflow-form"
            onSubmit={handleDispositionSubmit}
          >
            <h3>
              Disposition
            </h3>

            <label>
              <span>
                Disposition
              </span>

              <Select
                value={disposition}
                disabled={busy}
                onChange={(event) =>
                  setDisposition(
                    event.target.value,
                  )
                }
              >
                <option value="">
                  No disposition
                </option>

                {DISPOSITIONS.map(
                  (value) => (
                    <option
                      key={value}
                      value={value}
                    >
                      {humanize(value)}
                    </option>
                  ),
                )}
              </Select>
            </label>

            {disposition === 'DUPLICATE' && (
              <label>
                <span>
                  Canonical finding
                </span>

                <Select
                  value={duplicateFindingId}
                  disabled={busy}
                  onChange={(event) =>
                    setDuplicateFindingId(
                      event.target.value,
                    )
                  }
                >
                  <option value="">
                    Select canonical finding
                  </option>

                  {duplicateCandidates.map(
                    (candidate) => (
                      <option
                        key={candidate.id}
                        value={
                          candidate.primary_finding_id
                        }
                      >
                        {candidate.title}
                      </option>
                    ),
                  )}
                </Select>
              </label>
            )}

            <label>
              <span>
                Reason
              </span>

              <Textarea
                value={dispositionReason}
                disabled={busy}
                placeholder="Required disposition rationale"
                onChange={(event) =>
                  setDispositionReason(
                    event.target.value,
                  )
                }
              />
            </label>

            <div className="finding-workflow-actions">
              <button
                type="submit"
                className="primary-button"
                disabled={
                  busy
                  || !disposition
                }
              >
                Save disposition
              </button>

              {finding.disposition && (
                <button
                  type="button"
                  className="secondary-button"
                  disabled={busy}
                  onClick={
                    handleDispositionClear
                  }
                >
                  Clear disposition
                </button>
              )}
            </div>
          </form>
        </div>
      )}

      <section className="finding-retest-section">
        <div className="finding-section-heading">
          <div>
            <p className="eyebrow">
              VALIDATION
            </p>

            <h3>
              Retests
            </h3>
          </div>
        </div>

        {canManage
          && finding.lifecycle_state
            === 'READY_FOR_RETEST' && (
          <div className="finding-retest-request">
            <div>
              <strong>
                Ready for validation
              </strong>

              <p className="finding-muted">
                Request a retest now. A fresh validating assessment will be linked through the assessment workflow.
              </p>
            </div>

            <button
              type="button"
              className="primary-button finding-retest-button"
              disabled={busy}
              aria-busy={retestBusy}
              onClick={handleRetest}
            >
              {retestBusy && (
                <Spinner label="Requesting retest" />
              )}
              <span>
                {retestBusy
                  ? 'Requesting retest...'
                  : 'Request retest'}
              </span>
            </button>
          </div>
        )}

        <div className="finding-retest-list">
          {retests.length === 0 ? (
            <p className="finding-muted">
              No retests have been requested.
            </p>
          ) : (
            retests.map(
              (retest) => (
                <article
                  key={retest.id}
                  className="finding-retest-item"
                >
                  <div>
                    <strong>
                      {humanize(
                        retest.status,
                      )}
                    </strong>

                    <span>
                      Requested{' '}
                      {formatDate(
                        retest.requested_at,
                      )}
                    </span>
                  </div>

                  {retest.scan_id && (
                    <code>
                      {retest.scan_id}
                    </code>
                  )}
                </article>
              ),
            )
          )}
        </div>
      </section>

      <section className="finding-workflow-history">
        <div className="finding-section-heading">
          <div>
            <p className="eyebrow">
              AUDIT TRAIL
            </p>

            <h3>
              Workflow history
            </h3>
          </div>
        </div>

        {history.length === 0 ? (
          <p className="finding-muted">
            No workflow events recorded yet.
          </p>
        ) : (
          <ol>
            {history.map(
              (event) => {
                const actor =
                  memberById.get(
                    event.actor_user_id,
                  )

                return (
                  <li key={event.id}>
                    <div className="finding-history-heading">
                      <strong>
                        {humanize(
                          event.event_type,
                        )}
                      </strong>

                      <span>
                        {formatDate(
                          event.created_at,
                        )}
                      </span>
                    </div>

                    <p>
                      {event.previous_value
                        ? humanize(
                            event.previous_value,
                          )
                        : '—'}
                      {' → '}
                      {event.new_value
                        ? humanize(
                            event.new_value,
                          )
                        : '—'}
                    </p>

                    {event.reason && (
                      <p>
                        {event.reason}
                      </p>
                    )}

                    <small>
                      Actor:{' '}
                      {actor
                        ? memberLabel(actor)
                        : event.actor_user_id}
                    </small>
                  </li>
                )
              },
            )}
          </ol>
        )}
      </section>
    </section>
  )
}
