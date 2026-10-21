import {
  useEffect,
  useMemo,
  useState,
} from 'react'

import {
  Link,
  useNavigate,
  useSearchParams,
} from 'react-router'

import {
  createAssessment,
  listAssessmentProfiles,
} from '../../api/assessments'
import { linkFindingRetest } from '../../api/findings'
import { createScan } from '../../api/scans'
import { listTargets } from '../../api/targets'
import { isDemoUser } from '../../auth/demo-access'
import { PERMISSIONS } from '../../auth/rbac'
import { useAuth } from '../../auth/useAuth'

import {
  Card,
  Checkbox,
  EmptyState,
  ErrorAlert,
  PageHeader,
  SkeletonList,
  Spinner,
  StatusBadge,
  Textarea,
} from '../../components/ui'


const ASSESSMENT_WIZARD_STAGES = [
  'Target',
  'Profile',
  'Scope and authorization',
  'Review',
  'Launch',
]


const PROFILE_COPY = {
  quick: {
    title: 'Quick',
    description:
      'Fast passive-first assessment for initial posture review and low-impact discovery.',
    impact: 'Low',
  },

  standard: {
    title: 'Standard',
    description:
      'Balanced active web assessment with broader validation and controlled request rates.',
    impact: 'Moderate',
  },

  deep: {
    title: 'Deep',
    description:
      'Extended assessment for authorized environments that require deeper web and infrastructure coverage.',
    impact: 'Elevated',
  },
}


function formatDuration(
  totalSeconds,
) {
  const seconds = Number(
    totalSeconds,
  )

  if (
    !Number.isFinite(seconds)
    || seconds <= 0
  ) {
    return 'Bounded runtime'
  }

  if (seconds < 60) {
    return `${seconds}s maximum`
  }

  const minutes = Math.ceil(
    seconds / 60,
  )

  if (minutes < 60) {
    return `${minutes} min maximum`
  }

  const hours = (
    minutes / 60
  ).toFixed(
    minutes % 60 === 0
      ? 0
      : 1,
  )

  return `${hours} hr maximum`
}


function splitScopeEntries(
  value,
) {
  return value
    .split(/[\n,]+/)
    .map((entry) => entry.trim())
    .filter(Boolean)
}


function isIPv4(
  value,
) {
  const parts = value.split('.')

  if (parts.length !== 4) {
    return false
  }

  return parts.every(
    (part) => {
      if (!/^\d{1,3}$/.test(part)) {
        return false
      }

      const number = Number(part)

      return (
        number >= 0
        && number <= 255
        && String(number) === (
          part === '0'
            ? '0'
            : part.replace(
              /^0+(?=\d)/,
              '',
            )
        )
      )
    },
  )
}


function isIPv6(
  value,
) {
  return (
    value.includes(':')
    && /^[0-9a-f:]+$/i.test(value)
    && value.length <= 45
  )
}


function isIpAddress(
  value,
) {
  return (
    isIPv4(value)
    || isIPv6(value)
  )
}


function isCidr(
  value,
) {
  const pieces = value.split('/')

  if (pieces.length !== 2) {
    return false
  }

  const [
    address,
    prefixText,
  ] = pieces

  if (
    !/^\d+$/.test(prefixText)
    || !isIpAddress(address)
  ) {
    return false
  }

  const prefix = Number(
    prefixText,
  )

  const maximum = (
    isIPv4(address)
      ? 32
      : 128
  )

  return (
    prefix >= 0
    && prefix <= maximum
  )
}


function profileTitle(
  profile,
) {
  return (
    PROFILE_COPY[
      profile?.name
    ]?.title
    || profile?.name
    || 'Assessment'
  )
}


export default function NewAssessmentPage() {
  const navigate = useNavigate()

  const [searchParams] =
    useSearchParams()

  const retestId =
    searchParams.get(
      'retest_id',
    )

  const retestFindingId =
    searchParams.get(
      'finding_id',
    )

  const retestTargetId =
    searchParams.get(
      'target_id',
    )
  const { user, hasPermission } = useAuth()

  const isDemo = isDemoUser(
    user,
  )

  const canCreateAssessment =
    isDemo
    || hasPermission(
      PERMISSIONS.ASSESSMENT_CREATE,
    )

  const [
    targets,
    setTargets,
  ] = useState([])

  const [
    profiles,
    setProfiles,
  ] = useState([])

  const [
    selectedTargetId,
    setSelectedTargetId,
  ] = useState('')

  const [
    selectedProfileName,
    setSelectedProfileName,
  ] = useState('quick')

  const [
    assessmentMode,
    setAssessmentMode,
  ] = useState('web')

  const [
    activeTestingConfirmed,
    setActiveTestingConfirmed,
  ] = useState(false)

  const [
    infrastructureEnabled,
    setInfrastructureEnabled,
  ] = useState(false)

  const [
    authorizedIpsText,
    setAuthorizedIpsText,
  ] = useState('')

  const [
    authorizedCidrsText,
    setAuthorizedCidrsText,
  ] = useState('')

  const [
    broadPortScanAllowed,
    setBroadPortScanAllowed,
  ] = useState(false)

  const [
    networkActiveChecksAllowed,
    setNetworkActiveChecksAllowed,
  ] = useState(false)

  const [
    thirdPartyExcluded,
    setThirdPartyExcluded,
  ] = useState(false)

  const [
    loading,
    setLoading,
  ] = useState(true)

  const [
    launching,
    setLaunching,
  ] = useState(false)

  const [
    error,
    setError,
  ] = useState('')


  useEffect(
    () => {
      let cancelled = false

      async function loadWorkflow() {
        setLoading(true)
        setError('')

        try {
          const [
            targetResult,
            profileResult,
          ] = await Promise.all([
            listTargets(),

            isDemo
              ? Promise.resolve([])
              : listAssessmentProfiles(

              ),
          ])

          if (cancelled) {
            return
          }

          setTargets(
            targetResult,
          )

          setProfiles(
            profileResult,
          )

          if (
            targetResult.length === 1
          ) {
            setSelectedTargetId(
              targetResult[0].id,
            )
          }

          if (
            !isDemo
            && profileResult.length > 0
          ) {
            const defaultProfile = (
              profileResult.find(
                (profile) => (
                  profile.name
                  === 'quick'
                ),
              )
              || profileResult[0]
            )

            setSelectedProfileName(
              defaultProfile.name,
            )
          }
        } catch (requestError) {
          if (!cancelled) {
            setError(
              requestError.message
              || (
                'Unable to load '
                + 'assessment workflow.'
              ),
            )
          }
        } finally {
          if (!cancelled) {
            setLoading(false)
          }
        }
      }

      loadWorkflow()

      return () => {
        cancelled = true
      }
    },
    [
      isDemo,
    ],
  )


  // Retest target preselection:
  // fresh validation must stay on the original finding target.
  useEffect(() => {
    if (
      !retestTargetId
      || targets.length === 0
    ) {
      return
    }

    const requestedTarget =
      targets.find(
        (target) =>
          target.id === retestTargetId,
      )

    if (
      requestedTarget
      && selectedTargetId
        !== requestedTarget.id
    ) {
      setSelectedTargetId(
        requestedTarget.id,
      )
    }
  }, [
    retestTargetId,
    targets,
    selectedTargetId,
  ])


  const selectedTarget = useMemo(
    () => (
      targets.find(
        (target) => (
          target.id
          === selectedTargetId
        ),
      )
      || null
    ),
    [
      targets,
      selectedTargetId,
    ],
  )


  const selectedProfile = useMemo(
    () => (
      profiles.find(
        (profile) => (
          profile.name
          === selectedProfileName
        ),
      )
      || null
    ),
    [
      profiles,
      selectedProfileName,
    ],
  )


  const isVerified = (
    selectedTarget
      ?.verification_status
    === 'verified'
  )


  const selectedIsDeep = (
    selectedProfile?.name === 'deep'
  )


  const profileRequiresActive = Boolean(
    selectedProfile
      ?.active_web_testing,
  )


  const enabledEngines = useMemo(
    () => Object.entries(
      selectedProfile?.engines
      || {},
    )
      .filter(
        (
          [
            ,
            policy,
          ],
        ) => policy?.enabled,
      )
      .map(
        (
          [
            engine,
          ],
        ) => engine,
      ),
    [
      selectedProfile,
    ],
  )


  const authorizedIps = useMemo(
    () => splitScopeEntries(
      authorizedIpsText,
    ),
    [
      authorizedIpsText,
    ],
  )


  const authorizedCidrs = useMemo(
    () => splitScopeEntries(
      authorizedCidrsText,
    ),
    [
      authorizedCidrsText,
    ],
  )


  const scopeInputsValid = (
    authorizedIps.every(
      isIpAddress,
    )
    && authorizedCidrs.every(
      isCidr,
    )
  )


  const hasInfrastructureScope = (
    authorizedIps.length > 0
    || authorizedCidrs.length > 0
  )


  const infrastructureReady = (
    !infrastructureEnabled
    || (
      selectedIsDeep
      && hasInfrastructureScope
      && scopeInputsValid
      && broadPortScanAllowed
      && networkActiveChecksAllowed
      && thirdPartyExcluded
    )
  )


  const authorizationReady = (
    !profileRequiresActive
    || activeTestingConfirmed
  )


  const canLaunch = Boolean(
    selectedTarget
    && isVerified
    && (
      isDemo
      || selectedProfile
    )
    && (
      isDemo
      || authorizationReady
    )
    && (
      isDemo
      || infrastructureReady
    )
    && !launching,
  )


  const wizardStage = (() => {
    if (!selectedTarget) {
      return 1
    }

    if (
      !isDemo
      && !selectedProfile
    ) {
      return 2
    }

    if (
      !isDemo
      && (
        !authorizationReady
        || !infrastructureReady
      )
    ) {
      return 3
    }

    if (!canLaunch) {
      return 4
    }

    return 5
  })()


  function selectProfile(
    profileName,
  ) {
    setSelectedProfileName(
      profileName,
    )

    setActiveTestingConfirmed(
      false,
    )

    if (profileName !== 'deep') {
      setInfrastructureEnabled(
        false,
      )

      setAuthorizedIpsText('')
      setAuthorizedCidrsText('')

      setBroadPortScanAllowed(
        false,
      )

      setNetworkActiveChecksAllowed(
        false,
      )

      setThirdPartyExcluded(
        false,
      )
    }

    setError('')
  }


  async function handleLaunch() {
    if (
      retestId
      && (
        !retestTargetId
        || selectedTarget?.id
          !== retestTargetId
      )
    ) {
      setError(
        'Retest must use the original finding target.',
      )
      return
    }

    if (
      !canLaunch
      || !canCreateAssessment
    ) {
      return
    }

    setLaunching(true)
    setError('')

    try {
      if (isDemo) {
        const scan = await createScan(

          selectedTarget.id,
        )

        if (retestId) {
          await linkFindingRetest(
            retestId,
            scan.id,
          )
        }

        navigate(
          `/scans/${scan.id}`,
        )

        return
      }

      const infrastructure = (
        infrastructureEnabled
          ? {
            authorized_ips:
              authorizedIps,

            authorized_cidrs:
              authorizedCidrs,

            broad_port_scan_allowed:
              broadPortScanAllowed,

            network_active_checks_allowed:
              networkActiveChecksAllowed,

            third_party_infrastructure_attested_excluded:
              thirdPartyExcluded,
          }
          : null
      )

      const assessment = (
        await createAssessment(

          {
            targetId:
              selectedTarget.id,

            profile:
              selectedProfile.name,

            assessmentMode,

            activeTestingConfirmed:
              profileRequiresActive
              && activeTestingConfirmed,

            infrastructure,
          },
        )
      )

      if (retestId) {

        await linkFindingRetest(

          retestId,

          assessment.id,

        )

      }



      navigate(

        `/scans/${assessment.id}`,
      )
    } catch (requestError) {
      setError(
        requestError.message
        || 'Unable to launch assessment.',
      )
    } finally {
      setLaunching(false)
    }
  }


  return (
    <>
      <PageHeader
        eyebrow="NEW ASSESSMENT"
        title="Launch an assessment"
        description={
          isDemo
            ? (
              'Launch the predefined '
              + 'constrained demo assessment.'
            )
            : (
              'Choose a verified target, '
              + 'select a versioned Engine v2 '
              + 'profile, review authorization '
              + 'and scope, then launch.'
            )
        }
        breadcrumbs={[
          {
            label: 'Assessments',
            to: '/scans',
          },
          {
            label: 'New Assessment',
          },
        ]}
      />

      {retestId && (
        <section
          className="assessment-retest-context"
          role="status"
        >
          <div>
            <p className="eyebrow">
              VULNERABILITY RETEST
            </p>

            <strong>
              Fresh validation assessment
            </strong>

            <p>
              This assessment will validate the original
              finding using fresh scanner evidence.
            </p>
          </div>

          <dl>
            <div>
              <dt>
                Finding
              </dt>

              <dd>
                <code>
                  {retestFindingId || 'Unavailable'}
                </code>
              </dd>
            </div>

            <div>
              <dt>
                Target
              </dt>

              <dd>
                <code>
                  {retestTargetId || 'Unavailable'}
                </code>
              </dd>
            </div>
          </dl>
        </section>
      )}

      <nav
        className="assessment-wizard-v2"
        aria-label="Assessment creation progress"
      >
        <span
          className="assessment-wizard-v2-signal"
          aria-hidden="true"
        />

        {ASSESSMENT_WIZARD_STAGES.map(
          (stage, index) => {
            const number =
              index + 1

            const state = (
              number < wizardStage
                ? 'complete'
                : (
                  number === wizardStage
                    ? 'current'
                    : 'upcoming'
                )
            )

            const stateLabel = (
              state === 'complete'
                ? 'Complete'
                : (
                  state === 'current'
                    ? 'Current'
                    : 'Upcoming'
                )
            )

            return (
              <div
                key={stage}
                className={
                  `assessment-wizard-v2-step ${state}`
                }
                data-state={state}
                aria-current={
                  state === 'current'
                    ? 'step'
                    : undefined
                }
              >
                <span
                  className="assessment-wizard-v2-number"
                  aria-hidden="true"
                >
                  {String(number).padStart(2, '0')}
                </span>

                <span className="assessment-wizard-v2-copy">
                  <strong>
                    {stage}
                  </strong>

                  <small>
                    {stateLabel}
                  </small>
                </span>
              </div>
            )
          },
        )}
      </nav>


      <ErrorAlert
        message={error}
        className="page-message"
      />

      {loading && (
        <div className="assessment-wizard-loading">
          <SkeletonList
            rows={3}
            label="Loading assessment workflow"
          />
        </div>
      )}

      {!loading
        && targets.length === 0
        && (
          <EmptyState
            title="No registered targets"
            message={
              isDemo
                ? (
                  'The configured demo '
                  + 'target is unavailable.'
                )
                : (
                  'Register and verify a '
                  + 'target before launching '
                  + 'an assessment.'
                )
            }
          />
        )}

      {!loading
        && targets.length > 0
        && (
          <div className="new-assessment-layout">
            <Card
              eyebrow="STEP 01"
              title="Choose target"
              className="new-assessment-section"
            >
              <p className="assessment-step-description">
                Select the exact registered
                target BEACON is authorized
                to assess.
              </p>

              <div className="assessment-target-options">
                {targets.map(
                  (target) => {
                    const selected = (
                      target.id
                      === selectedTargetId
                    )

                    return (
                      <button
                        key={target.id}
                        type="button"
                        className={
                          selected
                            ? (
                              'assessment-target-option '
                              + 'selected'
                            )
                            : (
                              'assessment-target-option'
                            )
                        }
                        onClick={
                          () => {
                            setSelectedTargetId(
                              target.id,
                            )

                            setError('')
                          }
                        }
                      >
                        <span className="assessment-target-radio">
                          <span />
                        </span>

                        <span className="assessment-target-copy">
                          <strong>
                            {target.hostname}
                          </strong>

                          <small>
                            {target.normalized_url}
                          </small>
                        </span>

                        <StatusBadge
                          value={
                            target
                              .verification_status
                          }
                        />
                      </button>
                    )
                  },
                )}
              </div>

              {selectedTarget
                && !isVerified
                && (
                  <div className="assessment-readiness-state blocked">
                    <div>
                      <span className="detail-label">
                        OWNERSHIP
                      </span>

                      <strong>
                        Verification required
                      </strong>

                      <p>
                        This target cannot be
                        assessed until ownership
                        verification succeeds.
                      </p>
                    </div>

                    <Link
                      className="secondary-button inline-button"
                      to={
                        `/targets/${selectedTarget.id}`
                        + '?tab=verification'
                      }
                    >
                      Open verification
                    </Link>
                  </div>
                )}
            </Card>

            <Card
              eyebrow="STEP 02"
              title="Assessment profile"
              className="new-assessment-section"
            >
              {isDemo ? (
                <div className="assessment-profile-card">
                  <div className="assessment-profile-heading">
                    <div>
                      <span className="detail-label">
                        DEMO PROFILE
                      </span>

                      <strong>
                        Legacy
                      </strong>
                    </div>

                    <span className="readiness-profile">
                      Constrained · HTTP/S
                    </span>
                  </div>

                  <p>
                    The demo account retains
                    the existing constrained
                    legacy assessment path and
                    cannot launch Engine v2
                    active profiles.
                  </p>
                </div>
              ) : (
                <>
                  <p className="assessment-step-description">
                    Profile behavior comes
                    directly from the backend
                    versioned policy metadata.
                  </p>

                  <div className="assessment-profile-options">
                    {profiles.map(
                      (profile) => {
                        const selected = (
                          profile.name
                          === selectedProfileName
                        )

                        const copy = (
                          PROFILE_COPY[
                            profile.name
                          ] || {}
                        )

                        const engineCount = (
                          Object.values(
                            profile.engines
                            || {},
                          )
                            .filter(
                              (policy) => (
                                policy?.enabled
                              ),
                            )
                            .length
                        )

                        return (
                          <button
                            key={profile.name}
                            type="button"
                            className={
                              selected
                                ? (
                                  'assessment-profile-option '
                                  + 'selected'
                                )
                                : (
                                  'assessment-profile-option'
                                )
                            }
                            onClick={
                              () => selectProfile(
                                profile.name,
                              )
                            }
                          >
                            <div className="assessment-profile-option-heading">
                              <div>
                                <span className="detail-label">
                                  PROFILE
                                </span>

                                <strong>
                                  {copy.title
                                    || profile.name}
                                </strong>
                              </div>

                              <span className="assessment-profile-version">
                                {profile.version}
                              </span>
                            </div>

                            <p>
                              {copy.description
                                || (
                                  'Versioned BEACON '
                                  + 'assessment profile.'
                                )}
                            </p>

                            <dl className="assessment-profile-facts">
                              <div>
                                <dt>Impact</dt>
                                <dd>
                                  {copy.impact
                                    || 'Controlled'}
                                </dd>
                              </div>

                              <div>
                                <dt>Runtime</dt>
                                <dd>
                                  {formatDuration(
                                    profile
                                      .total_timeout_seconds,
                                  )}
                                </dd>
                              </div>

                              <div>
                                <dt>Active web testing</dt>
                                <dd>
                                  {profile
                                    .active_web_testing
                                    ? 'Enabled'
                                    : 'Passive'}
                                </dd>
                              </div>

                              <div>
                                <dt>Destructive testing</dt>
                                <dd>
                                  {profile
                                    .destructive_testing_enabled
                                    ? 'Enabled'
                                    : 'Disabled'}
                                </dd>
                              </div>

                              <div>
                                <dt>Engines</dt>
                                <dd>
                                  {engineCount}
                                </dd>
                              </div>

                              <div>
                                <dt>Target rate</dt>
                                <dd>
                                  {profile
                                    .target_request_rate}
                                  {' '}
                                  req/s
                                </dd>
                              </div>
                            </dl>
                          </button>
                        )
                      },
                    )}
                  </div>
                </>
              )}
            </Card>

            <Card
              eyebrow="STEP 03"
              title="Mode and scope"
              className="new-assessment-section"
            >
              {isDemo ? (
                <div className="assessment-scope-panel">
                  <span className="detail-label">
                    DEMO SCOPE
                  </span>

                  <strong>
                    {selectedTarget
                      ?.hostname
                      || 'Choose target'}
                  </strong>

                  <p>
                    Demo scope remains fixed
                    to the predefined target.
                  </p>
                </div>
              ) : (
                <>
                  <div
                    className="assessment-mode-options"
                    role="radiogroup"
                    aria-label="Assessment mode"
                  >
                    {[
                      {
                        value: 'web',
                        label: 'Web',
                        description:
                          'HTTP/S web application assessment.',
                      },
                      {
                        value: 'api',
                        label: 'API',
                        description:
                          'API-oriented assessment mode.',
                      },
                    ].map(
                      (mode) => (
                        <label
                          key={mode.value}
                          className={
                            assessmentMode
                            === mode.value
                              ? (
                                'assessment-mode-option '
                                + 'selected'
                              )
                              : (
                                'assessment-mode-option'
                              )
                          }
                        >
                          <input
                            type="radio"
                            name="assessment-mode"
                            value={mode.value}
                            checked={
                              assessmentMode
                              === mode.value
                            }
                            onChange={
                              () => setAssessmentMode(
                                mode.value,
                              )
                            }
                          />

                          <span>
                            <strong>
                              {mode.label}
                            </strong>

                            <small>
                              {mode.description}
                            </small>
                          </span>
                        </label>
                      ),
                    )}
                  </div>

                  <div className="assessment-scope-panel">
                    <span className="detail-label">
                      EXACT AUTHORIZED TARGET
                    </span>

                    <strong>
                      {selectedTarget
                        ?.hostname
                        || 'Choose a target'}
                    </strong>

                    <p>
                      {selectedTarget
                        ?.normalized_url
                        || (
                          'The immutable plan '
                          + 'will snapshot the '
                          + 'verified target scope.'
                        )}
                    </p>
                  </div>

                  {selectedProfile
                    && (
                      <div className="assessment-engine-summary">
                        <span className="detail-label">
                          ENABLED ENGINES
                        </span>

                        <div>
                          {enabledEngines.map(
                            (engine) => (
                              <span
                                key={engine}
                                className="assessment-engine-chip"
                              >
                                {engine}
                              </span>
                            ),
                          )}
                        </div>
                      </div>
                    )}
                </>
              )}
            </Card>

            <Card
              eyebrow="STEP 04"
              title="Authorization"
              className="new-assessment-section"
            >
              {isDemo ? (
                <div className="assessment-authorization-panel">
                  <span className="detail-label">
                    DEMO POLICY
                  </span>

                  <strong>
                    Constrained legacy authorization
                  </strong>

                  <p>
                    The demo user cannot enable
                    Engine v2 active testing or
                    Deep Infrastructure Extension.
                  </p>
                </div>
              ) : (
                <>
                  <div className="assessment-authorization-panel">
                    <div>
                      <span className="detail-label">
                        ACTIVE TESTING
                      </span>

                      <strong>
                        {profileRequiresActive
                          ? (
                            'Explicit authorization '
                            + 'required'
                          )
                          : (
                            'Passive profile — no '
                            + 'active confirmation '
                            + 'required'
                          )}
                      </strong>

                      <p>
                        {profileRequiresActive
                          ? (
                            'This profile performs '
                            + 'active security checks. '
                            + 'Confirm that you own '
                            + 'or are explicitly '
                            + 'authorized to test '
                            + 'this target.'
                          )
                          : (
                            'The selected profile '
                            + 'does not enable active '
                            + 'web testing.'
                          )}
                      </p>
                    </div>

                    {profileRequiresActive
                      && (
                        <label className="assessment-authorization-check">
                          <Checkbox
                            checked={
                              activeTestingConfirmed
                            }
                            onChange={
                              (event) => (
                                setActiveTestingConfirmed(
                                  event.target.checked,
                                )
                              )
                            }
                          />

                          <span>
                            I confirm active testing
                            authorization for this
                            exact verified target.
                          </span>
                        </label>
                      )}
                  </div>

                  {selectedProfile?.name === 'deep'
                    && (
                      <div className="assessment-infrastructure-panel">
                        <label className="assessment-infrastructure-toggle">
                          <Checkbox
                            checked={
                              infrastructureEnabled
                            }
                            onChange={
                              (event) => (
                                setInfrastructureEnabled(
                                  event.target.checked,
                                )
                              )
                            }
                          />

                          <span>
                            <strong>
                              Infrastructure Extension
                            </strong>

                            <small>
                              Extend Deep assessment
                              only to explicitly
                              authorized IP/CIDR scope.
                            </small>
                          </span>
                        </label>

                        {infrastructureEnabled
                          && (
                            <div className="assessment-infrastructure-body">
                              <div className="assessment-scope-fields">
                                <label>
                                  <span>
                                    Exact IP addresses
                                  </span>

                                  <Textarea
                                    value={
                                      authorizedIpsText
                                    }
                                    placeholder={
                                      '203.0.113.10\n'
                                      + '203.0.113.11'
                                    }
                                    onChange={
                                      (event) => (
                                        setAuthorizedIpsText(
                                          event.target.value,
                                        )
                                      )
                                    }
                                  />
                                </label>

                                <label>
                                  <span>
                                    Exact CIDR ranges
                                  </span>

                                  <Textarea
                                    value={
                                      authorizedCidrsText
                                    }
                                    placeholder={
                                      '203.0.113.0/28'
                                    }
                                    onChange={
                                      (event) => (
                                        setAuthorizedCidrsText(
                                          event.target.value,
                                        )
                                      )
                                    }
                                  />
                                </label>
                              </div>

                              {hasInfrastructureScope
                                && !scopeInputsValid
                                && (
                                  <p
                                    className="assessment-scope-error"
                                    role="alert"
                                  >
                                    Enter only valid
                                    IP addresses and
                                    CIDR ranges.
                                  </p>
                                )}

                              <div className="assessment-attestation-list">
                                <label>
                                  <Checkbox
                                    checked={
                                      broadPortScanAllowed
                                    }
                                    onChange={
                                      (event) => (
                                        setBroadPortScanAllowed(
                                          event.target.checked,
                                        )
                                      )
                                    }
                                  />

                                  <span>
                                    Broad port scanning
                                    is explicitly
                                    authorized.
                                  </span>
                                </label>

                                <label>
                                  <Checkbox
                                    checked={
                                      networkActiveChecksAllowed
                                    }
                                    onChange={
                                      (event) => (
                                        setNetworkActiveChecksAllowed(
                                          event.target.checked,
                                        )
                                      )
                                    }
                                  />

                                  <span>
                                    Network active checks
                                    are explicitly
                                    authorized.
                                  </span>
                                </label>

                                <label>
                                  <Checkbox
                                    checked={
                                      thirdPartyExcluded
                                    }
                                    onChange={
                                      (event) => (
                                        setThirdPartyExcluded(
                                          event.target.checked,
                                        )
                                      )
                                    }
                                  />

                                  <span>
                                    Shared and third-party
                                    infrastructure not
                                    covered by my
                                    authorization has
                                    been excluded.
                                  </span>
                                </label>
                              </div>
                            </div>
                          )}
                      </div>
                    )}
                </>
              )}
            </Card>

            <Card
              eyebrow="STEP 05"
              title="Review and launch"
              className="new-assessment-section"
            >
              {!selectedTarget ? (
                <p className="assessment-step-description">
                  Choose a target before
                  reviewing the assessment.
                </p>
              ) : (
                <div className="assessment-review">
                  <dl>
                    <div>
                      <dt>Target</dt>
                      <dd>
                        {selectedTarget.hostname}
                      </dd>
                    </div>

                    <div>
                      <dt>Verification</dt>
                      <dd>
                        {isVerified
                          ? 'Verified'
                          : 'Required'}
                      </dd>
                    </div>

                    <div>
                      <dt>Profile</dt>
                      <dd>
                        {isDemo
                          ? 'Legacy'
                          : (
                            profileTitle(
                              selectedProfile,
                            )
                          )}
                      </dd>
                    </div>

                    <div>
                      <dt>Mode</dt>
                      <dd>
                        {isDemo
                          ? 'web'
                          : assessmentMode}
                      </dd>
                    </div>

                    <div>
                      <dt>Active authorization</dt>
                      <dd>
                        {isDemo
                          ? 'Demo policy'
                          : (
                            profileRequiresActive
                              ? (
                                activeTestingConfirmed
                                  ? 'Confirmed'
                                  : 'Required'
                              )
                              : 'Not required'
                          )}
                      </dd>
                    </div>

                    <div>
                      <dt>Infrastructure</dt>
                      <dd>
                        {isDemo
                          ? 'Disabled'
                          : (
                            infrastructureEnabled
                              ? (
                                infrastructureReady
                                  ? 'Authorized'
                                  : 'Incomplete'
                              )
                              : 'Target only'
                          )}
                      </dd>
                    </div>
                  </dl>

                  {!isDemo
                    && selectedProfile
                    && (
                      <div className="assessment-review-safety">
                        <strong>
                          Safety review
                        </strong>

                        <p>
                          Destructive testing is
                          {selectedProfile
                            .destructive_testing_enabled
                            ? ' enabled'
                            : ' disabled'}
                          . Runtime is bounded to
                          {' '}
                          {formatDuration(
                            selectedProfile
                              .total_timeout_seconds,
                          )}
                          . Active behavior follows
                          the selected versioned
                          profile.
                        </p>
                      </div>
                    )}

                  <div className="assessment-launch-console">
                    <div
                      className="assessment-launch-readiness"
                      aria-label="Launch readiness"
                    >
                      <span className={isVerified ? 'ready' : 'blocked'}>
                        <b>Target</b>
                        {isVerified ? 'Verified' : 'Blocked'}
                      </span>

                      <span className={authorizationReady ? 'ready' : 'blocked'}>
                        <b>Authorization</b>
                        {authorizationReady ? 'Ready' : 'Required'}
                      </span>

                      <span className={infrastructureReady ? 'ready' : 'blocked'}>
                        <b>Infrastructure</b>
                        {infrastructureReady ? 'Ready' : 'Incomplete'}
                      </span>
                    </div>

                    {!authorizationReady
                      && !isDemo
                      && (
                        <p
                          className="assessment-launch-blocker"
                          role="alert"
                        >
                          Confirm active testing
                          authorization before launch.
                        </p>
                      )}

                    {!infrastructureReady
                      && !isDemo
                      && (
                        <p
                          className="assessment-launch-blocker"
                          role="alert"
                        >
                          Complete the exact Deep
                          infrastructure scope and
                          all three attestations
                          before launch.
                        </p>
                      )}

                    <div
                      className={
                        `assessment-launch-state ${
                          launching
                            ? 'launching'
                            : (canLaunch ? 'ready' : 'blocked')
                        }`
                      }
                      role="status"
                      aria-live="polite"
                    >
                      <span aria-hidden="true" />

                      <div>
                        <strong>
                          {launching
                            ? 'Launching assessment'
                            : (
                              canLaunch
                                ? 'Ready to launch'
                                : 'Launch requirements incomplete'
                            )}
                        </strong>

                        <small>
                          {launching
                            ? 'BEACON is creating the assessment plan.'
                            : 'Launch begins immediately after the API accepts the request.'}
                        </small>
                      </div>
                    </div>

                    <button
                      type="button"
                      className="primary-button assessment-launch-button"
                      disabled={
                        !canLaunch
                        || !canCreateAssessment
                      }
                      aria-busy={launching}
                      onClick={handleLaunch}
                    >
                      {launching && (
                        <Spinner label="Launching assessment" />
                      )}

                      <span>
                        {launching
                          ? 'Launching assessment...'
                          : (
                            isDemo
                              ? 'Launch Legacy Assessment'
                              : 'Launch assessment'
                          )}
                      </span>
                    </button>
                  </div>
                </div>
              )}
            </Card>
          </div>
        )}
    </>
  )
}
