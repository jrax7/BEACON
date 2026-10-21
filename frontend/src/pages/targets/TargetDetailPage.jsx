import {
  useCallback,
  useEffect,
  useState,
} from 'react'

import {
  Link,
  useNavigate,
  useParams,
  useSearchParams,
} from 'react-router'

import {
  listScans,
} from '../../api/scans'

import {
  deleteTarget,
  getTarget,
  regenerateVerificationToken,
  verifyTarget,
} from '../../api/targets'

import { isDemoUser } from '../../auth/demo-access'
import { PERMISSIONS } from '../../auth/rbac'
import { useAuth } from '../../auth/useAuth'

import {
  ErrorAlert,
  PageHeader,
  SkeletonList,
  StatusBadge,
  SuccessAlert,
  Tabs,
} from '../../components/ui'

import ReadinessPanel from './ReadinessPanel'
import TargetAssessments from './TargetAssessments'
import TargetOverview from './TargetOverview'
import TargetSettings from './TargetSettings'
import VerificationPanel from './VerificationPanel'

const TARGET_TABS = [
  {
    key: 'overview',
    label: 'Overview',
  },
  {
    key: 'verification',
    label: 'Verification',
  },
  {
    key: 'readiness',
    label: 'Readiness',
  },
  {
    key: 'assessments',
    label: 'Assessments',
  },
  {
    key: 'settings',
    label: 'Settings',
  },
]

const TARGET_TAB_KEYS = new Set(
  TARGET_TABS.map((tab) => tab.key),
)

function resolveTab(value) {
  return TARGET_TAB_KEYS.has(value)
    ? value
    : 'overview'
}

function tabLabel(key) {
  return TARGET_TABS.find(
    (tab) => tab.key === key,
  )?.label || 'Overview'
}

export default function TargetDetailPage() {
  const { targetId } = useParams()
  const navigate = useNavigate()

  const [
    searchParams, setSearchParams, ] = useSearchParams()

  const { user, hasPermission } = useAuth()
  const isDemo = isDemoUser(user)

  const canVerifyTarget =
    !isDemo
    && hasPermission(
      PERMISSIONS.TARGET_VERIFY,
    )

  const canDeleteTarget =
    !isDemo
    && hasPermission(
      PERMISSIONS.TARGET_DELETE,
    )

  const canCreateAssessment =
    isDemo
    || hasPermission(
      PERMISSIONS.ASSESSMENT_CREATE,
    )

  const activeTab = resolveTab(
    searchParams.get('tab'),
  )

  const [target, setTarget] = useState(null)
  const [loading, setLoading] = useState(true)
  const [loadError, setLoadError] = useState('')

  const [
    actionError,
    setActionError,
  ] = useState('')

  const [
    actionSuccess,
    setActionSuccess,
  ] = useState('')

  const [
    verification,
    setVerification,
  ] = useState(null)

  const [
    regenerating,
    setRegenerating,
  ] = useState(false)

  const [
    verifying,
    setVerifying,
  ] = useState(false)

  const [
    deleting,
    setDeleting,
  ] = useState(false)

  const [
    launchingScan,
    setLaunchingScan,
  ] = useState(false)

  const [
    activeScans,
    setActiveScans,
  ] = useState([])

  const [
    archivedScans,
    setArchivedScans,
  ] = useState([])

  const [
    assessmentsLoading,
    setAssessmentsLoading,
  ] = useState(false)

  const [
    assessmentsLoaded,
    setAssessmentsLoaded,
  ] = useState(false)

  const [
    assessmentsError,
    setAssessmentsError,
  ] = useState('')

  const loadTarget = useCallback(async () => {
    setLoading(true)
    setLoadError('')

    try {
      const result = await getTarget(

        targetId,
      )

      setTarget(result)
    } catch (requestError) {
      setLoadError(
        requestError.message
        || 'Unable to load target.',
      )
    } finally {
      setLoading(false)
    }
  }, [targetId])

  useEffect(() => {
    loadTarget()
  }, [loadTarget])

  useEffect(() => {
    if (
      activeTab !== 'assessments'
      || assessmentsLoaded
    ) {
      return undefined
    }

    let cancelled = false

    async function loadAssessments() {
      setAssessmentsLoading(true)
      setAssessmentsError('')

      try {
        const [
          activeResult,
          archivedResult,
        ] = await Promise.all([
          listScans( 'active'),
          listScans( 'archived'),
        ])

        if (cancelled) {
          return
        }

        setActiveScans(activeResult)
        setArchivedScans(archivedResult)
        setAssessmentsLoaded(true)
      } catch (requestError) {
        if (cancelled) {
          return
        }

        setAssessmentsError(
          requestError.message
          || 'Unable to load target assessments.',
        )
      } finally {
        if (!cancelled) {
          setAssessmentsLoading(false)
        }
      }
    }

    loadAssessments()

    return () => {
      cancelled = true
    }
  }, [
    activeTab,
    assessmentsLoaded,
  ])

  function handleTabChange(tab) {
    setActionError('')
    setActionSuccess('')

    if (tab === 'overview') {
      setSearchParams({})
      return
    }

    setSearchParams({ tab })
  }

  async function handleRegenerate() {
    if (!canVerifyTarget) {
      return
    }

    setActionError('')
    setActionSuccess('')
    setRegenerating(true)

    try {
      const result =
        await regenerateVerificationToken(

          target.id,
        )

      setVerification(result)

      setTarget((current) => ({
        ...current,
        verification_status: 'pending',
        verified_at: null,
        verification_expires_at: null,
      }))

      setActionSuccess(
        'A new verification value was generated. Complete the displayed ownership instructions before verifying the target.',
      )
    } catch (requestError) {
      setActionError(
        requestError.message
        || 'Unable to regenerate verification instructions.',
      )
    } finally {
      setRegenerating(false)
    }
  }

  async function handleVerify() {
    if (!canVerifyTarget) {
      return
    }

    setActionError('')
    setActionSuccess('')
    setVerifying(true)

    try {
      const result = await verifyTarget(

        target.id,
        target.verification_method,
      )

      setTarget((current) => ({
        ...current,
        verification_method:
          result.verification_method,
        verification_status:
          result.verification_status,
        verified_at:
          result.verified_at,
        verification_expires_at:
          result.verification_expires_at,
      }))

      setActionSuccess(
        result.message
        || 'Target ownership was verified successfully.',
      )
    } catch (requestError) {
      setActionError(
        requestError.message
        || 'Ownership verification failed.',
      )
    } finally {
      setVerifying(false)
    }
  }

  function handleLaunchScan() {
    if (!canCreateAssessment) {
      return
    }

    setActionError('')
    setActionSuccess('')
    setLaunchingScan(true)

    navigate('/scans/new')
  }

  async function handleDelete() {
    if (!canDeleteTarget) {
      return
    }

    setActionError('')
    setActionSuccess('')
    setDeleting(true)

    try {
      await deleteTarget(

        target.id,
      )

      navigate(
        '/targets',
        { replace: true },
      )
    } catch (requestError) {
      setActionError(
        requestError.message
        || 'Unable to remove target.',
      )
    } finally {
      setDeleting(false)
    }
  }

  if (loading) {
    return (
      <div className="detail-state detail-state-loading">
        <SkeletonList
          rows={5}
          label="Loading target workspace"
        />
      </div>
    )
  }

  if (loadError) {
    return (
      <section className="content-card">
        <ErrorAlert message={loadError} />

        <Link
          className="back-link"
          to="/targets"
        >
          ← Back to Targets
        </Link>
      </section>
    )
  }

  if (!target) {
    return null
  }

  const isVerified =
    target.verification_status === 'verified'

  const breadcrumbs = [
    {
      label: 'Targets',
      to: '/targets',
    },
    {
      label: target.hostname,
      to: `/targets/${target.id}`,
    },
    {
      label: tabLabel(activeTab),
    },
  ]

  return (
    <>
      <PageHeader
        eyebrow="TARGET"
        title={target.hostname}
        description={target.normalized_url}
        breadcrumbs={breadcrumbs}
        actions={
          <StatusBadge
            value={target.verification_status}
          />
        }
        className="target-detail-header"
      />

      <Tabs
        items={TARGET_TABS}
        activeKey={activeTab}
        onChange={handleTabChange}
        ariaLabel="Target workspace"
      />

      <ErrorAlert
        message={actionError}
        className="page-message"
      />

      <SuccessAlert
        message={actionSuccess}
        className="page-message"
      />

      {activeTab === 'overview' && (
        <TargetOverview target={target} />
      )}

      {activeTab === 'verification' && (
        <VerificationPanel
          target={target}
          isVerified={isVerified}
          verification={verification}
          onVerify={handleVerify}
          verifying={verifying}
          onRegenerate={handleRegenerate}
          regenerating={regenerating}
          readOnly={!canVerifyTarget}
        />
      )}

      {activeTab === 'readiness' && (
        <ReadinessPanel
          isVerified={isVerified}
          onLaunchScan={handleLaunchScan}
          launchingScan={launchingScan}
          readOnly={!canCreateAssessment}
        />
      )}

      {activeTab === 'assessments' && (
        <TargetAssessments
          target={target}
          activeScans={activeScans}
          archivedScans={archivedScans}
          loading={assessmentsLoading}
          error={assessmentsError}
        />
      )}

      {activeTab === 'settings' && (
        <TargetSettings
          target={target}
          onDelete={handleDelete}
          deleting={deleting}
          readOnly={!canDeleteTarget}
        />
      )}
    </>
  )
}
