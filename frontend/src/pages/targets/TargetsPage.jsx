import { useCallback, useEffect, useState } from 'react'

import { listTargets } from '../../api/targets'
import { isDemoUser } from '../../auth/demo-access'
import { PERMISSIONS } from '../../auth/rbac'
import { useAuth } from '../../auth/useAuth'
import { Card, EmptyState, ErrorAlert, PageHeader, SkeletonList } from '../../components/ui'
import TargetRegistrationForm from './TargetRegistrationForm'
import TargetsTable from './TargetsTable'
import VerificationInstructions from './VerificationInstructions'

export default function TargetsPage() {
  const { user, hasPermission } = useAuth()
  const isDemo = isDemoUser(user)

  const canCreateTargets =
    !isDemo
    && hasPermission(
      PERMISSIONS.TARGET_CREATE,
    )

  const [targets, setTargets] = useState([])
  const [loading, setLoading] = useState(true)
  const [loadError, setLoadError] = useState('')
  const [verification, setVerification] = useState(null)

  const loadTargets = useCallback(async () => {
    setLoadError('')
    setLoading(true)

    try {
      const result = await listTargets()
      setTargets(result)
    } catch (requestError) {
      setLoadError(requestError.message || 'Unable to load targets.')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    loadTargets()
  }, [loadTargets])

  function handleCreated(created) {
    setTargets((current) => [created, ...current.filter((target) => target.id !== created.id)])

    setVerification({
      targetId: created.id,
      hostname: created.hostname,
      method: created.verification_method,
      value: created.verification_value,
      location: created.verification_location,
      instructions: created.instructions,
    })
  }

  const verifiedCount = targets.filter((target) => target.verification_status === 'verified').length
  const pendingCount = targets.length - verifiedCount

  return (
    <>
      <PageHeader
        eyebrow="ASSETS"
        title="Authorized targets"
        description="Register web origins, verify ownership, and control which assets are eligible for BEACON assessments."
        actions={
          <div className="target-header-stats">
            <div>
              <span>Registered</span>
              <strong>{targets.length}</strong>
            </div>
            <div>
              <span>Verified</span>
              <strong>{verifiedCount}</strong>
            </div>
            <div>
              <span>Pending</span>
              <strong>{pendingCount}</strong>
            </div>
          </div>
        }
      />

      <section className="target-layout">
        {canCreateTargets && (
          <TargetRegistrationForm onCreated={handleCreated} />
        )}
        {verification && <VerificationInstructions verification={verification} />}
      </section>

      <Card
        eyebrow="REGISTERED TARGETS"
        title="Your targets"
        className="targets-list-card"
        headingActions={
          <button type="button" className="secondary-button" onClick={loadTargets} disabled={loading}>
            {loading ? 'Refreshing...' : 'Refresh'}
          </button>
        }
      >
        <ErrorAlert message={loadError} />

        {loading && <SkeletonList rows={4} label="Loading targets" />}

        {!loading && targets.length === 0 && (
          <EmptyState
            title="No targets registered"
            message="Add your first authorized target using the form above."
          />
        )}

        {!loading && targets.length > 0 && <TargetsTable targets={targets} />}
      </Card>
    </>
  )
}
