import {
  useEffect,
  useState,
} from 'react'

import {
  Link,
  useParams,
} from 'react-router'

import {
  getFinding,
} from '../../api/findings'
import PageHeader from '../../components/ui/PageHeader'
import SkeletonList from '../../components/ui/SkeletonList'
import {
  EmptyState,
  ErrorAlert,
} from '../../components/ui/StateMessage'
import FindingEvidence from './FindingEvidence'
import FindingOccurrences from './FindingOccurrences'
import FindingRemediation from './FindingRemediation'
import FindingSummary from './FindingSummary'
import FindingWorkflowPanel from './FindingWorkflowPanel'


function decodeFindingId(value) {
  try {
    return decodeURIComponent(
      value || '',
    )
  } catch {
    return value || ''
  }
}


export default function FindingDetailPage() {


  const {
    findingId,
  } = useParams()

  const decodedFindingId =
    decodeFindingId(findingId)

  const [
    finding,
    setFinding,
  ] = useState(null)

  const [
    loading,
    setLoading,
  ] = useState(true)

  const [
    error,
    setError,
  ] = useState('')

  const [
    notFound,
    setNotFound,
  ] = useState(false)

  const [
    retryCount,
    setRetryCount,
  ] = useState(0)

  useEffect(() => {
    let active = true

    async function loadFinding() {
      setLoading(true)
      setError('')
      setNotFound(false)

      try {
        const result =
          await getFinding(

            decodedFindingId,
          )

        if (active) {
          setFinding(result)
        }
      } catch (requestError) {
        if (!active) {
          return
        }

        setFinding(null)

        if (
          requestError.status === 404
        ) {
          setNotFound(true)
        } else {
          setError(
            requestError.message ||
              'Unable to load finding.',
          )
        }
      } finally {
        if (active) {
          setLoading(false)
        }
      }
    }

    loadFinding()

    return () => {
      active = false
    }
  }, [
    decodedFindingId,
    retryCount,
  ])

  function handleRetry() {
    setRetryCount(
      (value) => value + 1,
    )
  }

  return (
    <>
      <PageHeader
        eyebrow="FINDING"
        title={
          finding?.title ||
          'Finding detail'
        }
        description="Review correlated context, scanner evidence, raw occurrences, and stored remediation guidance."
        breadcrumbs={[
          {
            label: 'Findings',
            to: '/findings',
          },
          {
            label:
              finding?.title ||
              'Finding detail',
          },
        ]}
        actions={
          <Link
            className="secondary-button inline-button"
            to="/findings"
          >
            ← Back to Findings
          </Link>
        }
      />

      {loading && (
        <SkeletonList
          rows={5}
          label="Loading finding investigation"
          className="finding-detail-skeleton"
        />
      )}

      {!loading && notFound && (
        <EmptyState
          title="Finding not found"
          message="This finding does not exist or is not available to your account."
        />
      )}

      {!loading && error && (
        <section className="findings-error-state">
          <ErrorAlert
            message={error}
            className="page-message"
          />

          <button
            type="button"
            className="secondary-button"
            onClick={handleRetry}
          >
            Retry
          </button>
        </section>
      )}

      {!loading &&
        !error &&
        !notFound &&
        finding && (
          <div className="finding-detail-layout">
            <FindingSummary
              finding={finding}
            />

            <FindingWorkflowPanel
              finding={finding}
              findingId={decodedFindingId}
              onFindingChange={setFinding}
            />

            <FindingEvidence
              finding={finding}
            />

            <FindingOccurrences
              finding={finding}
            />

            <FindingRemediation
              finding={finding}
            />

            <section className="finding-detail-card finding-metadata">
              <div className="finding-section-heading">
                <div>
                  <p className="eyebrow">
                    METADATA
                  </p>
                  <h2>Finding metadata</h2>
                </div>
              </div>

              <dl className="finding-metadata-grid">
                <div>
                  <dt>Workspace finding ID</dt>
                  <dd>{finding.id}</dd>
                </div>

                <div>
                  <dt>Issue key</dt>
                  <dd>{finding.issue_key}</dd>
                </div>

                <div>
                  <dt>Scan ID</dt>
                  <dd>{finding.scan_id}</dd>
                </div>

                <div>
                  <dt>Target ID</dt>
                  <dd>{finding.target_id}</dd>
                </div>

                <div>
                  <dt>CWE</dt>
                  <dd>
                    {finding.cwe_id || '—'}
                  </dd>
                </div>

                <div>
                  <dt>Source count</dt>
                  <dd>
                    {finding.source_count}
                  </dd>
                </div>

                <div>
                  <dt>Manual validation</dt>
                  <dd>
                    {finding.requires_manual_validation
                      ? 'Required'
                      : 'Not required'}
                  </dd>
                </div>
              </dl>
            </section>
          </div>
        )}
    </>
  )
}
