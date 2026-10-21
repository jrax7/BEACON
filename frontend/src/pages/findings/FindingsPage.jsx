import {
  useEffect,
  useMemo,
  useState,
} from 'react'

import {
  useSearchParams,
} from 'react-router'

import {
  listFindingSourceTools,
  listFindings,
} from '../../api/findings'
import {
  listScans,
} from '../../api/scans'
import {
  listTargets,
} from '../../api/targets'
import PageHeader from '../../components/ui/PageHeader'
import {
  EmptyState,
  ErrorAlert,
  LoadingState,
} from '../../components/ui/StateMessage'
import FindingsFilters from './FindingsFilters'
import FindingWorkflowFilters from './FindingWorkflowFilters'
import FindingsTable from './FindingsTable'
import {
  buildAssessmentOptions,
  buildFindingSearch,
  buildSourceToolOptions,
  buildTargetOptions,
  parseFindingFilters,
  reconcileAssessmentForTarget,
  resolveFindingOptionValue,
} from './helpers'


const EMPTY_DATA = {
  total: 0,
  offset: 0,
  limit: 50,
  items: [],
}


export default function FindingsPage() {


  const [
    searchParams,
    setSearchParams,
  ] = useSearchParams()

  const [
    data,
    setData,
  ] = useState(EMPTY_DATA)

  const [
    loading,
    setLoading,
  ] = useState(true)

  const [
    error,
    setError,
  ] = useState('')

  const [
    retryCount,
    setRetryCount,
  ] = useState(0)

  const [
    targets,
    setTargets,
  ] = useState([])

  const [
    scans,
    setScans,
  ] = useState([])

  const [
    sourceToolNames,
    setSourceToolNames,
  ] = useState([])

  const [
    metadataLoading,
    setMetadataLoading,
  ] = useState(true)

  const [
    metadataError,
    setMetadataError,
  ] = useState('')

  const queryString =
    searchParams.toString()

  const filters = useMemo(
    () =>
      parseFindingFilters(
        new URLSearchParams(
          queryString,
        ),
      ),
    [
      queryString,
    ],
  )

  const targetOptions = useMemo(
    () =>
      buildTargetOptions(
        targets,
      ),
    [
      targets,
    ],
  )

  const assessmentOptions = useMemo(
    () =>
      buildAssessmentOptions(
        scans,
        targets,
        filters.target_id || '',
      ),
    [
      scans,
      targets,
      filters.target_id,
    ],
  )

  const sourceToolOptions = useMemo(
    () =>
      buildSourceToolOptions(
        sourceToolNames,
      ),
    [
      sourceToolNames,
    ],
  )

  const selectedTargetValue =
    resolveFindingOptionValue(
      filters.target_id,
      targetOptions,
      false,
    )

  const selectedAssessmentValue =
    resolveFindingOptionValue(
      filters.scan_id,
      assessmentOptions,
      false,
    )

  const selectedToolValue =
    resolveFindingOptionValue(
      filters.tool,
      sourceToolOptions,
      true,
    )

  const hasActiveFilters = [
    'severity',
    'confidence',
    'target_id',
    'scan_id',
    'tool',
    'classification',
    'lifecycle_state',
    'observation_state',
    'disposition',
    'assignee_user_id',
    'remediation_owner_user_id',
    'q',
  ].some(
    (key) => Boolean(filters[key]),
  )

  useEffect(() => {
    let active = true

    async function loadMetadata() {
      setMetadataLoading(true)
      setMetadataError('')

      try {
        const [
          targetResult,
          scanResult,
          sourceToolResult,
        ] = await Promise.all([
          listTargets(),
          listScans(

            'all',
          ),
          listFindingSourceTools(

          ),
        ])

        if (active) {
          setTargets(
            targetResult || [],
          )
          setScans(
            scanResult || [],
          )
          setSourceToolNames(
            sourceToolResult || [],
          )
        }
      } catch (requestError) {
        if (active) {
          setMetadataError(
            requestError.message ||
              'Unable to load finding filter metadata.',
          )
        }
      } finally {
        if (active) {
          setMetadataLoading(false)
        }
      }
    }

    loadMetadata()

    return () => {
      active = false
    }
  }, [
  ])

  useEffect(() => {
    let active = true

    async function loadFindings() {
      setLoading(true)
      setError('')

      try {
        const result =
          await listFindings(

            filters,
          )

        if (active) {
          setData(result)
        }
      } catch (requestError) {
        if (active) {
          setError(
            requestError.message ||
              'Unable to load findings.',
          )
        }
      } finally {
        if (active) {
          setLoading(false)
        }
      }
    }

    loadFindings()

    return () => {
      active = false
    }
  }, [
    filters,
    retryCount,
  ])

  function handleFilterChange(
    key,
    value,
  ) {
    const nextFilters = {
      ...filters,
    }

    if (
      value === undefined ||
      value === null ||
      value === ''
    ) {
      delete nextFilters[key]
    } else {
      nextFilters[key] = value
    }

    delete nextFilters.offset

    setSearchParams(
      buildFindingSearch(
        nextFilters,
      ),
    )
  }

  function handleTargetChange(
    targetId,
  ) {
    const nextFilters =
      reconcileAssessmentForTarget(
        filters,
        targetId,
        scans,
      )

    delete nextFilters.offset

    setSearchParams(
      buildFindingSearch(
        nextFilters,
      ),
    )
  }

  function handleReset() {
    setSearchParams(
      buildFindingSearch({}),
    )
  }

  function handleRetry() {
    setRetryCount(
      (value) => value + 1,
    )
  }

  const items =
    data?.items || []

  const total =
    data?.total || 0

  return (
    <>
      <PageHeader
        eyebrow="FINDINGS"
        title="Findings"
        description="Investigate correlated findings across assessments, review scanner provenance, and move into evidence and remediation."
        breadcrumbs={[
          {
            label: 'Findings',
          },
        ]}
      />

      <FindingWorkflowFilters
        filters={filters}
        onChange={handleFilterChange}
      />

      <FindingsFilters
        filters={filters}
        targetOptions={targetOptions}
        assessmentOptions={
          assessmentOptions
        }
        sourceToolOptions={
          sourceToolOptions
        }
        selectedTargetValue={
          selectedTargetValue
        }
        selectedAssessmentValue={
          selectedAssessmentValue
        }
        selectedToolValue={
          selectedToolValue
        }
        metadataLoading={
          metadataLoading
        }
        metadataError={
          metadataError
        }
        onChange={handleFilterChange}
        onTargetChange={
          handleTargetChange
        }
        onReset={handleReset}
        hasActiveFilters={
          hasActiveFilters
        }
      />

      {loading && (
        <LoadingState
          message="Loading findings..."
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
        total === 0 &&
        !hasActiveFilters && (
          <EmptyState
            title="No findings yet"
            message="Completed assessments with detected or observed findings will appear here."
          />
        )}

      {!loading &&
        !error &&
        total === 0 &&
        hasActiveFilters && (
          <EmptyState
            title="No findings match"
            message="No findings match the current search and filter criteria."
          />
        )}

      {!loading &&
        !error &&
        items.length > 0 && (
          <section className="findings-results">
            <div className="findings-results-heading">
              <div>
                <p className="eyebrow">
                  INVESTIGATION QUEUE
                </p>

                <h2>
                  Assessment findings
                </h2>
              </div>

              <span className="section-count">
                {total} total
              </span>
            </div>

            <FindingsTable
              items={items}
            />
          </section>
        )}
    </>
  )
}
