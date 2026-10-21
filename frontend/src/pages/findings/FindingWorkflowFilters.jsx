import {
  useEffect,
  useState,
} from 'react'

import {
  listOrganizationMembers,
} from '../../api/organization'
import {
  ErrorAlert,
  Select,
} from '../../components/ui'
import {
  FINDING_DISPOSITIONS,
  FINDING_LIFECYCLE_STATES,
  FINDING_OBSERVATION_STATES,
} from './helpers'


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


export default function FindingWorkflowFilters({
  filters,
  onChange,
}) {
  const [
    members,
    setMembers,
  ] = useState([])

  const [
    error,
    setError,
  ] = useState('')

  useEffect(() => {
    let active = true

    async function loadMembers() {
      try {
        const result =
          await listOrganizationMembers()

        if (active) {
          setMembers(
            Array.isArray(result)
              ? result
              : [],
          )
        }
      } catch (requestError) {
        if (active) {
          setError(
            requestError.message
            || 'Unable to load workspace members.',
          )
        }
      }
    }

    loadMembers()

    return () => {
      active = false
    }
  }, [])

  return (
    <section
      className="finding-workflow-filters"
      aria-label="Finding workflow filters"
    >
      <div className="finding-workflow-filter-grid">
        <label
          className="findings-filter"
          htmlFor="finding-lifecycle-filter"
        >
          <span>Lifecycle</span>

          <Select
            id="finding-lifecycle-filter"
            value={
              filters.lifecycle_state
              || ''
            }
            onChange={(event) =>
              onChange(
                'lifecycle_state',
                event.target.value,
              )
            }
          >
            <option value="">
              All lifecycle states
            </option>

            {FINDING_LIFECYCLE_STATES.map(
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

        <label
          className="findings-filter"
          htmlFor="finding-observation-filter"
        >
          <span>Observation</span>

          <Select
            id="finding-observation-filter"
            value={
              filters.observation_state
              || ''
            }
            onChange={(event) =>
              onChange(
                'observation_state',
                event.target.value,
              )
            }
          >
            <option value="">
              All observations
            </option>

            {FINDING_OBSERVATION_STATES.map(
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

        <label
          className="findings-filter"
          htmlFor="finding-disposition-filter"
        >
          <span>Disposition</span>

          <Select
            id="finding-disposition-filter"
            value={
              filters.disposition
              || ''
            }
            onChange={(event) =>
              onChange(
                'disposition',
                event.target.value,
              )
            }
          >
            <option value="">
              All dispositions
            </option>

            {FINDING_DISPOSITIONS.map(
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

        <label
          className="findings-filter"
          htmlFor="finding-assignee-filter"
        >
          <span>Assignee</span>

          <Select
            id="finding-assignee-filter"
            value={
              filters.assignee_user_id
              || ''
            }
            onChange={(event) =>
              onChange(
                'assignee_user_id',
                event.target.value,
              )
            }
          >
            <option value="">
              All assignees
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

        <label
          className="findings-filter"
          htmlFor="finding-owner-filter"
        >
          <span>
            Remediation owner
          </span>

          <Select
            id="finding-owner-filter"
            value={
              filters.remediation_owner_user_id
              || ''
            }
            onChange={(event) =>
              onChange(
                'remediation_owner_user_id',
                event.target.value,
              )
            }
          >
            <option value="">
              All remediation owners
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
      </div>

      {error && (
        <ErrorAlert
          message={error}
          className="finding-workflow-filter-error"
        />
      )}
    </section>
  )
}
