import { Input, Select } from '../../components/ui'

import {
  FINDING_CLASSIFICATIONS,
  FINDING_SEVERITIES,
} from './helpers'


export default function FindingsFilters({
  filters,
  targetOptions = [],
  assessmentOptions = [],
  sourceToolOptions = [],
  selectedTargetValue = '',
  selectedAssessmentValue = '',
  selectedToolValue = '',
  metadataLoading = false,
  metadataError = '',
  onChange,
  onTargetChange,
  onReset,
  hasActiveFilters,
}) {
  return (
    <section
      className="findings-filter-panel"
      aria-label="Finding filters"
    >
      <label
        className="findings-filter findings-search-filter"
        htmlFor="findings-search"
      >
        <span>Search</span>

        <Input
          id="findings-search"
          type="search"
          value={filters.q || ''}
          placeholder="Search findings"
          onChange={(event) => (
            onChange(
              'q',
              event.target.value,
            )
          )}
        />
      </label>

      <label
        className="findings-filter findings-filter-target"
        htmlFor="findings-target"
      >
        <span>Target</span>

        <Select
          id="findings-target"
          value={selectedTargetValue}
          disabled={metadataLoading}
          onChange={(event) => (
            onTargetChange(
              event.target.value,
            )
          )}
        >
          <option value="">
            All targets
          </option>

          {targetOptions.map(
            (option) => (
              <option
                key={option.value}
                value={option.value}
              >
                {option.label}
              </option>
            ),
          )}
        </Select>
      </label>

      <label
        className="findings-filter findings-filter-assessment"
        htmlFor="findings-assessment"
      >
        <span>Assessment</span>

        <Select
          id="findings-assessment"
          value={selectedAssessmentValue}
          disabled={metadataLoading}
          onChange={(event) => (
            onChange(
              'scan_id',
              event.target.value,
            )
          )}
        >
          <option value="">
            All assessments
          </option>

          {assessmentOptions.map(
            (option) => (
              <option
                key={option.value}
                value={option.value}
              >
                {option.label}
              </option>
            ),
          )}
        </Select>
      </label>

      <label
        className="findings-filter findings-filter-severity"
        htmlFor="findings-severity"
      >
        <span>Severity</span>

        <Select
          id="findings-severity"
          value={filters.severity || ''}
          onChange={(event) => (
            onChange(
              'severity',
              event.target.value,
            )
          )}
        >
          <option value="">
            All severities
          </option>

          {FINDING_SEVERITIES.map(
            (severity) => (
              <option
                key={severity}
                value={severity}
              >
                {severity}
              </option>
            ),
          )}
        </Select>
      </label>

      <label
        className="findings-filter findings-filter-confidence"
        htmlFor="findings-confidence"
      >
        <span>Confidence</span>

        <Select
          id="findings-confidence"
          value={filters.confidence || ''}
          onChange={(event) => (
            onChange(
              'confidence',
              event.target.value,
            )
          )}
        >
          <option value="">
            All confidence levels
          </option>
          <option value="high">
            High
          </option>
          <option value="medium">
            Medium
          </option>
          <option value="low">
            Low
          </option>
        </Select>
      </label>

      <label
        className="findings-filter findings-filter-tool"
        htmlFor="findings-tool"
      >
        <span>Source tool</span>

        <Select
          id="findings-tool"
          value={selectedToolValue}
          disabled={metadataLoading}
          onChange={(event) => (
            onChange(
              'tool',
              event.target.value,
            )
          )}
        >
          <option value="">
            All source tools
          </option>

          {sourceToolOptions.map(
            (option) => (
              <option
                key={option.value}
                value={option.value}
              >
                {option.label}
              </option>
            ),
          )}
        </Select>
      </label>

      <label
        className="findings-filter findings-filter-classification"
        htmlFor="findings-classification"
      >
        <span>Classification</span>

        <Select
          id="findings-classification"
          value={filters.classification || ''}
          onChange={(event) => (
            onChange(
              'classification',
              event.target.value,
            )
          )}
        >
          <option value="">
            All classifications
          </option>

          {FINDING_CLASSIFICATIONS.map(
            (classification) => (
              <option
                key={classification}
                value={classification}
              >
                {classification.replaceAll(
                  '_',
                  ' ',
                )}
              </option>
            ),
          )}
        </Select>
      </label>

      {metadataError && (
        <p
          className="findings-filter-metadata-error"
          role="alert"
        >
          {metadataError}
        </p>
      )}

      <div className="findings-filter-actions">
        <button
          type="button"
          className="secondary-button"
          onClick={onReset}
          disabled={!hasActiveFilters}
        >
          Reset filters
        </button>
      </div>
    </section>
  )
}
