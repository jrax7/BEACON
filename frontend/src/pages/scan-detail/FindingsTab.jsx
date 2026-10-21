import { Link } from 'react-router'

import { EmptyState } from '../../components/ui'
import { severityBadgeClass } from '../../lib/format'
import { buildFindingsPath } from '../findings/helpers'
import {
  FINDING_CLASSIFICATIONS,
  ISSUES_PER_PAGE,
  classificationLabel,
  displayToolName,
  issueSources,
  normalize,
  requiresManualValidation,
} from './helpers'
import { FindingSelect, UnavailablePanel } from './parts'

export default function FindingsTab({
  scan,
  issues,
  correlatedResultCount,
  classificationCounts,
  filters,
  availableTools,
  filteredIssues,
  pagedIssues,
  issuePage,
  totalIssuePages,
  setIssuePage,
}) {
  const {
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
  } = filters

  if (scan.status !== 'completed') {
    return (
      <div className="assessment-tab-panel">
        <UnavailablePanel
          kicker="FINDINGS"
          title="Assessment results are still being collected"
          message="Classified results become available when scanner execution and normalization are complete."
        />
      </div>
    )
  }

  return (
    <div className="assessment-tab-panel">
      <section className="scan-console-card issues-card">
        <div className="console-card-heading findings-heading">
          <div>
            <p className="scan-kicker">CLASSIFIED RESULTS</p>
            <h2>Security findings and assessment context</h2>
          </div>
          <span className="console-heading-meta">
            {filteredIssues.length} shown · {correlatedResultCount} classified
          </span>

          <Link
            className="secondary-button compact-button"
            to={buildFindingsPath({
              scan_id: scan.id,
            })}
          >
            Open in Findings workspace
          </Link>
        </div>

        <div className="finding-classification-grid">
          {FINDING_CLASSIFICATIONS.map(([classification, label]) => (
            <button
              type="button"
              className={`finding-classification-card classification-${classification}${
                classificationFilter === classification ? ' active' : ''
              }`}
              key={classification}
              onClick={() => setClassificationFilter(classification)}
            >
              <span>{label}</span>
              <strong>{classificationCounts[classification]}</strong>
            </button>
          ))}
        </div>

        <div className="finding-filter-bar">
          <label className="finding-search-field">
            <span>Search findings</span>
            <input
              type="search"
              value={issueSearch}
              placeholder="Title, URL, remediation..."
              onChange={(event) => setIssueSearch(event.target.value)}
            />
          </label>

          <FindingSelect
            label="Classification"
            value={classificationFilter}
            onChange={setClassificationFilter}
            options={[['all', 'All classified results'], ...FINDING_CLASSIFICATIONS]}
          />

          <FindingSelect
            label="Severity"
            value={severityFilter}
            onChange={setSeverityFilter}
            options={[
              ['all', 'All severities'],
              ['critical', 'Critical'],
              ['high', 'High'],
              ['medium', 'Medium'],
              ['low', 'Low'],
              ['informational', 'Informational'],
            ]}
          />

          <FindingSelect
            label="Scanner"
            value={toolFilter}
            onChange={setToolFilter}
            options={[
              ['all', 'All scanners'],
              ...availableTools.map((tool) => [tool, displayToolName(tool)]),
            ]}
          />

          <FindingSelect
            label="Confidence"
            value={confidenceFilter}
            onChange={setConfidenceFilter}
            options={[
              ['all', 'All confidence'],
              ['high', 'High'],
              ['medium', 'Medium'],
              ['low', 'Low'],
              ['10', 'Scanner score 10'],
            ]}
          />

          <FindingSelect
            label="Validation"
            value={validationFilter}
            onChange={setValidationFilter}
            options={[
              ['all', 'All results'],
              ['required', 'Manual validation'],
              ['standard', 'Standard findings'],
            ]}
          />
        </div>

        {issues && issues.total_groups > issues.items.length && (
          <div className="finding-limit-note">
            This view loaded the first {issues.items.length} grouped issues from the API.
            Server-side search/filtering can be added later if a scan exceeds 100 distinct groups.
          </div>
        )}

        {pagedIssues.length === 0 ? (
          <EmptyState
            title="No classified results match these filters"
            message="Clear one or more filters to broaden the result set."
          />
        ) : (
          <div className="issues-list">
            {pagedIssues.map((issue) => (
              <IssueRow key={issue.issue_key} issue={issue} />
            ))}
          </div>
        )}

        {filteredIssues.length > ISSUES_PER_PAGE && (
          <div className="findings-pagination">
            <button
              type="button"
              className="secondary-button compact-button"
              disabled={issuePage === 1}
              onClick={() => setIssuePage((page) => Math.max(1, page - 1))}
            >
              ← Previous
            </button>

            <span>
              Page {issuePage} of {totalIssuePages}
            </span>

            <button
              type="button"
              className="secondary-button compact-button"
              disabled={issuePage === totalIssuePages}
              onClick={() => setIssuePage((page) => Math.min(totalIssuePages, page + 1))}
            >
              Next →
            </button>
          </div>
        )}
      </section>
    </div>
  )
}

function IssueRow({ issue }) {
  const manualValidation = requiresManualValidation(issue)
  const sources = issueSources(issue)
  const isCrossEngine = sources.length > 1
  const classification = normalize(issue.classification) || 'security_issue'

  return (
    <article className="issue-row">
      <div className="issue-main">
        <div className="issue-title-row">
          <span className={`issue-classification-badge classification-${classification}`}>
            {classificationLabel(classification)}
          </span>

          {classification === 'security_issue' && (
            <span className={severityBadgeClass(issue.severity)}>{issue.severity}</span>
          )}

          {isCrossEngine ? (
            <span className="issue-correlation-badge">cross-engine</span>
          ) : (
            <span className="issue-tool">
              {displayToolName(normalize(sources[0]?.tool_name || issue.tool_name))}
            </span>
          )}
          {issue.confidence && (
            <span className="issue-confidence">confidence: {issue.confidence}</span>
          )}
          {manualValidation && (
            <span className="manual-validation-badge">manual validation</span>
          )}
          <span className="issue-count">
            {issue.occurrence_count} occurrence{issue.occurrence_count === 1 ? '' : 's'}
          </span>
        </div>
        <strong>{issue.title}</strong>

        {sources.length > 0 && (
          <div className="issue-source-row">
            <span className="issue-source-label">
              {isCrossEngine ? 'Confirmed by' : 'Observed by'}
            </span>

            <div className="issue-source-badges">
              {sources.map((source) => (
                <span
                  className={`issue-source-badge${isCrossEngine ? ' confirmed' : ''}`}
                  key={normalize(source.tool_name)}
                  title={`${source.occurrence_count} observation${
                    source.occurrence_count === 1 ? '' : 's'
                  }`}
                >
                  {displayToolName(normalize(source.tool_name))}
                </span>
              ))}
            </div>

            {isCrossEngine && (
              <span className="issue-source-meta">
                {sources.length} scanners
                {' · '}
                {issue.affected_url_count} affected resource
                {issue.affected_url_count === 1 ? '' : 's'}
              </span>
            )}
          </div>
        )}

        {issue.cwe_id && <span className="issue-cwe">{issue.cwe_id}</span>}

        {issue.description && <p>{issue.description}</p>}
        {issue.sample_affected_urls?.length > 0 && (
          <code>{issue.sample_affected_urls[0]}</code>
        )}
      </div>

      {issue.remediation && (
        <div className="issue-remediation">
          <span>
            {classification === 'security_issue' ? 'Recommended action' : 'Assessment guidance'}
          </span>
          <p>{issue.remediation}</p>
        </div>
      )}
    </article>
  )
}
