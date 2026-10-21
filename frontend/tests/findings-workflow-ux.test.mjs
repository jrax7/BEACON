import assert from 'node:assert/strict'
import fs from 'node:fs'
import test from 'node:test'


function source(path) {
  try {
    return fs.readFileSync(
      new URL(
        `../${path}`,
        import.meta.url,
      ),
      'utf8',
    )
  } catch (error) {
    if (error.code === 'ENOENT') {
      return ''
    }

    throw error
  }
}


test(
  'findings API exposes workflow mutations history and retests',
  () => {
    const api = source(
      'src/api/findings.js',
    )

    for (const symbol of [
      'updateFindingLifecycle',
      'setFindingDisposition',
      'clearFindingDisposition',
      'updateFindingAssignee',
      'updateFindingRemediationOwner',
      'getFindingHistory',
      'createFindingRetest',
      'listFindingRetests',
    ]) {
      assert.match(
        api,
        new RegExp(
          `export (?:async )?function ${symbol}`,
        ),
      )
    }

    for (const suffix of [
      '/lifecycle',
      '/disposition',
      '/assignee',
      '/remediation-owner',
      '/history',
      '/retests',
    ]) {
      assert.match(
        api,
        new RegExp(
          suffix.replace(
            '/',
            '\\/',
          ),
        ),
      )
    }
  },
)


test(
  'frontend RBAC gives finding management only to analyst and admin',
  () => {
    const rbac = source(
      'src/auth/rbac.js',
    )

    assert.match(
      rbac,
      /FINDING_MANAGE/,
    )

    assert.match(
      rbac,
      /finding\.manage/,
    )

    const viewerStart =
      rbac.indexOf(
        'const VIEWER_PERMISSIONS',
      )

    const analystStart =
      rbac.indexOf(
        'const ANALYST_PERMISSIONS',
      )

    const adminStart =
      rbac.indexOf(
        'const ADMIN_PERMISSIONS',
      )

    assert.ok(
      viewerStart >= 0,
    )

    assert.ok(
      analystStart > viewerStart,
    )

    assert.ok(
      adminStart > analystStart,
    )

    const viewer =
      rbac.slice(
        viewerStart,
        analystStart,
      )

    const analyst =
      rbac.slice(
        analystStart,
        adminStart,
      )

    assert.doesNotMatch(
      viewer,
      /FINDING_MANAGE/,
    )

    assert.match(
      analyst,
      /FINDING_MANAGE/,
    )
  },
)


test(
  'findings helpers expose workflow filter enums and URL keys',
  () => {
    const helpers = source(
      'src/pages/findings/helpers.js',
    )

    for (const symbol of [
      'FINDING_LIFECYCLE_STATES',
      'FINDING_OBSERVATION_STATES',
      'FINDING_DISPOSITIONS',
    ]) {
      assert.match(
        helpers,
        new RegExp(symbol),
      )
    }

    for (const key of [
      'lifecycle_state',
      'observation_state',
      'disposition',
      'assignee_user_id',
      'remediation_owner_user_id',
    ]) {
      assert.match(
        helpers,
        new RegExp(
          `['"]${key}['"]`,
        ),
      )
    }
  },
)


test(
  'findings list exposes workflow filters using workspace members',
  () => {
    const page = source(
      'src/pages/findings/FindingsPage.jsx',
    )

    const filters = source(
      'src/pages/findings/FindingWorkflowFilters.jsx',
    )

    assert.match(
      page,
      /FindingWorkflowFilters/,
    )

    assert.match(
      filters,
      /listOrganizationMembers/,
    )

    for (const label of [
      'Lifecycle',
      'Observation',
      'Disposition',
      'Assignee',
      'Remediation owner',
    ]) {
      assert.match(
        filters,
        new RegExp(
          label,
          'i',
        ),
      )
    }
  },
)


test(
  'finding detail composes workflow history and retest UX',
  () => {
    const page = source(
      'src/pages/findings/FindingDetailPage.jsx',
    )

    const panel = source(
      'src/pages/findings/FindingWorkflowPanel.jsx',
    )

    assert.match(
      page,
      /FindingWorkflowPanel/,
    )

    assert.match(
      panel,
      /PERMISSIONS\.FINDING_MANAGE/,
    )

    assert.match(
      panel,
      /hasPermission/,
    )

    assert.match(
      panel,
      /isDemoUser/,
    )

    for (const text of [
      'Workflow',
      'Lifecycle',
      'Assignee',
      'Remediation owner',
      'Disposition',
      'Workflow history',
      'Retests',
    ]) {
      assert.match(
        panel,
        new RegExp(
          text,
          'i',
        ),
      )
    }

    for (const symbol of [
      'updateFindingLifecycle',
      'setFindingDisposition',
      'clearFindingDisposition',
      'updateFindingAssignee',
      'updateFindingRemediationOwner',
      'getFindingHistory',
      'createFindingRetest',
      'listFindingRetests',
    ]) {
      assert.match(
        panel,
        new RegExp(symbol),
      )
    }
  },
)


test(
  'viewer and demo workflow surfaces stay read only',
  () => {
    const panel = source(
      'src/pages/findings/FindingWorkflowPanel.jsx',
    )

    assert.match(
      panel,
      /const canManage/,
    )

    assert.match(
      panel,
      /!isDemoUser\(user\)/,
    )

    assert.match(
      panel,
      /hasPermission\(\s*user,\s*PERMISSIONS\.FINDING_MANAGE/,
    )

    assert.match(
      panel,
      /\{canManage && \(/,
    )

    assert.match(
      panel,
      /read-only access/i,
    )
  },
)


test(
  'duplicate disposition submits canonical raw finding identity',
  () => {
    const panel = source(
      'src/pages/findings/FindingWorkflowPanel.jsx',
    )

    assert.match(
      panel,
      /primary_finding_id/,
    )

    assert.match(
      panel,
      /duplicate_of_finding_id/,
    )

    assert.match(
      panel,
      /listFindings/,
    )
  },
)


test(
  'retest request does not retroactively select an old assessment',
  () => {
    const panel = source(
      'src/pages/findings/FindingWorkflowPanel.jsx',
    )

    assert.doesNotMatch(
      panel,
      /listScans/,
    )

    assert.doesNotMatch(
      panel,
      /retestScanId/,
    )

    assert.match(
      panel,
      /createFindingRetest\(\s*findingId\s*,?\s*\)/,
    )

    assert.match(
      panel,
      /fresh validating assessment/i,
    )
  },
)


test(
  'workflow UI uses findings design surface',
  () => {
    const css = source(
      'src/styles/pages/findings.css',
    )

    for (const className of [
      'finding-workflow-panel',
      'finding-workflow-grid',
      'finding-workflow-history',
      'finding-retest-list',
      'finding-workflow-filters',
    ]) {
      assert.match(
        css,
        new RegExp(
          `\\.${className}`,
        ),
      )
    }
  },
)
