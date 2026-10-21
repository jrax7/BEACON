import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import test from 'node:test'


const ROOT = process.cwd()


function read(relative) {
  const filename =
    path.join(
      ROOT,
      relative,
    )

  return fs.existsSync(filename)
    ? fs.readFileSync(
        filename,
        'utf8',
      )
    : ''
}


test(
  'organization API exposes workspace member and invitation lifecycle',
  () => {
    const source = read(
      'src/api/organization.js',
    )

    for (const token of [
      '/organizations',
      '/organization',
      '/organization/members',
      '/organization/invitations',
      'resend',
      'resolve',
      'accept',
      'DELETE',
      'PATCH',
    ]) {
      assert.match(
        source,
        new RegExp(token),
      )
    }
  },
)


test(
  'frontend RBAC mirrors the three organization roles',
  () => {
    const source = read(
      'src/auth/rbac.js',
    )

    for (const role of [
      'admin',
      'analyst',
      'viewer',
    ]) {
      assert.match(
        source,
        new RegExp(role),
      )
    }

    for (const permission of [
      'TARGET_CREATE',
      'TARGET_VERIFY',
      'TARGET_DELETE',
      'ASSESSMENT_CREATE',
      'ASSESSMENT_CANCEL',
      'ASSESSMENT_LIFECYCLE',
      'ASSESSMENT_DELETE',
      'REPORT_GENERATE',
      'REPORT_LIFECYCLE',
      'REPORT_DELETE',
      'MEMBER_MANAGE',
    ]) {
      assert.match(
        source,
        new RegExp(permission),
      )
    }

    assert.match(
      source,
      /organization_role/,
    )

    assert.match(
      source,
      /can|hasPermission/,
    )
  },
)


test(
  'multi-organization switching uses request-scoped organization context',
  () => {
    const client = read('src/api/client.js')
    const auth = read('src/auth/AuthContext.jsx')
    const layout = read('src/components/AppLayout.jsx')
    const invite = read('src/pages/InvitationPage.jsx')

    assert.match(client, /X-Organization-ID/)
    assert.match(auth, /switchOrganization/)
    assert.match(auth, /organizations/)
    assert.match(layout, /Active workspace/)
    assert.match(invite, /acceptOrganizationInvitation/)
    assert.match(invite, /existing BEACON account/)
  },
)


test(
  'workspace switching persists through the server session without browser storage',
  () => {
    const api = read('src/api/organization.js')
    const context = read('src/auth/AuthContext.jsx')
    assert.match(api, /organization\/active/)
    assert.match(context, /setActiveOrganizationPreference/)
    assert.doesNotMatch(context, /localStorage|sessionStorage/)
  },
)


test(
  'auth context exposes server organization metadata',
  () => {
    const source = read(
      'src/auth/AuthContext.jsx',
    )

    for (const field of [
      'organization_id',
      'organization_name',
      'organization_role',
    ]) {
      assert.match(
        source,
        new RegExp(field),
      )
    }

    assert.match(
      source,
      /hasPermission|can/,
    )
  },
)


test(
  'registration forwards invitation token from URL',
  () => {
    const auth = read(
      'src/api/auth.js',
    )

    const register = read(
      'src/pages/RegisterPage.jsx',
    )

    assert.match(
      auth,
      /invitation_token/,
    )

    assert.match(
      register,
      /useSearchParams/,
    )

    assert.match(
      register,
      /invitation/,
    )

    assert.match(
      register,
      /resolveOrganizationInvitation/,
    )
  },
)


test(
  'settings exposes workspace role members and pending invitations',
  () => {
    const source = read(
      'src/pages/settings/SettingsPage.jsx',
    )

    for (const token of [
      'Workspace',
      'Your role',
      'Members',
      'Pending invitations',
      'Invite member',
      'Operator profile',
      'Current session',
      'Change password',
    ]) {
      assert.match(
        source,
        new RegExp(token),
      )
    }

    assert.match(
      source,
      /MEMBER_MANAGE/,
    )

    assert.match(
      source,
      /ORGANIZATION_MANAGE/,
    )
  },
)


test(
  'layout shows organization name and organization role',
  () => {
    const source = read(
      'src/components/AppLayout.jsx',
    )

    assert.match(
      source,
      /organization_name/,
    )

    assert.match(
      source,
      /organization_role/,
    )

    assert.match(
      source,
      /full_name/,
    )

    assert.match(
      source,
      /email/,
    )
  },
)


test(
  'target mutation surfaces use organization RBAC',
  () => {
    const targets = read(
      'src/pages/targets/TargetsPage.jsx',
    )

    const detail = read(
      'src/pages/targets/TargetDetailPage.jsx',
    )

    assert.match(
      targets,
      /TARGET_CREATE/,
    )

    assert.match(
      detail,
      /TARGET_VERIFY/,
    )

    assert.match(
      detail,
      /TARGET_DELETE/,
    )

    assert.match(
      detail,
      /ASSESSMENT_CREATE/,
    )
  },
)


test(
  'assessment lifecycle distinguishes analyst lifecycle from admin delete',
  () => {
    const page = read(
      'src/pages/scans/ScansPage.jsx',
    )

    const launch = read(
      'src/pages/scans/NewAssessmentPage.jsx',
    )

    assert.match(
      page,
      /ASSESSMENT_LIFECYCLE/,
    )

    assert.match(
      page,
      /ASSESSMENT_DELETE/,
    )

    assert.match(
      page,
      /ASSESSMENT_CREATE/,
    )

    assert.match(
      launch,
      /ASSESSMENT_CREATE/,
    )
  },
)


test(
  'assessment detail uses cancel and report permissions',
  () => {
    const detail = read(
      'src/pages/scan-detail/ScanDetailPage.jsx',
    )

    const reports = read(
      'src/pages/scan-detail/ReportsTab.jsx',
    )

    assert.match(
      detail,
      /ASSESSMENT_CANCEL/,
    )

    assert.match(
      detail,
      /cancelAssessment/,
    )

    assert.match(
      detail,
      /REPORT_GENERATE/,
    )

    assert.match(
      detail,
      /REPORT_LIFECYCLE/,
    )

    assert.match(
      detail,
      /REPORT_DELETE/,
    )

    assert.match(
      reports,
      /canGenerateReports/,
    )

    assert.match(
      reports,
      /canLifecycleReports/,
    )

    assert.match(
      reports,
      /canDeleteReports/,
    )
  },
)


test(
  'global report lifecycle distinguishes analyst lifecycle from admin delete',
  () => {
    const source = read(
      'src/pages/reports/ReportsPage.jsx',
    )

    assert.match(
      source,
      /REPORT_LIFECYCLE/,
    )

    assert.match(
      source,
      /REPORT_DELETE/,
    )
  },
)


test(
  'demo policy remains layered separately from organization role',
  () => {
    const rbac = read(
      'src/auth/rbac.js',
    )

    const demo = read(
      'src/auth/demo-access.js',
    )

    assert.match(
      demo,
      /user\?\.role === 'demo'/,
    )

    assert.doesNotMatch(
      rbac,
      /user\?\.role === 'demo'/,
    )
  },
)


test(
  'workspace switcher uses the BEACON menu instead of a native select popup',
  () => {
    const layout = read(
      'src/components/AppLayout.jsx',
    )
    const styles = read(
      'src/styles/layout.css',
    )

    assert.match(layout, /aria-haspopup="listbox"/)
    assert.match(layout, /sidebar-workspace-menu/)
    assert.match(layout, /sidebar-workspace-option/)
    assert.doesNotMatch(layout, /sidebar-workspace-select/)
    assert.match(styles, /\.sidebar-workspace-trigger/)
    assert.match(styles, /\.sidebar-workspace-menu/)
  },
)


test(
  'settings presents pending invitations as compact lifecycle rows',
  () => {
    const settings = read(
      'src/pages/settings/SettingsPage.jsx',
    )
    const styles = read(
      'src/styles/pages/settings.css',
    )

    assert.match(settings, /settings-invitation-row/)
    assert.match(settings, /settings-pending-badge/)
    assert.match(settings, /pending/)
    assert.match(styles, /\.settings-invitation-list/)
    assert.match(styles, /\.settings-invitation-row/)
  },
)


test(
  'settings defensively renders only active pending invitations',
  () => {
    const settings = read(
      'src/pages/settings/SettingsPage.jsx',
    )

    assert.match(settings, /isPendingInvitation/)
    assert.match(settings, /accepted_at/)
    assert.match(settings, /revoked_at/)
    assert.match(settings, /expires_at/)
    assert.match(settings, /Date\.now\(\)/)
    assert.match(settings, /\.filter\(\s*isPendingInvitation/)
  },
)
