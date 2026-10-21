export const ORGANIZATION_ROLES =
  Object.freeze({
    ADMIN:
      'admin',
    ANALYST:
      'analyst',
    VIEWER:
      'viewer',
  })


export const PERMISSIONS =
  Object.freeze({
    ORGANIZATION_READ:
      'organization.read',
    ORGANIZATION_MANAGE:
      'organization.manage',
    MEMBER_MANAGE:
      'member.manage',

    TARGET_READ:
      'target.read',
    TARGET_CREATE:
      'target.create',
    TARGET_VERIFY:
      'target.verify',
    TARGET_DELETE:
      'target.delete',

    ASSESSMENT_READ:
      'assessment.read',
    ASSESSMENT_CREATE:
      'assessment.create',
    ASSESSMENT_CANCEL:
      'assessment.cancel',
    ASSESSMENT_LIFECYCLE:
      'assessment.lifecycle',
    ASSESSMENT_DELETE:
      'assessment.delete',

    FINDING_READ:
      'finding.read',

    FINDING_MANAGE:
      'finding.manage',
    REPORT_READ:
      'report.read',
    REPORT_GENERATE:
      'report.generate',
    REPORT_LIFECYCLE:
      'report.lifecycle',
    REPORT_DELETE:
      'report.delete',
  })


const VIEWER_PERMISSIONS =
  new Set([
    PERMISSIONS.ORGANIZATION_READ,
    PERMISSIONS.TARGET_READ,
    PERMISSIONS.ASSESSMENT_READ,
    PERMISSIONS.FINDING_READ,
    PERMISSIONS.REPORT_READ,
  ])


const ANALYST_PERMISSIONS =
  new Set([
    ...VIEWER_PERMISSIONS,

    PERMISSIONS.TARGET_CREATE,
    PERMISSIONS.TARGET_VERIFY,

    PERMISSIONS.ASSESSMENT_CREATE,
    PERMISSIONS.ASSESSMENT_CANCEL,
    PERMISSIONS.ASSESSMENT_LIFECYCLE,

    PERMISSIONS.FINDING_MANAGE,
    PERMISSIONS.REPORT_GENERATE,
    PERMISSIONS.REPORT_LIFECYCLE,
  ])


const ADMIN_PERMISSIONS =
  new Set(
    Object.values(
      PERMISSIONS,
    ),
  )


const ROLE_PERMISSIONS =
  new Map([
    [
      ORGANIZATION_ROLES.VIEWER,
      VIEWER_PERMISSIONS,
    ],
    [
      ORGANIZATION_ROLES.ANALYST,
      ANALYST_PERMISSIONS,
    ],
    [
      ORGANIZATION_ROLES.ADMIN,
      ADMIN_PERMISSIONS,
    ],
  ])


export function organizationRole(
  user,
) {
  return (
    user?.organization_role
    || null
  )
}


export function hasPermission(
  user,
  permission,
) {
  const role =
    organizationRole(
      user,
    )

  return Boolean(
    role
    && ROLE_PERMISSIONS
      .get(role)
      ?.has(permission),
  )
}


export function can(
  user,
  permission,
) {
  return hasPermission(
    user,
    permission,
  )
}
