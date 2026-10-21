import {
  useCallback,
  useEffect,
  useState,
} from 'react'

import {
  useNavigate,
} from 'react-router'

import {
  changePassword,
} from '../../api/auth'

import {
  createOrganizationInvitation,
  deleteOrganizationMember,
  getOrganization,
  listOrganizationInvitations,
  listOrganizationMembers,
  resendOrganizationInvitation,
  revokeOrganizationInvitation,
  updateOrganization,
  updateOrganizationMember,
} from '../../api/organization'

import {
  PERMISSIONS,
} from '../../auth/rbac'

import {
  useAuth,
} from '../../auth/useAuth'

import {
  Avatar,
  Card,
  ErrorAlert,
  FormField,
  Input,
  PageHeader,
  Select,
  SkeletonList,
  SuccessAlert,
} from '../../components/ui'


const ORGANIZATION_ROLES = [
  'viewer',
  'analyst',
  'admin',
]


function normalizeList(
  result,
  key,
) {
  if (Array.isArray(result)) {
    return result
  }

  if (Array.isArray(result?.[key])) {
    return result[key]
  }

  return []
}


function membershipId(
  member,
) {
  return (
    member?.membership_id
    || member?.id
    || null
  )
}


function invitationId(
  invitation,
) {
  return (
    invitation?.invitation_id
    || invitation?.id
    || null
  )
}


function isPendingInvitation(
  invitation,
) {
  if (
    invitation?.accepted_at
    || invitation?.revoked_at
  ) {
    return false
  }

  const expiresAt = Date.parse(
    invitation?.expires_at || '',
  )

  return (
    Number.isNaN(expiresAt)
    || expiresAt > Date.now()
  )
}


function memberEmail(
  member,
) {
  return (
    member?.email
    || member?.user_email
    || member?.user?.email
    || ''
  )
}


function memberName(
  member,
) {
  return (
    member?.full_name
    || member?.user?.full_name
    || memberEmail(member)
    || 'Workspace member'
  )
}



export default function SettingsPage() {
  const {
    user,
    logout,
    organizationName,
    organizationRole,
    hasPermission,
  } = useAuth()

  const navigate =
    useNavigate()

  const canManageOrganization =
    hasPermission(
      PERMISSIONS.ORGANIZATION_MANAGE,
    )

  const canManageMembers =
    hasPermission(
      PERMISSIONS.MEMBER_MANAGE,
    )

  const [
    workspaceName,
    setWorkspaceName,
  ] = useState(
    organizationName || '',
  )

  const [
    members,
    setMembers,
  ] = useState([])

  const [
    invitations,
    setInvitations,
  ] = useState([])

  const [
    workspaceLoading,
    setWorkspaceLoading,
  ] = useState(true)

  const [
    workspaceBusy,
    setWorkspaceBusy,
  ] = useState(false)

  const [
    workspaceError,
    setWorkspaceError,
  ] = useState('')

  const [
    workspaceMessage,
    setWorkspaceMessage,
  ] = useState('')

  const [
    inviteEmail,
    setInviteEmail,
  ] = useState('')

  const [
    inviteRole,
    setInviteRole,
  ] = useState('analyst')

  const [
    currentPassword,
    setCurrentPassword,
  ] = useState('')

  const [
    newPassword,
    setNewPassword,
  ] = useState('')

  const [
    confirmPassword,
    setConfirmPassword,
  ] = useState('')

  const [
    passwordError,
    setPasswordError,
  ] = useState('')

  const [
    passwordSubmitting,
    setPasswordSubmitting,
  ] = useState(false)


  const loadWorkspace =
    useCallback(
      async () => {
        setWorkspaceLoading(true)
        setWorkspaceError('')

        try {
          const [
            organizationResult,
            membersResult,
          ] = await Promise.all([
            getOrganization(),
            listOrganizationMembers(),
          ])

          const organization =
            organizationResult?.organization
            || organizationResult

          setWorkspaceName(
            organization?.name
            || organizationName
            || '',
          )

          setMembers(
            normalizeList(
              membersResult,
              'members',
            ),
          )

          if (canManageMembers) {
            const invitationResult =
              await listOrganizationInvitations()

            setInvitations(
              normalizeList(
                invitationResult,
                'invitations',
              ).filter(
                isPendingInvitation,
              ),
            )
          } else {
            setInvitations([])
          }
        } catch (requestError) {
          setWorkspaceError(
            requestError.message
            || 'Unable to load workspace settings.',
          )
        } finally {
          setWorkspaceLoading(false)
        }
      },
      [
        canManageMembers,
        organizationName,
      ],
    )


  useEffect(() => {
    loadWorkspace()
  }, [
    loadWorkspace,
  ])


  async function submitWorkspace(
    event,
  ) {
    event.preventDefault()

    if (
      !canManageOrganization
      || workspaceBusy
    ) {
      return
    }

    const name =
      workspaceName.trim()

    if (!name) {
      setWorkspaceError(
        'Workspace name is required.',
      )

      return
    }

    setWorkspaceBusy(true)
    setWorkspaceError('')
    setWorkspaceMessage('')

    try {
      await updateOrganization(
        name,
      )

      setWorkspaceName(
        name,
      )

      setWorkspaceMessage(
        'Workspace updated.',
      )
    } catch (requestError) {
      setWorkspaceError(
        requestError.message
        || 'Unable to update workspace.',
      )
    } finally {
      setWorkspaceBusy(false)
    }
  }


  async function submitInvitation(
    event,
  ) {
    event.preventDefault()

    if (
      !canManageMembers
      || workspaceBusy
    ) {
      return
    }

    const email =
      inviteEmail.trim()

    if (!email) {
      setWorkspaceError(
        'Member email is required.',
      )

      return
    }

    setWorkspaceBusy(true)
    setWorkspaceError('')
    setWorkspaceMessage('')

    try {
      await createOrganizationInvitation({
        email,
        role:
          inviteRole,
      })

      setInviteEmail('')

      setWorkspaceMessage(
        'Invitation created and delivery queued.',
      )

      await loadWorkspace()
    } catch (requestError) {
      setWorkspaceError(
        requestError.message
        || 'Unable to invite member.',
      )
    } finally {
      setWorkspaceBusy(false)
    }
  }


  async function changeMemberRole(
    member,
    role,
  ) {
    if (
      !canManageMembers
      || workspaceBusy
    ) {
      return
    }

    const id =
      membershipId(
        member,
      )

    if (!id) {
      return
    }

    setWorkspaceBusy(true)
    setWorkspaceError('')
    setWorkspaceMessage('')

    try {
      await updateOrganizationMember(
        id,
        role,
      )

      setWorkspaceMessage(
        'Member role updated.',
      )

      await loadWorkspace()
    } catch (requestError) {
      setWorkspaceError(
        requestError.message
        || 'Unable to update member role.',
      )
    } finally {
      setWorkspaceBusy(false)
    }
  }


  async function removeMember(
    member,
  ) {
    if (
      !canManageMembers
      || workspaceBusy
    ) {
      return
    }

    const id =
      membershipId(
        member,
      )

    if (!id) {
      return
    }

    setWorkspaceBusy(true)
    setWorkspaceError('')
    setWorkspaceMessage('')

    try {
      await deleteOrganizationMember(
        id,
      )

      setWorkspaceMessage(
        'Member removed.',
      )

      await loadWorkspace()
    } catch (requestError) {
      setWorkspaceError(
        requestError.message
        || 'Unable to remove member.',
      )
    } finally {
      setWorkspaceBusy(false)
    }
  }


  async function resendInvitation(
    invitation,
  ) {
    if (
      !canManageMembers
      || workspaceBusy
    ) {
      return
    }

    const id =
      invitationId(
        invitation,
      )

    if (!id) {
      return
    }

    setWorkspaceBusy(true)
    setWorkspaceError('')
    setWorkspaceMessage('')

    try {
      await resendOrganizationInvitation(
        id,
      )

      setWorkspaceMessage(
        'Invitation delivery queued again.',
      )

      await loadWorkspace()
    } catch (requestError) {
      setWorkspaceError(
        requestError.message
        || 'Unable to resend invitation.',
      )
    } finally {
      setWorkspaceBusy(false)
    }
  }


  async function revokeInvitation(
    invitation,
  ) {
    if (
      !canManageMembers
      || workspaceBusy
    ) {
      return
    }

    const id =
      invitationId(
        invitation,
      )

    if (!id) {
      return
    }

    setWorkspaceBusy(true)
    setWorkspaceError('')
    setWorkspaceMessage('')

    try {
      await revokeOrganizationInvitation(
        id,
      )

      setWorkspaceMessage(
        'Invitation revoked.',
      )

      await loadWorkspace()
    } catch (requestError) {
      setWorkspaceError(
        requestError.message
        || 'Unable to revoke invitation.',
      )
    } finally {
      setWorkspaceBusy(false)
    }
  }


  async function submitPasswordChange(
    event,
  ) {
    event.preventDefault()

    setPasswordError('')

    if (
      newPassword.length < 12
    ) {
      setPasswordError(
        'New password must contain at least 12 characters.',
      )

      return
    }

    if (
      newPassword !==
      confirmPassword
    ) {
      setPasswordError(
        'New passwords do not match.',
      )

      return
    }

    setPasswordSubmitting(true)

    try {
      await changePassword({
        currentPassword,
        newPassword,
      })

      /*
       * Password change revokes server-side sessions.
       * logout() also clears the AuthContext client state.
       */
      await logout()
        .catch(() => undefined)

      navigate(
        '/login',
        {
          replace: true,
          state: {
            message:
              'Password changed successfully. Sign in again with your new password.',
          },
        },
      )
    } catch (requestError) {
      setPasswordError(
        requestError.message
        || 'Unable to change password.',
      )
    } finally {
      setPasswordSubmitting(false)
    }
  }


  return (
    <>
      <PageHeader
        eyebrow="ACCOUNT"
        title="Settings"
        description="Manage your BEACON workspace, membership, operator profile, and current session."
      />

      <ErrorAlert
        message={workspaceError}
        className="page-message"
      />

      <SuccessAlert
        message={workspaceMessage}
        className="page-message"
      />

      <div className="settings-layout">
        <Card
          eyebrow="WORKSPACE"
          title="Workspace"
        >
          {workspaceLoading ? (
            <SkeletonList
              rows={3}
              label="Loading workspace settings"
            />
          ) : (
            <>
              <dl className="settings-details">
                <div>
                  <dt>Name</dt>

                  <dd>
                    {workspaceName || '—'}
                  </dd>
                </div>

                <div>
                  <dt>Workspace role · Your role</dt>

                  <dd>
                    {organizationRole || '—'}
                  </dd>
                </div>
              </dl>

              <p className="settings-role-help">
                <strong>Workspace role</strong> determines permissions within the current organization.
              </p>

              {canManageOrganization && (
                <form
                  className="settings-form"
                  onSubmit={submitWorkspace}
                >
                  <FormField
                    label="Workspace name"
                    htmlFor="settings-workspace-name"
                  >
                    <Input
                      id="settings-workspace-name"
                      type="text"
                      required
                      value={workspaceName}
                      disabled={workspaceBusy}
                      onChange={(event) =>
                        setWorkspaceName(
                          event.target.value,
                        )
                      }
                    />
                  </FormField>

                  <button
                    type="submit"
                    className="secondary-button"
                    disabled={workspaceBusy}
                  >
                    Save workspace
                  </button>
                </form>
              )}
            </>
          )}
        </Card>

        <Card
          eyebrow="ACCESS"
          title="Members"
        >
          {workspaceLoading ? (
            <SkeletonList
              rows={4}
              label="Loading workspace members"
            />
          ) : members.length === 0 ? (
            <p className="empty-state">
              No workspace members found.
            </p>
          ) : (
            <div className="settings-member-list">
              {members.map(
                (member) => {
                  const id =
                    membershipId(
                      member,
                    )

                  return (
                    <div
                      className="settings-member-row"
                      key={
                        id
                        || memberEmail(
                          member,
                        )
                      }
                    >
                      <Avatar
                        label={memberName(member)}
                        className="settings-member-avatar"
                      />

                      <div className="settings-member-identity">
                        <strong>
                          {memberName(
                            member,
                          )}
                        </strong>

                        <p
                          className="settings-member-email"
                          title={memberEmail(member)}
                        >
                          {memberEmail(
                            member,
                          )}
                        </p>
                      </div>

                      {canManageMembers ? (
                        <div className="settings-member-actions">
                          <Select
                            className="settings-role-select"
                            aria-label={`Workspace role for ${memberName(member)}`}
                            value={
                              member.role
                              || 'viewer'
                            }
                            disabled={
                              workspaceBusy
                              || !id
                            }
                            onChange={(event) =>
                              changeMemberRole(
                                member,
                                event.target.value,
                              )
                            }
                          >
                            {ORGANIZATION_ROLES.map(
                              (role) => (
                                <option
                                  key={role}
                                  value={role}
                                >
                                  {role}
                                </option>
                              ),
                            )}
                          </Select>

                          <button
                            type="button"
                            className="danger-button compact-button"
                            disabled={
                              workspaceBusy
                              || !id
                            }
                            onClick={() =>
                              removeMember(
                                member,
                              )
                            }
                          >
                            Remove
                          </button>
                        </div>
                      ) : (
                        <span className="status-badge">
                          {member.role
                            || 'viewer'}
                        </span>
                      )}
                    </div>
                  )
                },
              )}
            </div>
          )}
        </Card>

        <Card
          eyebrow="ACCESS"
          title="Pending invitations"
        >
          {canManageMembers ? (
            <>
              <p className="settings-access-note">
                Invite a new or existing BEACON account. A user can belong
                to multiple workspaces and switch between them without
                mixing organization data.
              </p>

              <form
                className="settings-form settings-invite-form"
                onSubmit={submitInvitation}
              >
                <FormField label="Member email" htmlFor="settings-invite-email">
                  <Input
                    id="settings-invite-email"
                    type="email"
                    required
                    value={inviteEmail}
                    disabled={workspaceBusy}
                    onChange={(event) =>
                      setInviteEmail(
                        event.target.value,
                      )
                    }
                  />
                </FormField>

                <FormField label="Workspace role" htmlFor="settings-invite-role">
                  <Select
                    id="settings-invite-role"
                    value={inviteRole}
                    disabled={workspaceBusy}
                    onChange={(event) =>
                      setInviteRole(
                        event.target.value,
                      )
                    }
                  >
                    {ORGANIZATION_ROLES.map(
                      (role) => (
                        <option key={role} value={role}>
                          {role}
                        </option>
                      ),
                    )}
                  </Select>
                </FormField>

                <button
                  type="submit"
                  className="primary-button"
                  disabled={workspaceBusy}
                >
                  Invite member
                </button>
              </form>

              {invitations.length === 0 ? (
                <p className="empty-state">
                  No pending invitations.
                </p>
              ) : (
                <div className="settings-invitation-list">
                  {invitations.map(
                    (invitation) => {
                      const id =
                        invitationId(
                          invitation,
                        )

                      return (
                        <div
                          className="settings-invitation-row"
                          key={
                            id
                            || invitation.email
                          }
                        >
                          <div
                            className="settings-invitation-mark"
                            aria-hidden="true"
                          >
                            @
                          </div>

                          <div className="settings-invitation-copy">
                            <strong
                              title={invitation.email}
                            >
                              {invitation.email}
                            </strong>

                            <div className="settings-invitation-meta">
                              <span className="status-badge settings-pending-badge">
                                pending
                              </span>

                              <span>
                                {invitation.role
                                  || 'viewer'}{' '}
                                access
                              </span>
                            </div>
                          </div>

                          <div className="settings-invitation-actions">
                            <button
                              type="button"
                              className="secondary-button compact-button"
                              disabled={
                                workspaceBusy
                                || !id
                              }
                              onClick={() =>
                                resendInvitation(
                                  invitation,
                                )
                              }
                            >
                              Resend
                            </button>

                            <button
                              type="button"
                              className="danger-button compact-button"
                              disabled={
                                workspaceBusy
                                || !id
                              }
                              onClick={() =>
                                revokeInvitation(
                                  invitation,
                                )
                              }
                            >
                              Revoke
                            </button>
                          </div>
                        </div>
                      )
                    },
                  )}
                </div>
              )}
            </>
          ) : (
            <p className="empty-state">
              Workspace administrators manage member invitations.
            </p>
          )}
        </Card>

        <Card
          className="settings-profile-card"
          eyebrow="ACCOUNT"
          title="Operator profile"
          headingActions={
            <span
              className={
                user?.is_active
                  ? 'status-badge status-verified'
                  : 'status-badge status-failed'
              }
            >
              {user?.is_active
                ? 'active'
                : 'inactive'}
            </span>
          }
        >
          <dl className="settings-details">
            <div>
              <dt>Name</dt>
              <dd>
                {user?.full_name || '—'}
              </dd>
            </div>

            <div>
              <dt>Email</dt>
              <dd>
                {user?.email || '—'}
              </dd>
            </div>

            <div>
              <dt>Account role</dt>
              <dd>
                {user?.role || '—'}
              </dd>
            </div>

            <div>
              <dt>
                Account status
              </dt>

              <dd>
                {user?.is_active
                  ? 'Active'
                  : 'Inactive'}
              </dd>
            </div>
          </dl>

          <p className="settings-role-help">
            <strong>Account role</strong> is the account-level classification exposed by this account and is separate from organization membership authorization.
          </p>
        </Card>

        <Card
          className="settings-session-card"
          eyebrow="SESSION"
          title="Current session"
        >
          <div className="settings-session-state">
            <span className="settings-session-dot" />

            <div>
              <strong>
                Authenticated
              </strong>

              <p>
                This browser session is authenticated as{' '}
                <span>
                  {user?.email
                    || 'the current operator'}
                </span>.
              </p>
            </div>
          </div>
        </Card>

        <Card
          className="settings-password-card"
          eyebrow="CREDENTIALS"
          title="Change password"
        >
          <form
            className="settings-form settings-password-form"
            onSubmit={
              submitPasswordChange
            }
          >
            <ErrorAlert
              message={
                passwordError
              }
            />

            <FormField
              label="Current password"
              htmlFor="settings-current-password"
            >
              <Input
                id="settings-current-password"
                type="password"
                required
                autoComplete="current-password"
                value={
                  currentPassword
                }
                onChange={(event) =>
                  setCurrentPassword(
                    event.target.value,
                  )
                }
                placeholder="Enter current password"
              />
            </FormField>

            <FormField
              label="New password"
              htmlFor="settings-new-password"
            >
              <Input
                id="settings-new-password"
                type="password"
                required
                minLength="12"
                autoComplete="new-password"
                value={
                  newPassword
                }
                onChange={(event) =>
                  setNewPassword(
                    event.target.value,
                  )
                }
                placeholder="At least 12 characters"
              />
            </FormField>

            <FormField
              label="Confirm new password"
              htmlFor="settings-confirm-password"
            >
              <Input
                id="settings-confirm-password"
                type="password"
                required
                minLength="12"
                autoComplete="new-password"
                value={
                  confirmPassword
                }
                onChange={(event) =>
                  setConfirmPassword(
                    event.target.value,
                  )
                }
                placeholder="Repeat new password"
              />
            </FormField>

            <button
              type="submit"
              className="primary-button auth-submit"
              disabled={
                passwordSubmitting
              }
            >
              {passwordSubmitting
                ? 'Changing password...'
                : 'Change password'}

              {!passwordSubmitting && (
                <span>→</span>
              )}
            </button>
          </form>
        </Card>
      </div>
    </>
  )
}
