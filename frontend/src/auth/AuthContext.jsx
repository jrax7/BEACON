import {
  useCallback,
  useEffect,
  useMemo,
  useState,
} from 'react'

import {
  getCurrentUser,
  loginUser,
  logoutUser,
} from '../api/auth'
import {
  listOrganizations,
  setActiveOrganizationPreference,
} from '../api/organization'
import {
  clearActiveOrganizationId,
  getActiveOrganizationId,
  setActiveOrganizationId,
} from './organization-state'
import {
  clearCsrfToken,
  setAuthExpiredHandler,
  setSessionMetadataRefresher,
} from './session-state'
import AuthContext from './auth-context'
import { hasPermission } from './rbac'


function normalizeOrganizations(result) {
  if (Array.isArray(result)) {
    return result
  }

  return Array.isArray(result?.organizations)
    ? result.organizations
    : []
}


export function AuthProvider({ children }) {
  const [user, setUser] = useState(null)
  const [organizations, setOrganizations] = useState([])
  const [loading, setLoading] = useState(true)
  const [sessionExpired, setSessionExpired] = useState(false)

  const clearAuthentication = useCallback(() => {
    clearCsrfToken()
    clearActiveOrganizationId()
    setUser(null)
    setOrganizations([])
  }, [])

  const loadOrganizations = useCallback(async () => {
    try {
      const result = await listOrganizations()
      const normalized = normalizeOrganizations(result)
      setOrganizations(normalized)
      return normalized
    } catch {
      setOrganizations([])
      return []
    }
  }, [])

  const refreshSession = useCallback(async () => {
    let currentUser

    try {
      currentUser = await getCurrentUser()
    } catch (requestError) {
      if (
        requestError?.code !==
        'ORGANIZATION_CONTEXT_INVALID'
      ) {
        throw requestError
      }

      clearActiveOrganizationId()
      currentUser = await getCurrentUser()
    }

    setActiveOrganizationId(
      currentUser?.organization_id || null,
    )
    setUser(currentUser)
    setSessionExpired(false)
    await loadOrganizations()

    return currentUser
  }, [loadOrganizations])

  useEffect(() => {
    let cancelled = false

    async function restoreSession() {
      setLoading(true)

      try {
        const currentUser =
          await refreshSession()

        if (cancelled) {
          return
        }

        setUser(currentUser)
      } catch {
        if (!cancelled) {
          clearAuthentication()
        }
      } finally {
        if (!cancelled) {
          setLoading(false)
        }
      }
    }

    restoreSession()

    return () => {
      cancelled = true
    }
  }, [clearAuthentication, refreshSession])

  useEffect(() => {
    const removeExpiredHandler =
      setAuthExpiredHandler(() => {
        setSessionExpired(true)
        clearAuthentication()
        setLoading(false)
      })

    const removeMetadataRefresher =
      setSessionMetadataRefresher(
        refreshSession,
      )

    return () => {
      removeExpiredHandler()
      removeMetadataRefresher()
    }
  }, [clearAuthentication, refreshSession])

  const login = useCallback(async ({ email, password }) => {
    const currentUser = await loginUser({
      email,
      password,
    })

    setActiveOrganizationId(
      currentUser?.organization_id || null,
    )
    setUser(currentUser)
    setSessionExpired(false)
    await loadOrganizations()

    return currentUser
  }, [loadOrganizations])

  const switchOrganization = useCallback(
    async (organizationId) => {
      const previousId =
        getActiveOrganizationId()

      setActiveOrganizationId(
        organizationId,
      )

      try {
        await setActiveOrganizationPreference(
          organizationId,
        )

        const currentUser =
          await getCurrentUser()

        setUser(currentUser)
        setSessionExpired(false)
        await loadOrganizations()

        return currentUser
      } catch (requestError) {
        setActiveOrganizationId(previousId)
        throw requestError
      }
    },
    [loadOrganizations],
  )

  const logout = useCallback(async () => {
    try {
      await logoutUser()
    } finally {
      setSessionExpired(false)
      clearAuthentication()
      setLoading(false)
    }
  }, [clearAuthentication])

  const value = useMemo(() => ({
    user,
    organizations,
    loading,
    sessionExpired,
    organizationId:
      user?.organization_id || null,
    organizationName:
      user?.organization_name || null,
    organizationRole:
      user?.organization_role || null,
    hasPermission:
      (permission) =>
        hasPermission(user, permission),
    isAuthenticated: Boolean(user),
    login,
    logout,
    refreshSession,
    switchOrganization,
  }), [
    user,
    organizations,
    loading,
    sessionExpired,
    login,
    logout,
    refreshSession,
    switchOrganization,
  ])

  return (
    <AuthContext value={value}>
      {children}
    </AuthContext>
  )
}
