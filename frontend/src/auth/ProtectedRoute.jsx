import {
  Navigate,
  Outlet,
  useLocation,
} from 'react-router'

import { SkeletonList } from '../components/ui'
import { useAuth } from './useAuth'

export default function ProtectedRoute() {
  const { isAuthenticated, loading, sessionExpired } = useAuth()

  const location =
    useLocation()

  if (loading) {
    return (
      <div className="page-loader" aria-label="Restoring secure session">
        <div className="loader-mark">
          B
        </div>
        <SkeletonList
          rows={3}
          label="Restoring secure session"
          className="protected-route-skeleton"
        />
      </div>
    )
  }

  if (!isAuthenticated) {
    const requestedPath =
      `${location.pathname}${location.search}`

    return (
      <Navigate
        to="/login"
        replace
        state={{
          from: requestedPath,
          sessionExpired,
        }}
      />
    )
  }

  return <Outlet />
}
