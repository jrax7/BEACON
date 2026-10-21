import {
  Navigate,
  Outlet,
} from 'react-router'

import { useAuth } from './useAuth'

export default function PublicOnlyRoute() {
  const { isAuthenticated, loading } = useAuth()

  if (loading) {
    return (
      <div className="page-loader">
        <div className="loader-mark">
          B
        </div>

        <p>
          Loading BEACON...
        </p>
      </div>
    )
  }

  if (isAuthenticated) {
    return (
      <Navigate
        to="/dashboard"
        replace
      />
    )
  }

  return <Outlet />
}
