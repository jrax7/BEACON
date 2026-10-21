import { Outlet, useLocation } from 'react-router'

export default function RouteViewport() {
  const location = useLocation()
  return (
    <div className="route-viewport" key={location.pathname}>
      <Outlet />
    </div>
  )
}
