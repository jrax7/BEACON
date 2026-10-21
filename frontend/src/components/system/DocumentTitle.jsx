import { useEffect } from 'react'
import { useLocation } from 'react-router'
import { getRouteTitle } from '../../system/routeMetadata'

export default function DocumentTitle() {
  const location = useLocation()
  useEffect(() => { document.title = getRouteTitle(location.pathname) }, [location.pathname])
  return null
}
