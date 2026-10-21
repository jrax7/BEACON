import { useSyncExternalStore } from 'react'
import { getRequestActivitySnapshot, subscribeRequestActivity } from '../../system/requestActivity'

export default function ApiProgressBeam() {
  const active = useSyncExternalStore(subscribeRequestActivity, getRequestActivitySnapshot)
  return <div className={active > 0 ? 'api-progress-beam active' : 'api-progress-beam'} aria-hidden="true" />
}
