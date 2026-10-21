import { useEffect, useState } from 'react'
import { claimBootSequence } from '../../system/bootSession'
import BrandMark from '../BrandMark'

export default function BootSequence() {
  const [visible, setVisible] = useState(() => claimBootSequence())
  useEffect(() => {
    if (!visible) return undefined
    const timer = window.setTimeout(() => setVisible(false), 760)
    return () => window.clearTimeout(timer)
  }, [visible])
  if (!visible) return null
  return <div className="boot-sequence" aria-hidden="true"><BrandMark size="md" subtitle="Signal acquired" /></div>
}
