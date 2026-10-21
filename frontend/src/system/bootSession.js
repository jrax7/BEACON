let bootShown = false

export function claimBootSequence() {
  if (bootShown) return false
  bootShown = true
  return true
}
