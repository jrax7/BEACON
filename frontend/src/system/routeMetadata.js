const routes = [
  [/^\/dashboard(?:\/|$)/, 'Dashboard'],
  [/^\/targets\/[^/]+/, 'Target Detail'],
  [/^\/targets(?:\/|$)/, 'Targets'],
  [/^\/scans\/new(?:\/|$)/, 'New Assessment'],
  [/^\/scans\/[^/]+/, 'Assessment Detail'],
  [/^\/scans(?:\/|$)/, 'Assessments'],
  [/^\/findings\/[^/]+/, 'Finding Detail'],
  [/^\/findings(?:\/|$)/, 'Findings'],
  [/^\/reports(?:\/|$)/, 'Reports'],
  [/^\/settings(?:\/|$)/, 'Settings'],
]

export function getRouteTitle(pathname) {
  const match = routes.find(([pattern]) => pattern.test(pathname))
  return `${match?.[1] || 'Security Assessment Platform'} · BEACON`
}
