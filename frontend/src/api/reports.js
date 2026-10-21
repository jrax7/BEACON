import { apiRequest } from './client'


export function listReports(
  archived = 'active',
) {
  const parameters =
    new URLSearchParams({ archived })

  return apiRequest(
    `/reports?${parameters}`,
  )
}
