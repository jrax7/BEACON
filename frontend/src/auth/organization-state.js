let activeOrganizationId = null


export function getActiveOrganizationId() {
  return activeOrganizationId
}


export function setActiveOrganizationId(
  organizationId,
) {
  activeOrganizationId =
    organizationId
      ? String(organizationId)
      : null
}


export function clearActiveOrganizationId() {
  activeOrganizationId = null
}
