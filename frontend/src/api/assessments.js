import {
  apiRequest,
} from './client'


export function listAssessmentProfiles() {
  return apiRequest(
    '/assessment-profiles',
  )
}


export function createAssessment(
  {
    targetId,
    profile,
    assessmentMode = 'web',
    activeTestingConfirmed = false,
    infrastructure = null,
  },
) {
  return apiRequest(
    '/assessments',
    {
      method: 'POST',
      body: {
        target_id:
          targetId,
        profile,
        assessment_mode:
          assessmentMode,
        active_testing_confirmed:
          activeTestingConfirmed,
        infrastructure,
      },
    },
  )
}


export function getAssessment(
  assessmentId,
) {
  return apiRequest(
    `/assessments/${encodeURIComponent(
      assessmentId,
    )}`,
  )
}


export function cancelAssessment(
  assessmentId,
) {
  return apiRequest(
    `/assessments/${encodeURIComponent(
      assessmentId,
    )}/cancel`,
    {
      method: 'POST',
    },
  )
}


export function getScannerHealth() {
  return apiRequest(
    '/scanner-health',
  )
}
