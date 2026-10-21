import {
  apiRequest,
} from './client'


export function registerUser({
  email,
  fullName,
  password,
  turnstileToken = '',
  invitationToken = null,
}) {
  return apiRequest(
    '/auth/register',
    {
      method: 'POST',
      body: {
        email,
        full_name:
          fullName,
        password,
        turnstile_token:
          turnstileToken,
        invitation_token:
          invitationToken,
      },
    },
  )
}


export function loginUser({
  email,
  password,
}) {
  return apiRequest(
    '/auth/login',
    {
      method: 'POST',
      body: {
        email,
        password,
      },
    },
  )
}


export function getCurrentUser() {
  return apiRequest(
    '/auth/me',
  )
}


export function logoutUser() {
  return apiRequest(
    '/auth/logout',
    {
      method: 'POST',
    },
  )
}


export function verifyEmail(
  verificationToken,
) {
  return apiRequest(
    '/auth/email/verify',
    {
      method: 'POST',
      body: {
        token:
          verificationToken,
      },
    },
  )
}


export function resendVerification({
  email,
  turnstileToken = '',
}) {
  return apiRequest(
    '/auth/email/verification/resend',
    {
      method: 'POST',
      body: {
        email,
        turnstile_token:
          turnstileToken,
      },
    },
  )
}


export function forgotPassword({
  email,
  turnstileToken = '',
}) {
  return apiRequest(
    '/auth/password/forgot',
    {
      method: 'POST',
      body: {
        email,
        turnstile_token:
          turnstileToken,
      },
    },
  )
}


export function resetPassword({
  resetToken,
  newPassword,
}) {
  return apiRequest(
    '/auth/password/reset',
    {
      method: 'POST',
      body: {
        token:
          resetToken,
        new_password:
          newPassword,
      },
    },
  )
}


export function changePassword({
  currentPassword,
  newPassword,
}) {
  return apiRequest(
    '/auth/password/change',
    {
      method: 'POST',
      body: {
        current_password:
          currentPassword,
        new_password:
          newPassword,
      },
    },
  )
}
