import type { AuthClient } from '../index'

export const useAuth = (): AuthClient => {
  const nuxtApp = useNuxtApp()
  const auth = nuxtApp.$auth

  if (!auth) {
    throw createError({
      statusCode: 500,
      statusMessage: 'Auth client not available. Make sure auth plugin is configured.'
    })
  }

  return auth
}
