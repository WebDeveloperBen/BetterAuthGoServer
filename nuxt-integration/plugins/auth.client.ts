import { createAuthClient } from '../client'

export default defineNuxtPlugin((nuxtApp) => {
  const config = useRuntimeConfig().public.betterAuthGo as any || {}

  // Create auth client instance
  const authClient = createAuthClient(config)

  // Provide globally
  return {
    provide: {
      auth: authClient
    }
  }
})

