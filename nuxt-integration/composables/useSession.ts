export const useSession = () => {
  const auth = useAuth()

  // Use useState for SSR-compatible reactive state
  const session = useState('auth-session', () => null)
  const isLoading = useState('auth-session-loading', () => true)

  // Only run on client or when explicitly called
  if (process.client) {
    // Watch for auth state changes and update reactive state
    const updateSession = async () => {
      try {
        isLoading.value = true
        const result = await auth.getSession()
        session.value = result
      } catch (error) {
        session.value = null
        console.warn('Failed to fetch session:', error)
      } finally {
        isLoading.value = false
      }
    }

    // Initial load
    if (!session.value && isLoading.value) {
      updateSession()
    }

    // Return reactive query-like object
    return {
      data: readonly(session),
      isPending: readonly(isLoading),
      isLoading: readonly(isLoading),
      error: readonly(useState('auth-session-error', () => null)),
      refetch: updateSession
    }
  }

  // Server-side return
  return {
    data: readonly(session),
    isPending: readonly(isLoading),
    isLoading: readonly(isLoading),
    error: readonly(useState('auth-session-error', () => null)),
    refetch: () => Promise.resolve()
  }
}

