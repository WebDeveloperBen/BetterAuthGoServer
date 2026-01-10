export const useSignOut = () => {
  const auth = useAuth()
  const sessionComposable = useSession()

  const isPending = useState('auth-signout-pending', () => false)
  const error = useState('auth-signout-error', () => null)

  const mutateAsync = async () => {
    try {
      isPending.value = true
      error.value = null

      await auth.signOut()

      // Clear session state
      sessionComposable.refetch()

      return undefined
    } catch (err: any) {
      error.value = err
      throw err
    } finally {
      isPending.value = false
    }
  }

  return {
    mutateAsync,
    isPending: readonly(isPending),
    error: readonly(error)
  }
}
