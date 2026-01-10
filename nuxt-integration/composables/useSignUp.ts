export const useSignUp = () => {
  const auth = useAuth()
  const sessionComposable = useSession()

  const isPending = useState('auth-signup-pending', () => false)
  const error = useState('auth-signup-error', () => null)

  const mutateAsync = async (data: { email: string; password: string; name: string }) => {
    try {
      isPending.value = true
      error.value = null

      const result = await auth.signUp.email(data)

      // Refresh session after successful sign up
      await sessionComposable.refetch()

      return result
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
