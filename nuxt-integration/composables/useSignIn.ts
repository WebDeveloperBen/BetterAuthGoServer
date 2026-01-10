export const useSignIn = () => {
  const auth = useAuth()
  const sessionComposable = useSession()

  const isPending = useState('auth-signin-pending', () => false)
  const error = useState('auth-signin-error', () => null)

  const mutateAsync = async (data: { email: string; password: string }) => {
    try {
      isPending.value = true
      error.value = null

      const result = await auth.signIn.email(data)

      // Refresh session after successful sign in
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
