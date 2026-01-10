export const useUser = () => {
  const session = useSession()

  // Computed property that extracts user from session
  return computed(() => session.data.value?.user || null)
}