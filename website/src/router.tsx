import { Link, createRouter } from '@tanstack/react-router'

// Import the generated route tree
import { routeTree } from './routeTree.gen'

const NotFound = () => (
  <div className="mx-auto flex min-h-screen max-w-[720px] flex-col items-start justify-center gap-4 px-6">
    <p className="text-sm uppercase tracking-[0.2em] text-fd-muted-foreground">Not Found</p>
    <h1 className="text-3xl font-semibold">We could not find that page.</h1>
    <p className="text-fd-muted-foreground">
      The page may have moved or the URL is incorrect.
    </p>
    <Link to="/" className="text-fd-primary hover:underline">
      Back to docs
    </Link>
  </div>
)

// Create a new router instance
export const getRouter = () => {
  const router = createRouter({
    routeTree,
    context: {},

    scrollRestoration: true,
    defaultPreloadStaleTime: 0,
    defaultPendingMs: 200,
    defaultNotFoundComponent: NotFound,
  })

  return router
}
