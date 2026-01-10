# BetterAuthGoServer Nuxt Integration

**Copy this entire folder** to your Nuxt project

Then **git ignore it**:
```bash
echo "nuxt-integration/" >> .gitignore
```

## Quick Setup

### 1. Copy to Your Project
```bash
cp -r BetterAuthGoServer/nuxt-integration ~/my-nuxt-project/
```

### 2. Configure in nuxt.config.ts
```typescript
// nuxt.config.ts
export default defineNuxtConfig({
  // Auto-import composables from the directory
  imports: {
    dirs: ['./nuxt-integration/composables']
  },

  // Runtime config for auth
  runtimeConfig: {
    public: {
      betterAuthGo: {
        baseURL: 'http://localhost:8080/auth'
      }
    }
  },

  // Register the auth plugin
  plugins: ['./nuxt-integration/plugins/auth.client.ts']
})
```

### 3. Use in Pages/Components
```vue
<template>
  <div>
    <!-- Loading state -->
    <div v-if="session.isPending">Loading...</div>

    <!-- Authenticated user -->
    <div v-else-if="session.data">
      <h1>Welcome, {{ user?.name }}!</h1>
      <button @click="handleSignOut" :disabled="signOutMutation.isPending">
        Sign Out
      </button>
    </div>

    <!-- Login form -->
    <div v-else>
      <form @submit.prevent="handleSignIn">
        <input v-model="email" type="email" placeholder="Email" required />
        <input v-model="password" type="password" placeholder="Password" required />
        <button type="submit" :disabled="signInMutation.isPending">
          Sign In
        </button>
      </form>

      <div v-if="signInMutation.error">
        {{ signInMutation.error.message }}
      </div>
    </div>
  </div>
</template>

<script setup>
const email = ref('')
const password = ref('')

// Auto-imported composables (no import needed!)
const session = useSession()
const user = useUser()
const signInMutation = useSignIn()
const signOutMutation = useSignOut()

const handleSignIn = async () => {
  try {
    await signInMutation.mutateAsync({
      email: email.value,
      password: password.value
    })
    // Success! Session updates automatically
    await navigateTo('/dashboard')
  } catch (error) {
    // Error handled by mutation
  }
}

const handleSignOut = async () => {
  try {
    await signOutMutation.mutateAsync()
    await navigateTo('/')
  } catch (error) {
    console.error('Sign out failed:', error)
  }
}
</script>
```

## Directory Structure

After copying, your project should look like:

```
your-nuxt-project/
├── nuxt.config.ts                    # Configure auth here
├── plugins/
│   └── auth.client.ts               # (existing) Auth plugin
├── composables/
│   ├── useAuth.ts                   # (existing) Auth composables
│   ├── useSession.ts
│   ├── useSignIn.ts
│   ├── useSignUp.ts
│   ├── useSignOut.ts
│   └── useUser.ts
└── nuxt-integration/                # This folder (git ignored)
    ├── index.ts                     # Main exports
    ├── types.ts                     # TypeScript types
    ├── fetch.ts                     # CSRF + cookies
    ├── client.ts                    # Core auth client
    ├── plugins/
    │   └── auth.client.ts          # Nuxt plugin
    └── composables/                # Auto-imported composables
        ├── useAuth.ts
        ├── useSession.ts
        ├── useSignIn.ts
        ├── useSignUp.ts
        ├── useSignOut.ts
        └── useUser.ts
```

## API Reference

### Auto-imported Composables

```typescript
// Session management (auto-imported)
const session = useSession()           // { data, isPending, error, refetch }
const user = useUser()                 // Computed user object
const isAuth = useIsAuthenticated()    // Computed boolean (if you add it)

// Authentication mutations (auto-imported)
const signIn = useSignIn()             // { mutateAsync, isPending, error }
const signUp = useSignUp()             // { mutateAsync, isPending, error }
const signOut = useSignOut()           // { mutateAsync, isPending, error }

// Direct access to client
const auth = useAuth()                 // AuthClient instance
```

### Direct Client Usage

```typescript
const auth = useAuth()

// Direct API calls
await auth.signIn.email({ email, password })
await auth.signUp.email({ email, password, name })
await auth.signOut()
const session = await auth.getSession()
```

## Features

- ✅ **SSR Compatible** - Works with Nuxt's server-side rendering
- ✅ **Auto-imports** - Composables available globally
- ✅ **Reactive State** - Uses `useState` for SSR compatibility
- ✅ **CSRF Protection** - Automatic token handling
- ✅ **Session Management** - Cookie-based with auto-refresh
- ✅ **TypeScript Support** - Full type safety
- ✅ **Vue Query Ready** - Works with @tanstack/vue-query

## Dependencies Required

Make sure your Nuxt project has:
```bash
npm install @tanstack/vue-query
```

## Updating

When you update BetterAuthGoServer, just copy the new version:
```bash
cp -r BetterAuthGoServer/nuxt-integration ~/my-nuxt-project/
```

That's it! No complex setup, no packages - just copy and use Nuxt auth! 🚀
<parameter name="filePath">nuxt-integration/README.md