// Core types for BetterAuthGoServer integration

export interface AuthConfig {
  baseURL?: string
  fetchOptions?: RequestInit
}

export interface AuthSession {
  user: AuthUser
  session: {
    id: string
    userId: string
    ipAddress?: string
    userAgent?: string
    createdAt: string
    expiresAt: string
  }
}

export interface AuthUser {
  id: string
  email: string
  emailVerified: boolean
  name: string
  image?: string
  role: string
  banned: boolean
  createdAt: string
  updatedAt: string
}

export interface SignInRequest {
  email: string
  password: string
}

export interface SignUpRequest {
  email: string
  password: string
  name: string
}

export interface AuthResponse {
  user: AuthUser
  session: AuthSession['session']
}

export interface AuthError {
  message: string
  status: number
  code?: string
}

export interface FetchOptions extends RequestInit {
  onSuccess?: (data: any) => void
  onError?: (error: any) => void
}

export interface AuthClient {
  config: AuthConfig
  signIn: {
    email: (data: SignInRequest, options?: FetchOptions) => Promise<AuthResponse>
  }
  signUp: {
    email: (data: SignUpRequest, options?: FetchOptions) => Promise<AuthResponse>
  }
  signOut: (options?: FetchOptions) => Promise<void>
  getSession: (options?: FetchOptions) => Promise<AuthSession | null>
  refreshSession: (options?: FetchOptions) => Promise<AuthSession | null>
  updateUser: (data: any, options?: FetchOptions) => Promise<AuthUser>
}
<parameter name="filePath">nuxt-integration/types.ts