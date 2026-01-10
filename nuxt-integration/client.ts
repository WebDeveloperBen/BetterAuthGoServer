import { AuthClient, AuthConfig, FetchOptions } from './types'
import { AuthFetch } from './fetch'

export class BetterAuthGoClient implements AuthClient {
  public config: AuthConfig
  private fetch: AuthFetch

  constructor(config: AuthConfig = {}) {
    this.config = {
      baseURL: 'http://localhost:8080/auth',
      ...config,
    }
    this.fetch = new AuthFetch(this.config.baseURL!, this.config.fetchOptions)
  }

  // Authentication methods
  signIn = {
    email: async (data: { email: string; password: string }, options?: FetchOptions) => {
      return this.fetch.post('/sign-in', data, options)
    }
  }

  signUp = {
    email: async (data: { email: string; password: string; name: string }, options?: FetchOptions) => {
      return this.fetch.post('/sign-up', data, options)
    }
  }

  async signOut(options?: FetchOptions): Promise<void> {
    await this.fetch.post('/sign-out', {}, options)
  }

  async getSession(options?: FetchOptions) {
    try {
      return await this.fetch.get('/me', options)
    } catch (error) {
      // Session might not exist
      return null
    }
  }

  async refreshSession(options?: FetchOptions) {
    // Force refresh the session
    return this.getSession({ ...options, cache: 'reload' } as any)
  }

  async updateUser(data: any, options?: FetchOptions) {
    return this.fetch.put('/profile', data, options)
  }
}

// Factory function
export function createAuthClient(config: AuthConfig = {}): BetterAuthGoClient {
  return new BetterAuthGoClient(config)
}
