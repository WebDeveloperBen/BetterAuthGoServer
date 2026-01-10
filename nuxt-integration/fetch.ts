// Enhanced fetch wrapper with CSRF and cookie handling

export class AuthFetch {
  private baseURL: string
  private defaultOptions: RequestInit

  constructor(baseURL: string, defaultOptions: RequestInit = {}) {
    this.baseURL = baseURL.replace(/\/$/, '') // Remove trailing slash
    this.defaultOptions = defaultOptions
  }

  async request<T>(
    endpoint: string,
    options: RequestInit & { onSuccess?: (data: T) => void; onError?: (error: any) => void } = {}
  ): Promise<T> {
    const { onSuccess, onError, ...fetchOptions } = options

    // Build full URL
    const url = endpoint.startsWith('http') ? endpoint : `${this.baseURL}${endpoint}`

    // Merge options with defaults
    const finalOptions: RequestInit = {
      ...this.defaultOptions,
      ...fetchOptions,
      headers: {
        'Content-Type': 'application/json',
        ...this.defaultOptions.headers,
        ...fetchOptions.headers,
      },
    }

    // Add CSRF token for state-changing requests
    if (this.needsCsrfToken(finalOptions.method)) {
      const csrfToken = this.getCsrfToken()
      if (csrfToken) {
        finalOptions.headers = {
          ...finalOptions.headers,
          'X-CSRF-Token': csrfToken,
        }
      }
    }

    // Convert body to JSON if it's an object
    if (finalOptions.body && typeof finalOptions.body === 'object') {
      finalOptions.body = JSON.stringify(finalOptions.body)
    }

    try {
      const response = await fetch(url, finalOptions)

      // Handle CSRF token updates
      this.updateCsrfToken(response)

      if (!response.ok) {
        const errorData = await this.parseError(response)
        if (onError) {
          onError(errorData)
        }
        throw errorData
      }

      const data = await this.parseResponse<T>(response)

      if (onSuccess) {
        onSuccess(data)
      }

      return data
    } catch (error) {
      if (onError && error !== undefined) {
        onError(error as any)
      }
      throw error
    }
  }

  private needsCsrfToken(method?: string): boolean {
    const csrfMethods = ['POST', 'PUT', 'PATCH', 'DELETE']
    return method ? csrfMethods.includes(method.toUpperCase()) : false
  }

  private getCsrfToken(): string | null {
    return this.getCookie('csrf_token')
  }

  private updateCsrfToken(response: Response): void {
    // Server might set new CSRF token in response
    const newToken = response.headers.get('X-CSRF-Token')
    if (newToken) {
      document.cookie = `csrf_token=${newToken}; path=/; SameSite=Lax`
    }
  }

  private getCookie(name: string): string | null {
    const value = `; ${document.cookie}`
    const parts = value.split(`; ${name}=`)
    if (parts.length === 2) {
      return parts.pop()?.split(';').shift() || null
    }
    return null
  }

  private async parseError(response: Response): Promise<any> {
    try {
      const errorData = await response.json()
      return {
        message: errorData.message || response.statusText,
        status: response.status,
        code: errorData.code,
        ...errorData,
      }
    } catch {
      return {
        message: response.statusText || 'Request failed',
        status: response.status,
      }
    }
  }

  private async parseResponse<T>(response: Response): Promise<T> {
    const contentType = response.headers.get('content-type')
    if (contentType?.includes('application/json')) {
      return response.json()
    }
    return response.text() as any
  }

  get<T>(endpoint: string, options?: RequestInit & { onSuccess?: (data: T) => void; onError?: (error: any) => void }): Promise<T> {
    return this.request<T>(endpoint, { ...options, method: 'GET' })
  }

  post<T>(endpoint: string, data?: any, options?: RequestInit & { onSuccess?: (data: T) => void; onError?: (error: any) => void }): Promise<T> {
    return this.request<T>(endpoint, {
      ...options,
      method: 'POST',
      body: data,
    })
  }

  put<T>(endpoint: string, data?: any, options?: RequestInit & { onSuccess?: (data: T) => void; onError?: (error: any) => void }): Promise<T> {
    return this.request<T>(endpoint, {
      ...options,
      method: 'PUT',
      body: data,
    })
  }

  delete<T>(endpoint: string, options?: RequestInit & { onSuccess?: (data: T) => void; onError?: (error: any) => void }): Promise<T> {
    return this.request<T>(endpoint, { ...options, method: 'DELETE' })
  }
}
