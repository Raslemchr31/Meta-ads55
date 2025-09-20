import { vi } from 'vitest'
import { cleanup } from '@testing-library/react'
import { afterEach, beforeAll } from 'vitest'
import '@testing-library/jest-dom'

// Mock Next.js router
vi.mock('next/router', () => ({
  useRouter: () => ({
    push: vi.fn(),
    replace: vi.fn(),
    back: vi.fn(),
    query: {},
    pathname: '/',
    asPath: '/',
    events: {
      on: vi.fn(),
      off: vi.fn(),
      emit: vi.fn()
    }
  })
}))

// Mock next/navigation for App Router
vi.mock('next/navigation', () => ({
  useRouter: () => ({
    push: vi.fn(),
    replace: vi.fn(),
    back: vi.fn(),
    forward: vi.fn(),
    refresh: vi.fn(),
    prefetch: vi.fn()
  }),
  usePathname: () => '/',
  useSearchParams: () => new URLSearchParams(),
  useParams: () => ({})
}))

// Mock NextAuth.js
vi.mock('next-auth/react', () => ({
  useSession: vi.fn(() => ({
    data: {
      user: {
        id: 'test-user-1',
        email: 'test@example.com',
        name: 'Test User'
      },
      expires: '2024-12-31'
      // Importantly: NO access tokens in client session (security fix)
    },
    status: 'authenticated'
  })),
  signIn: vi.fn(),
  signOut: vi.fn(),
  getSession: vi.fn(),
  SessionProvider: ({ children }: { children: React.ReactNode }) => children
}))

// Mock React Query
vi.mock('@tanstack/react-query', () => ({
  useQuery: vi.fn(() => ({
    data: null,
    isLoading: false,
    error: null,
    refetch: vi.fn()
  })),
  useMutation: vi.fn(() => ({
    mutate: vi.fn(),
    isLoading: false,
    error: null,
    data: null
  })),
  QueryClient: vi.fn(() => ({
    invalidateQueries: vi.fn(),
    setQueryData: vi.fn(),
    getQueryData: vi.fn()
  })),
  QueryClientProvider: ({ children }: { children: React.ReactNode }) => children
}))

// Mock Zustand stores
vi.mock('@/store/auth-store', () => ({
  useAuthStore: vi.fn(() => ({
    user: {
      id: 'test-user-1',
      email: 'test@example.com',
      name: 'Test User'
    },
    isAuthenticated: true,
    login: vi.fn(),
    logout: vi.fn(),
    updateUser: vi.fn()
  }))
}))

vi.mock('@/store/app-store', () => ({
  useAppStore: vi.fn(() => ({
    theme: 'light',
    sidebarOpen: false,
    toggleTheme: vi.fn(),
    toggleSidebar: vi.fn()
  }))
}))

// Mock API calls
vi.mock('@/api/client', () => ({
  apiClient: {
    get: vi.fn(),
    post: vi.fn(),
    put: vi.fn(),
    delete: vi.fn()
  }
}))

// Mock environment variables
beforeAll(() => {
  Object.defineProperty(window, 'location', {
    value: {
      href: 'http://localhost:3000',
      origin: 'http://localhost:3000',
      protocol: 'http:',
      host: 'localhost:3000',
      hostname: 'localhost',
      port: '3000',
      pathname: '/',
      search: '',
      hash: ''
    },
    writable: true
  })

  // Mock environment variables for testing
  process.env.NEXT_PUBLIC_API_URL = 'http://localhost:3001/api'
  process.env.NEXTAUTH_URL = 'http://localhost:3000'
})

// Cleanup after each test
afterEach(() => {
  cleanup()
  vi.clearAllMocks()
})

// Global test helpers
;(global as any).testHelpers = {
  // Security test helpers
  createMaliciousInput: () => '<script>alert("XSS")</script>',
  createSQLInjectionPayload: () => "'; DROP TABLE users; --",
  createCSRFPayload: () => '<img src="x" onerror="fetch(\'/api/campaigns\', {method: \'POST\'})">',
  
  // Mock session without tokens (secure)
  createSecureSession: () => ({
    user: {
      id: 'test-user',
      email: 'test@example.com',
      name: 'Test User'
    },
    expires: '2024-12-31'
    // No access tokens - they should stay server-side
  }),
  
  // Mock vulnerable session (for testing)
  createVulnerableSession: () => ({
    user: {
      id: 'test-user',
      email: 'test@example.com'
    },
    // SECURITY VULNERABILITY: Tokens in client session
    accessToken: 'EAAG...facebook-access-token',
    refreshToken: 'EAAG...facebook-refresh-token'
  }),
  
  // Component test helpers
  createMockComponent: (props = {}) => ({
    props,
    children: null,
    type: 'div'
  }),
  
  // Form test helpers
  createFormData: (data: Record<string, any>) => {
    const formData = new FormData()
    Object.entries(data).forEach(([key, value]) => {
      formData.append(key, value)
    })
    return formData
  }
}

// Mock browser APIs that might not be available in jsdom
Object.defineProperty(window, 'matchMedia', {
  writable: true,
  value: vi.fn().mockImplementation(query => ({
    matches: false,
    media: query,
    onchange: null,
    addListener: vi.fn(),
    removeListener: vi.fn(),
    addEventListener: vi.fn(),
    removeEventListener: vi.fn(),
    dispatchEvent: vi.fn(),
  })),
})

// Mock IntersectionObserver
global.IntersectionObserver = vi.fn().mockImplementation(() => ({
  observe: vi.fn(),
  unobserve: vi.fn(),
  disconnect: vi.fn()
}))

// Mock ResizeObserver
global.ResizeObserver = vi.fn().mockImplementation(() => ({
  observe: vi.fn(),
  unobserve: vi.fn(),
  disconnect: vi.fn()
}))

// Mock localStorage
Object.defineProperty(window, 'localStorage', {
  value: {
    getItem: vi.fn(),
    setItem: vi.fn(),
    removeItem: vi.fn(),
    clear: vi.fn(),
    length: 0,
    key: vi.fn()
  },
  writable: true
})

// Mock sessionStorage
Object.defineProperty(window, 'sessionStorage', {
  value: {
    getItem: vi.fn(),
    setItem: vi.fn(),
    removeItem: vi.fn(),
    clear: vi.fn(),
    length: 0,
    key: vi.fn()
  },
  writable: true
})