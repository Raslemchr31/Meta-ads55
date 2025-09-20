import { create } from 'zustand'
import { persist, createJSONStorage } from 'zustand/middleware'
import { devtools, subscribeWithSelector } from 'zustand/middleware'
import { User, FacebookPage } from '@/types/auth'
import { MetaAdAccount, MetaBusiness } from '@/lib/api-client'

interface AuthState {
  // User authentication
  user: User | null
  isAuthenticated: boolean
  accessToken: string | null
  tokenExpiresAt: number | null
  
  // Connected platforms
  connectedPages: FacebookPage[]
  connectedAdAccounts: MetaAdAccount[]
  connectedBusinesses: MetaBusiness[]
  
  // Selected entities
  selectedPageId: string | null
  selectedAdAccountId: string | null
  selectedBusinessId: string | null
  
  // UI state
  isLoading: boolean
  isInitializing: boolean
  error: string | null
  
  // Permissions
  permissions: string[]
  hasRequiredPermissions: boolean
  
  // Settings
  preferences: {
    defaultTimeZone: string
    currency: string
    language: string
    theme: 'light' | 'dark' | 'system'
    emailNotifications: boolean
    pushNotifications: boolean
  }
}

interface AuthActions {
  // Authentication actions
  setUser: (user: User | null) => void
  setAccessToken: (token: string | null, expiresAt?: number) => void
  login: (user: User, token: string, expiresAt: number) => void
  logout: () => void
  refreshToken: () => Promise<boolean>
  
  // Platform connection actions
  setConnectedPages: (pages: FacebookPage[]) => void
  setConnectedAdAccounts: (accounts: MetaAdAccount[]) => void
  setConnectedBusinesses: (businesses: MetaBusiness[]) => void
  
  // Selection actions
  setSelectedPageId: (pageId: string | null) => void
  setSelectedAdAccountId: (accountId: string | null) => void
  setSelectedBusinessId: (businessId: string | null) => void
  
  // Entity management
  addConnectedPage: (page: FacebookPage) => void
  removeConnectedPage: (pageId: string) => void
  updatePage: (pageId: string, updates: Partial<FacebookPage>) => void
  addAdAccount: (account: MetaAdAccount) => void
  removeAdAccount: (accountId: string) => void
  updateAdAccount: (accountId: string, updates: Partial<MetaAdAccount>) => void
  
  // UI state actions
  setLoading: (loading: boolean) => void
  setInitializing: (initializing: boolean) => void
  setError: (error: string | null) => void
  clearError: () => void
  
  // Permission actions
  setPermissions: (permissions: string[]) => void
  checkPermissions: (requiredPermissions: string[]) => boolean
  
  // Preferences
  updatePreferences: (updates: Partial<AuthState['preferences']>) => void
  
  // Utility actions
  reset: () => void
  initialize: () => Promise<void>
}

type AuthStore = AuthState & AuthActions

const REQUIRED_PERMISSIONS = [
  'ads_management',
  'ads_read',
  'business_management',
  'read_insights'
]

const initialState: AuthState = {
  // Authentication
  user: null,
  isAuthenticated: false,
  accessToken: null,
  tokenExpiresAt: null,
  
  // Connected platforms
  connectedPages: [],
  connectedAdAccounts: [],
  connectedBusinesses: [],
  
  // Selected entities
  selectedPageId: null,
  selectedAdAccountId: null,
  selectedBusinessId: null,
  
  // UI state
  isLoading: false,
  isInitializing: false,
  error: null,
  
  // Permissions
  permissions: [],
  hasRequiredPermissions: false,
  
  // Settings
  preferences: {
    defaultTimeZone: 'UTC',
    currency: 'USD',
    language: 'en',
    theme: 'system',
    emailNotifications: true,
    pushNotifications: true,
  },
}

export const useAuthStore = create<AuthStore>()(
  devtools(
    subscribeWithSelector(
      persist(
        (set, get) => ({
          ...initialState,

          // Authentication actions
          setUser: (user) => set({ 
            user, 
            isAuthenticated: !!user 
          }),

          setAccessToken: (token, expiresAt) => set({ 
            accessToken: token,
            tokenExpiresAt: expiresAt || null,
            isAuthenticated: !!token
          }),

          login: (user, token, expiresAt) => set({
            user,
            accessToken: token,
            tokenExpiresAt: expiresAt,
            isAuthenticated: true,
            error: null,
          }),

          logout: () => {
            // Clear localStorage
            localStorage.removeItem('auth-storage')
            localStorage.removeItem('selected-ad-account')
            
            set(initialState)
          },

          refreshToken: async () => {
            try {
              // Implementation would depend on your auth provider
              // For now, return false to indicate refresh failed
              return false
            } catch (error) {
              set({ error: 'Failed to refresh token', isAuthenticated: false })
              return false
            }
          },

          // Platform connection actions
          setConnectedPages: (pages) => set({ connectedPages: pages }),

          setConnectedAdAccounts: (accounts) => set({ 
            connectedAdAccounts: accounts,
            // Auto-select first account if none selected
            selectedAdAccountId: get().selectedAdAccountId || accounts[0]?.id || null
          }),

          setConnectedBusinesses: (businesses) => set({ 
            connectedBusinesses: businesses,
            selectedBusinessId: get().selectedBusinessId || businesses[0]?.id || null
          }),

          // Selection actions
          setSelectedPageId: (pageId) => set({ selectedPageId: pageId }),

          setSelectedAdAccountId: (accountId) => {
            set({ selectedAdAccountId: accountId })
            if (accountId) {
              localStorage.setItem('selected-ad-account', accountId)
            } else {
              localStorage.removeItem('selected-ad-account')
            }
          },

          setSelectedBusinessId: (businessId) => set({ selectedBusinessId: businessId }),

          // Entity management
          addConnectedPage: (page) => set((state) => ({
            connectedPages: [...state.connectedPages, page]
          })),

          removeConnectedPage: (pageId) => set((state) => ({
            connectedPages: state.connectedPages.filter(page => page.id !== pageId),
            selectedPageId: state.selectedPageId === pageId ? null : state.selectedPageId
          })),

          updatePage: (pageId, updates) => set((state) => ({
            connectedPages: state.connectedPages.map(page =>
              page.id === pageId ? { ...page, ...updates } : page
            )
          })),

          addAdAccount: (account) => set((state) => ({
            connectedAdAccounts: [...state.connectedAdAccounts, account]
          })),

          removeAdAccount: (accountId) => set((state) => ({
            connectedAdAccounts: state.connectedAdAccounts.filter(acc => acc.id !== accountId),
            selectedAdAccountId: state.selectedAdAccountId === accountId ? null : state.selectedAdAccountId
          })),

          updateAdAccount: (accountId, updates) => set((state) => ({
            connectedAdAccounts: state.connectedAdAccounts.map(account =>
              account.id === accountId ? { ...account, ...updates } : account
            )
          })),

          // UI state actions
          setLoading: (loading) => set({ isLoading: loading }),

          setInitializing: (initializing) => set({ isInitializing: initializing }),

          setError: (error) => set({ error }),

          clearError: () => set({ error: null }),

          // Permission actions
          setPermissions: (permissions) => set({
            permissions,
            hasRequiredPermissions: REQUIRED_PERMISSIONS.every(perm => permissions.includes(perm))
          }),

          checkPermissions: (requiredPermissions) => {
            const { permissions } = get()
            return requiredPermissions.every(perm => permissions.includes(perm))
          },

          // Preferences
          updatePreferences: (updates) => set((state) => ({
            preferences: { ...state.preferences, ...updates }
          })),

          // Utility actions
          reset: () => set(initialState),

          initialize: async () => {
            set({ isInitializing: true })
            
            try {
              // Check for existing token
              const { accessToken, tokenExpiresAt } = get()
              
              if (accessToken && tokenExpiresAt && Date.now() < tokenExpiresAt) {
                // Token is valid, user is authenticated
                set({ isAuthenticated: true })
              } else if (accessToken) {
                // Token expired, try to refresh
                const refreshed = await get().refreshToken()
                if (!refreshed) {
                  // Refresh failed, clear auth state
                  get().logout()
                }
              }
              
              // Restore selected account from localStorage
              const selectedAccountId = localStorage.getItem('selected-ad-account')
              if (selectedAccountId) {
                set({ selectedAdAccountId: selectedAccountId })
              }
              
            } catch (error) {
              console.error('Auth initialization failed:', error)
              set({ error: 'Failed to initialize authentication' })
            } finally {
              set({ isInitializing: false })
            }
          },
        }),
        {
          name: 'auth-storage',
          storage: createJSONStorage(() => localStorage),
          partialize: (state) => ({
            user: state.user,
            accessToken: state.accessToken,
            tokenExpiresAt: state.tokenExpiresAt,
            connectedPages: state.connectedPages,
            connectedAdAccounts: state.connectedAdAccounts,
            connectedBusinesses: state.connectedBusinesses,
            selectedPageId: state.selectedPageId,
            selectedAdAccountId: state.selectedAdAccountId,
            selectedBusinessId: state.selectedBusinessId,
            permissions: state.permissions,
            preferences: state.preferences,
          }),
          onRehydrateStorage: () => (state) => {
            if (state) {
              state.initialize()
            }
          },
        }
      )
    ),
    { name: 'auth-store' }
  )
)

// Computed selectors
export const useAuthSelectors = () => {
  const store = useAuthStore()
  
  return {
    selectedPage: store.connectedPages.find(page => page.id === store.selectedPageId),
    selectedAdAccount: store.connectedAdAccounts.find(acc => acc.id === store.selectedAdAccountId),
    selectedBusiness: store.connectedBusinesses.find(biz => biz.id === store.selectedBusinessId),
    isTokenExpired: store.tokenExpiresAt ? Date.now() >= store.tokenExpiresAt : true,
    canManageAds: store.checkPermissions(['ads_management']),
    canReadInsights: store.checkPermissions(['read_insights']),
  }
}