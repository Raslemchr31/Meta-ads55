import { create } from 'zustand'
import { persist } from 'zustand/middleware'

interface Notification {
  id: string
  title: string
  message: string
  type: 'info' | 'success' | 'warning' | 'error'
  timestamp: Date
  read: boolean
  actionUrl?: string
}

interface AppState {
  // UI State
  sidebarCollapsed: boolean
  theme: 'light' | 'dark' | 'system'
  
  // Notifications
  notifications: Notification[]
  unreadCount: number
  
  // Global loading states
  isGlobalLoading: boolean
  globalLoadingMessage: string
  
  // Date range filter
  dateRange: {
    from: Date
    to: Date
  }
  
  // Currency preference
  currency: string
  
  // Recent searches
  recentSearches: string[]
  
  // Quick access items
  pinnedCampaigns: string[]
  pinnedPages: string[]
}

interface AppActions {
  // UI Actions
  toggleSidebar: () => void
  setSidebarCollapsed: (collapsed: boolean) => void
  setTheme: (theme: 'light' | 'dark' | 'system') => void
  
  // Notification Actions
  addNotification: (notification: Omit<Notification, 'id' | 'timestamp' | 'read'>) => void
  markNotificationAsRead: (id: string) => void
  markAllNotificationsAsRead: () => void
  removeNotification: (id: string) => void
  clearNotifications: () => void
  
  // Global loading
  setGlobalLoading: (loading: boolean, message?: string) => void
  
  // Date range
  setDateRange: (from: Date, to: Date) => void
  
  // Currency
  setCurrency: (currency: string) => void
  
  // Recent searches
  addRecentSearch: (search: string) => void
  clearRecentSearches: () => void
  
  // Quick access
  pinCampaign: (campaignId: string) => void
  unpinCampaign: (campaignId: string) => void
  pinPage: (pageId: string) => void
  unpinPage: (pageId: string) => void
  
  // Reset
  reset: () => void
}

type AppStore = AppState & AppActions

const initialState: AppState = {
  sidebarCollapsed: false,
  theme: 'system',
  notifications: [],
  unreadCount: 0,
  isGlobalLoading: false,
  globalLoadingMessage: '',
  dateRange: {
    from: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000), // 30 days ago
    to: new Date(),
  },
  currency: 'USD',
  recentSearches: [],
  pinnedCampaigns: [],
  pinnedPages: [],
}

export const useAppStore = create<AppStore>()(
  persist(
    (set, get) => ({
      ...initialState,

      // UI Actions
      toggleSidebar: () => set((state) => ({ 
        sidebarCollapsed: !state.sidebarCollapsed 
      })),

      setSidebarCollapsed: (collapsed) => set({ sidebarCollapsed: collapsed }),

      setTheme: (theme) => set({ theme }),

      // Notification Actions
      addNotification: (notification) => {
        const id = Math.random().toString(36).substring(7)
        const newNotification: Notification = {
          ...notification,
          id,
          timestamp: new Date(),
          read: false,
        }
        
        set((state) => ({
          notifications: [newNotification, ...state.notifications].slice(0, 50), // Keep only last 50
          unreadCount: state.unreadCount + 1,
        }))
      },

      markNotificationAsRead: (id) => set((state) => {
        const notification = state.notifications.find(n => n.id === id)
        if (!notification?.read) {
          return {
            notifications: state.notifications.map(n =>
              n.id === id ? { ...n, read: true } : n
            ),
            unreadCount: Math.max(0, state.unreadCount - 1),
          }
        }
        return state
      }),

      markAllNotificationsAsRead: () => set((state) => ({
        notifications: state.notifications.map(n => ({ ...n, read: true })),
        unreadCount: 0,
      })),

      removeNotification: (id) => set((state) => {
        const notification = state.notifications.find(n => n.id === id)
        return {
          notifications: state.notifications.filter(n => n.id !== id),
          unreadCount: notification && !notification.read 
            ? Math.max(0, state.unreadCount - 1)
            : state.unreadCount,
        }
      }),

      clearNotifications: () => set({
        notifications: [],
        unreadCount: 0,
      }),

      // Global loading
      setGlobalLoading: (loading, message = '') => set({
        isGlobalLoading: loading,
        globalLoadingMessage: message,
      }),

      // Date range
      setDateRange: (from, to) => set({
        dateRange: { from, to },
      }),

      // Currency
      setCurrency: (currency) => set({ currency }),

      // Recent searches
      addRecentSearch: (search) => set((state) => {
        const filtered = state.recentSearches.filter(s => s !== search)
        return {
          recentSearches: [search, ...filtered].slice(0, 10), // Keep only last 10
        }
      }),

      clearRecentSearches: () => set({ recentSearches: [] }),

      // Quick access
      pinCampaign: (campaignId) => set((state) => ({
        pinnedCampaigns: [...new Set([...state.pinnedCampaigns, campaignId])],
      })),

      unpinCampaign: (campaignId) => set((state) => ({
        pinnedCampaigns: state.pinnedCampaigns.filter(id => id !== campaignId),
      })),

      pinPage: (pageId) => set((state) => ({
        pinnedPages: [...new Set([...state.pinnedPages, pageId])],
      })),

      unpinPage: (pageId) => set((state) => ({
        pinnedPages: state.pinnedPages.filter(id => id !== pageId),
      })),

      // Reset
      reset: () => set(initialState),
    }),
    {
      name: 'app-storage',
      partialize: (state) => ({
        sidebarCollapsed: state.sidebarCollapsed,
        theme: state.theme,
        dateRange: state.dateRange,
        currency: state.currency,
        recentSearches: state.recentSearches,
        pinnedCampaigns: state.pinnedCampaigns,
        pinnedPages: state.pinnedPages,
      }),
    }
  )
)