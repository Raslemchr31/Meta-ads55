'use client'

import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { clientSafeApi, type MetaAdAccount } from '@/lib/api/client-safe'
import { toast } from 'sonner'

// Query keys for React Query
export const adAccountQueryKeys = {
  all: ['adAccounts'] as const,
  lists: () => [...adAccountQueryKeys.all, 'list'] as const,
  details: () => [...adAccountQueryKeys.all, 'detail'] as const,
  detail: (id: string) => [...adAccountQueryKeys.details(), id] as const,
  insights: () => [...adAccountQueryKeys.all, 'insights'] as const,
  insight: (id: string, timeRange?: { since: string; until: string }) => 
    [...adAccountQueryKeys.insights(), id, timeRange] as const,
}

interface UseAdAccountsOptions {
  enabled?: boolean
}

interface UseAdAccountInsightsOptions {
  accountId: string
  timeRange?: { since: string; until: string }
  fields?: string[]
  breakdowns?: string[]
  level?: 'account' | 'campaign' | 'adset' | 'ad'
  enabled?: boolean
}

// Hook to fetch all ad accounts for the current user
export function useAdAccounts({ enabled = true }: UseAdAccountsOptions = {}) {
  return useQuery({
    queryKey: adAccountQueryKeys.lists(),
    queryFn: async () => {
      const data = await clientSafeApi.getAdAccounts()
      return { data }
    },
    enabled,
    staleTime: 10 * 60 * 1000, // 10 minutes (ad accounts don't change frequently)
    gcTime: 30 * 60 * 1000, // 30 minutes
    refetchOnWindowFocus: false,
    retry: (failureCount, error: any) => {
      if (error?.status === 401 || error?.status === 403) {
        return false
      }
      return failureCount < 3
    },
  })
}

// Hook to fetch ad account insights
export function useAdAccountInsights({
  accountId,
  timeRange,
  fields,
  breakdowns,
  level = 'campaign',
  enabled = true
}: UseAdAccountInsightsOptions) {
  return useQuery({
    queryKey: adAccountQueryKeys.insight(accountId, timeRange),
    queryFn: async () => {
      if (!accountId) {
        throw new Error('Account ID is required')
      }
      
      const response = await clientSafeApi.getInsights(accountId, timeRange ? `${timeRange.since}_${timeRange.until}` : undefined)
      return response
    },
    enabled: enabled && !!accountId,
    staleTime: 2 * 60 * 1000, // 2 minutes
    gcTime: 5 * 60 * 1000,
    refetchOnWindowFocus: false,
    retry: (failureCount, error: any) => {
      if (error?.status === 401 || error?.status === 403) {
        return false
      }
      return failureCount < 3
    },
  })
}

// Hook to fetch detailed information about a specific ad account
export function useAdAccount(accountId: string, enabled = true) {
  return useQuery({
    queryKey: adAccountQueryKeys.detail(accountId),
    queryFn: async () => {
      if (!accountId) {
        throw new Error('Account ID is required')
      }
      
      throw new Error('Account details not implemented yet')
      return response
    },
    enabled: enabled && !!accountId,
    staleTime: 10 * 60 * 1000, // 10 minutes
    gcTime: 30 * 60 * 1000,
    refetchOnWindowFocus: false,
  })
}

// Hook to check ad account health and rate limits
export function useAdAccountHealth() {
  return useQuery({
    queryKey: ['adAccount', 'health'],
    queryFn: async () => {
      throw new Error('Rate limit check not implemented yet')
      return response
    },
    staleTime: 30 * 1000, // 30 seconds
    gcTime: 2 * 60 * 1000, // 2 minutes
    refetchInterval: 60 * 1000, // Check every minute
    refetchOnWindowFocus: false,
    retry: false, // Don't retry rate limit checks
  })
}

// Hook to get businesses associated with the user
export function useBusinesses(enabled = true) {
  return useQuery({
    queryKey: ['businesses'],
    queryFn: async () => {
      throw new Error('Get businesses not implemented yet')
      return response
    },
    enabled,
    staleTime: 15 * 60 * 1000, // 15 minutes
    gcTime: 30 * 60 * 1000,
    refetchOnWindowFocus: false,
    retry: (failureCount, error: any) => {
      if (error?.status === 401 || error?.status === 403) {
        return false
      }
      return failureCount < 3
    },
  })
}

// Mutation to update ad account settings
export function useUpdateAdAccount() {
  const queryClient = useQueryClient()
  
  return useMutation({
    mutationFn: async ({ accountId, updates }: { accountId: string; updates: any }) => {
      throw new Error('Update account not implemented yet')
      return response
    },
    onSuccess: (data, variables) => {
      // Invalidate specific account and lists
      queryClient.invalidateQueries({
        queryKey: adAccountQueryKeys.detail(variables.accountId)
      })
      queryClient.invalidateQueries({
        queryKey: adAccountQueryKeys.lists()
      })
      
      toast.success('Account settings updated successfully')
    },
    onError: (error: any) => {
      toast.error(error.message || 'Failed to update account settings')
    },
  })
}

// Helper functions for account management
export function useAdAccountOperations() {
  const queryClient = useQueryClient()
  
  return {
    // Refresh account data
    refreshAccount: async (accountId: string) => {
      await queryClient.invalidateQueries({
        queryKey: adAccountQueryKeys.detail(accountId)
      })
    },
    
    // Refresh all accounts
    refreshAccounts: async () => {
      await queryClient.invalidateQueries({
        queryKey: adAccountQueryKeys.lists()
      })
    },
    
    // Prefetch account data
    prefetchAccount: async (accountId: string) => {
      await queryClient.prefetchQuery({
        queryKey: adAccountQueryKeys.detail(accountId),
        queryFn: async () => {
          throw new Error('Prefetch account not implemented yet')
          return response
        },
        staleTime: 10 * 60 * 1000,
      })
    },
    
    // Prefetch account insights
    prefetchAccountInsights: async (accountId: string, timeRange?: { since: string; until: string }) => {
      await queryClient.prefetchQuery({
        queryKey: adAccountQueryKeys.insight(accountId, timeRange),
        queryFn: async () => {
          const response = await clientSafeApi.getInsights(accountId, timeRange ? `${timeRange.since}_${timeRange.until}` : undefined)
          return response
        },
        staleTime: 2 * 60 * 1000,
      })
    },
  }
}

// Custom hook to handle account selection and persistence
export function useSelectedAccount() {
  const { data: accounts } = useAdAccounts()
  
  return useQuery({
    queryKey: ['selectedAccount'],
    queryFn: async () => {
      // Get from localStorage or default to first account
      const stored = localStorage.getItem('selected-ad-account')
      if (stored && accounts?.data) {
        const account = accounts.data.find((acc: MetaAdAccount) => acc.id === stored)
        if (account) return account
      }
      
      // Return first account if available
      return accounts?.data?.[0] || null
    },
    enabled: !!accounts?.data,
    staleTime: Infinity, // Keep until manually invalidated
  })
}

// Hook to set selected account
export function useSetSelectedAccount() {
  const queryClient = useQueryClient()
  
  return useMutation({
    mutationFn: async (account: MetaAdAccount) => {
      localStorage.setItem('selected-ad-account', account.id)
      return account
    },
    onSuccess: (account) => {
      // Update the selected account cache
      queryClient.setQueryData(['selectedAccount'], account)
      toast.success(`Switched to account: ${account.name}`)
    },
    onError: (error: any) => {
      toast.error('Failed to switch account')
    },
  })
}