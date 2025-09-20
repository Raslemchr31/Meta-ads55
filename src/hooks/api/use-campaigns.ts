'use client'

import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { clientSafeApi, type MetaCampaign } from '@/lib/api/client-safe'
import { toast } from 'sonner'

// Query keys for React Query
export const campaignQueryKeys = {
  all: ['campaigns'] as const,
  lists: () => [...campaignQueryKeys.all, 'list'] as const,
  list: (accountId: string) => [...campaignQueryKeys.lists(), accountId] as const,
  details: () => [...campaignQueryKeys.all, 'detail'] as const,
  detail: (id: string) => [...campaignQueryKeys.details(), id] as const,
  insights: () => [...campaignQueryKeys.all, 'insights'] as const,
  insight: (id: string, timeRange?: { since: string; until: string }) => 
    [...campaignQueryKeys.insights(), id, timeRange] as const,
}

interface UseCampaignsOptions {
  accountId: string
  fields?: string[]
  limit?: number
  enabled?: boolean
}

interface UseCampaignInsightsOptions {
  campaignId: string
  timeRange?: { since: string; until: string }
  fields?: string[]
  breakdowns?: string[]
  level?: 'campaign' | 'adset' | 'ad'
  enabled?: boolean
}

// Hook to fetch campaigns for an account
export function useCampaigns({
  accountId,
  fields,
  limit = 100,
  enabled = true
}: UseCampaignsOptions) {
  return useQuery({
    queryKey: campaignQueryKeys.list(accountId),
    queryFn: async () => {
      if (!accountId) {
        throw new Error('Account ID is required')
      }
      
      const data = await clientSafeApi.getCampaigns(accountId)
      return { data }
    },
    enabled: enabled && !!accountId,
    staleTime: 5 * 60 * 1000, // 5 minutes
    gcTime: 10 * 60 * 1000, // 10 minutes
    refetchOnWindowFocus: false,
    retry: (failureCount, error: any) => {
      // Don't retry on authentication or permission errors
      if (error?.status === 401 || error?.status === 403) {
        return false
      }
      return failureCount < 3
    },
  })
}

// Hook to fetch campaign insights
export function useCampaignInsights({
  campaignId,
  timeRange,
  fields,
  breakdowns,
  level = 'campaign',
  enabled = true
}: UseCampaignInsightsOptions) {
  return useQuery({
    queryKey: campaignQueryKeys.insight(campaignId, timeRange),
    queryFn: async () => {
      if (!campaignId) {
        throw new Error('Campaign ID is required')
      }
      
      const response = await clientSafeApi.getInsights(campaignId, timeRange ? `${timeRange.since}_${timeRange.until}` : undefined)
      return response
    },
    enabled: enabled && !!campaignId,
    staleTime: 2 * 60 * 1000, // 2 minutes (insights change frequently)
    gcTime: 5 * 60 * 1000, // 5 minutes
    refetchOnWindowFocus: false,
    retry: (failureCount, error: any) => {
      if (error?.status === 401 || error?.status === 403) {
        return false
      }
      return failureCount < 3
    },
  })
}

// Hook to fetch a single campaign's details
export function useCampaign(campaignId: string, enabled = true) {
  return useQuery({
    queryKey: campaignQueryKeys.detail(campaignId),
    queryFn: async () => {
      if (!campaignId) {
        throw new Error('Campaign ID is required')
      }
      
      // Use the campaigns endpoint with specific ID
      throw new Error('Campaign details not implemented yet')
      return response
    },
    enabled: enabled && !!campaignId,
    staleTime: 5 * 60 * 1000,
    gcTime: 10 * 60 * 1000,
    refetchOnWindowFocus: false,
  })
}

// Mutation hooks for campaign operations
export function useCreateCampaign() {
  const queryClient = useQueryClient()
  
  return useMutation({
    mutationFn: async (campaignData: any) => {
      throw new Error('Create campaign not implemented yet')
    },
    onSuccess: (data, variables) => {
      // Invalidate campaigns list for the account
      queryClient.invalidateQueries({
        queryKey: campaignQueryKeys.list(variables.accountId)
      })
      
      toast.success('Campaign created successfully')
    },
    onError: (error: any) => {
      toast.error(error.message || 'Failed to create campaign')
    },
  })
}

export function useUpdateCampaign() {
  const queryClient = useQueryClient()
  
  return useMutation({
    mutationFn: async ({ campaignId, updates }: { campaignId: string; updates: any }) => {
      throw new Error('Update campaign not implemented yet')
    },
    onSuccess: (data, variables) => {
      // Invalidate specific campaign and related queries
      queryClient.invalidateQueries({
        queryKey: campaignQueryKeys.detail(variables.campaignId)
      })
      
      // Also invalidate the campaigns list
      queryClient.invalidateQueries({
        queryKey: campaignQueryKeys.lists()
      })
      
      toast.success('Campaign updated successfully')
    },
    onError: (error: any) => {
      toast.error(error.message || 'Failed to update campaign')
    },
  })
}

export function useDeleteCampaign() {
  const queryClient = useQueryClient()
  
  return useMutation({
    mutationFn: async (campaignId: string) => {
      throw new Error('Delete campaign not implemented yet')
    },
    onSuccess: (data, campaignId) => {
      // Remove from cache
      queryClient.removeQueries({
        queryKey: campaignQueryKeys.detail(campaignId)
      })
      
      // Invalidate campaigns lists
      queryClient.invalidateQueries({
        queryKey: campaignQueryKeys.lists()
      })
      
      toast.success('Campaign deleted successfully')
    },
    onError: (error: any) => {
      toast.error(error.message || 'Failed to delete campaign')
    },
  })
}

// Bulk operations
export function useBulkCampaignUpdate() {
  const queryClient = useQueryClient()
  
  return useMutation({
    mutationFn: async ({ campaignIds, updates }: { campaignIds: string[]; updates: any }) => {
      // Use batch API for efficiency
      const requests = campaignIds.map(id => ({
        method: 'POST',
        relative_url: `${id}`,
        body: JSON.stringify(updates)
      }))
      
      throw new Error('Bulk update not implemented yet')
    },
    onSuccess: (data, variables) => {
      // Invalidate all affected campaigns and lists
      variables.campaignIds.forEach(campaignId => {
        queryClient.invalidateQueries({
          queryKey: campaignQueryKeys.detail(campaignId)
        })
      })
      
      queryClient.invalidateQueries({
        queryKey: campaignQueryKeys.lists()
      })
      
      toast.success(`Updated ${variables.campaignIds.length} campaigns successfully`)
    },
    onError: (error: any) => {
      toast.error(error.message || 'Failed to update campaigns')
    },
  })
}

// Helper hook for prefetching campaign data
export function usePrefetchCampaigns() {
  const queryClient = useQueryClient()
  
  return {
    prefetchCampaigns: async (accountId: string) => {
      await queryClient.prefetchQuery({
        queryKey: campaignQueryKeys.list(accountId),
        queryFn: async () => {
          const response = await clientSafeApi.getCampaigns(accountId)
          return response
        },
        staleTime: 5 * 60 * 1000,
      })
    },
    
    prefetchCampaignInsights: async (campaignId: string, timeRange?: { since: string; until: string }) => {
      await queryClient.prefetchQuery({
        queryKey: campaignQueryKeys.insight(campaignId, timeRange),
        queryFn: async () => {
          const response = await clientSafeApi.getInsights(campaignId, timeRange ? `${timeRange.since}_${timeRange.until}` : undefined)
          return response
        },
        staleTime: 2 * 60 * 1000,
      })
    },
  }
}