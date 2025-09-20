import { create } from 'zustand'

interface Campaign {
  id: string
  name: string
  objective: string
  status: 'active' | 'paused' | 'deleted' | 'draft'
  budget: {
    amount: number
    type: 'daily' | 'lifetime'
  }
  spend: number
  reach: number
  impressions: number
  clicks: number
  conversions: number
  ctr: number
  cpc: number
  cpm: number
  roas: number
  createdAt: Date
  updatedAt: Date
  startDate: Date
  endDate?: Date
  pageId: string
  adSets: AdSet[]
}

interface AdSet {
  id: string
  name: string
  campaignId: string
  status: 'active' | 'paused' | 'deleted'
  budget: {
    amount: number
    type: 'daily' | 'lifetime'
  }
  targeting: {
    locations: string[]
    ageMin: number
    ageMax: number
    genders: string[]
    interests: string[]
    behaviors: string[]
    customAudiences: string[]
    lookalikeSources: string[]
  }
  placement: string[]
  optimization: string
  bidStrategy: string
  ads: Ad[]
}

interface Ad {
  id: string
  name: string
  adSetId: string
  status: 'active' | 'paused' | 'deleted'
  creative: {
    type: 'image' | 'video' | 'carousel' | 'slideshow'
    title: string
    body: string
    callToAction: string
    imageUrl?: string
    videoUrl?: string
    images?: string[]
  }
  metrics: {
    impressions: number
    clicks: number
    spend: number
    conversions: number
    ctr: number
    cpc: number
    cpm: number
  }
}

interface CampaignFilters {
  status: string[]
  objectives: string[]
  dateRange: {
    from: Date
    to: Date
  }
  spendRange: {
    min: number
    max: number
  }
  pageIds: string[]
  searchQuery: string
}

interface CampaignState {
  campaigns: Campaign[]
  selectedCampaignId: string | null
  selectedAdSetId: string | null
  selectedAdId: string | null
  filters: CampaignFilters
  isLoading: boolean
  error: string | null
  sortBy: string
  sortOrder: 'asc' | 'desc'
  viewMode: 'grid' | 'list'
}

interface CampaignActions {
  // Campaign CRUD
  setCampaigns: (campaigns: Campaign[]) => void
  addCampaign: (campaign: Campaign) => void
  updateCampaign: (id: string, updates: Partial<Campaign>) => void
  deleteCampaign: (id: string) => void
  
  // Campaign status actions
  pauseCampaign: (id: string) => void
  resumeCampaign: (id: string) => void
  duplicateCampaign: (id: string) => Promise<string>
  
  // Selection
  setSelectedCampaign: (id: string | null) => void
  setSelectedAdSet: (id: string | null) => void
  setSelectedAd: (id: string | null) => void
  
  // Filters and sorting
  setFilters: (filters: Partial<CampaignFilters>) => void
  resetFilters: () => void
  setSortBy: (field: string) => void
  setSortOrder: (order: 'asc' | 'desc') => void
  setViewMode: (mode: 'grid' | 'list') => void
  
  // Search
  searchCampaigns: (query: string) => void
  
  // Loading and error states
  setLoading: (loading: boolean) => void
  setError: (error: string | null) => void
  clearError: () => void
  
  // Bulk actions
  bulkUpdateStatus: (campaignIds: string[], status: 'active' | 'paused') => void
  bulkDelete: (campaignIds: string[]) => void
  
  // Analytics helpers
  getCampaignMetrics: (id: string) => Pick<Campaign, 'spend' | 'reach' | 'impressions' | 'clicks' | 'conversions' | 'ctr' | 'cpc' | 'cpm' | 'roas'> | null
  getTotalSpend: () => number
  getAverageROAS: () => number
  
  // Reset
  reset: () => void
}

type CampaignStore = CampaignState & CampaignActions

const initialFilters: CampaignFilters = {
  status: [],
  objectives: [],
  dateRange: {
    from: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000),
    to: new Date(),
  },
  spendRange: {
    min: 0,
    max: 10000,
  },
  pageIds: [],
  searchQuery: '',
}

const initialState: CampaignState = {
  campaigns: [],
  selectedCampaignId: null,
  selectedAdSetId: null,
  selectedAdId: null,
  filters: initialFilters,
  isLoading: false,
  error: null,
  sortBy: 'updatedAt',
  sortOrder: 'desc',
  viewMode: 'list',
}

export const useCampaignStore = create<CampaignStore>((set, get) => ({
  ...initialState,

  // Campaign CRUD
  setCampaigns: (campaigns) => set({ campaigns }),

  addCampaign: (campaign) => set((state) => ({
    campaigns: [campaign, ...state.campaigns],
  })),

  updateCampaign: (id, updates) => set((state) => ({
    campaigns: state.campaigns.map(campaign =>
      campaign.id === id ? { ...campaign, ...updates, updatedAt: new Date() } : campaign
    ),
  })),

  deleteCampaign: (id) => set((state) => ({
    campaigns: state.campaigns.filter(campaign => campaign.id !== id),
    selectedCampaignId: state.selectedCampaignId === id ? null : state.selectedCampaignId,
  })),

  // Campaign status actions
  pauseCampaign: (id) => {
    get().updateCampaign(id, { status: 'paused' })
  },

  resumeCampaign: (id) => {
    get().updateCampaign(id, { status: 'active' })
  },

  duplicateCampaign: async (id) => {
    const campaign = get().campaigns.find(c => c.id === id)
    if (!campaign) throw new Error('Campaign not found')
    
    const duplicatedCampaign: Campaign = {
      ...campaign,
      id: Math.random().toString(36).substring(7),
      name: `${campaign.name} (Copy)`,
      status: 'draft',
      createdAt: new Date(),
      updatedAt: new Date(),
      adSets: campaign.adSets.map(adSet => ({
        ...adSet,
        id: Math.random().toString(36).substring(7),
        campaignId: campaign.id,
        ads: adSet.ads.map(ad => ({
          ...ad,
          id: Math.random().toString(36).substring(7),
          adSetId: adSet.id,
        })),
      })),
    }
    
    get().addCampaign(duplicatedCampaign)
    return duplicatedCampaign.id
  },

  // Selection
  setSelectedCampaign: (id) => set({ selectedCampaignId: id }),
  setSelectedAdSet: (id) => set({ selectedAdSetId: id }),
  setSelectedAd: (id) => set({ selectedAdId: id }),

  // Filters and sorting
  setFilters: (filters) => set((state) => ({
    filters: { ...state.filters, ...filters },
  })),

  resetFilters: () => set({ filters: initialFilters }),

  setSortBy: (field) => set({ sortBy: field }),
  setSortOrder: (order) => set({ sortOrder: order }),
  setViewMode: (mode) => set({ viewMode: mode }),

  // Search
  searchCampaigns: (query) => set((state) => ({
    filters: { ...state.filters, searchQuery: query },
  })),

  // Loading and error states
  setLoading: (loading) => set({ isLoading: loading }),
  setError: (error) => set({ error }),
  clearError: () => set({ error: null }),

  // Bulk actions
  bulkUpdateStatus: (campaignIds, status) => set((state) => ({
    campaigns: state.campaigns.map(campaign =>
      campaignIds.includes(campaign.id)
        ? { ...campaign, status, updatedAt: new Date() }
        : campaign
    ),
  })),

  bulkDelete: (campaignIds) => set((state) => ({
    campaigns: state.campaigns.filter(campaign => !campaignIds.includes(campaign.id)),
    selectedCampaignId: campaignIds.includes(state.selectedCampaignId || '')
      ? null
      : state.selectedCampaignId,
  })),

  // Analytics helpers
  getCampaignMetrics: (id) => {
    const campaign = get().campaigns.find(c => c.id === id)
    if (!campaign) return null
    
    return {
      spend: campaign.spend,
      reach: campaign.reach,
      impressions: campaign.impressions,
      clicks: campaign.clicks,
      conversions: campaign.conversions,
      ctr: campaign.ctr,
      cpc: campaign.cpc,
      cpm: campaign.cpm,
      roas: campaign.roas,
    }
  },

  getTotalSpend: () => {
    return get().campaigns.reduce((total, campaign) => total + campaign.spend, 0)
  },

  getAverageROAS: () => {
    const campaigns = get().campaigns.filter(c => c.roas > 0)
    if (campaigns.length === 0) return 0
    
    const totalROAS = campaigns.reduce((total, campaign) => total + campaign.roas, 0)
    return totalROAS / campaigns.length
  },

  // Reset
  reset: () => set(initialState),
}))

export type { Campaign, AdSet, Ad, CampaignFilters }