import { getSession } from 'next-auth/react'
import { metaApiCache } from './cache/meta-api-cache'
import { campaignInsightsCache } from './cache/campaign-insights-cache'
import { logger } from './logger'

interface ApiClientConfig {
  baseURL: string
  timeout: number
  retries: number
}

interface ApiError {
  message: string
  status: number
  code?: string
  details?: any
}

class ApiClient {
  private config: ApiClientConfig
  private baseURL: string

  constructor(config: Partial<ApiClientConfig> = {}) {
    this.config = {
      baseURL: process.env.NEXT_PUBLIC_API_URL || 'http://localhost:3001/api',
      timeout: 10000,
      retries: 3,
      ...config,
    }
    this.baseURL = this.config.baseURL
  }

  private async getAuthToken(): Promise<string | null> {
    try {
      const session = await getSession()
      return session?.accessToken || null
    } catch (error) {
      console.error('Failed to get auth token:', error)
      return null
    }
  }

  private async makeRequest<T>(
    endpoint: string,
    options: RequestInit = {}
  ): Promise<T> {
    const url = `${this.baseURL}${endpoint}`
    const token = await this.getAuthToken()

    const defaultHeaders: Record<string, string> = {
      'Content-Type': 'application/json',
    }

    if (token) {
      defaultHeaders.Authorization = `Bearer ${token}`
    }

    const config: RequestInit = {
      ...options,
      headers: {
        ...defaultHeaders,
        ...options.headers,
      },
    }

    let lastError: Error

    for (let attempt = 0; attempt <= this.config.retries; attempt++) {
      try {
        const controller = new AbortController()
        const timeoutId = setTimeout(() => controller.abort(), this.config.timeout)

        const response = await fetch(url, {
          ...config,
          signal: controller.signal,
        })

        clearTimeout(timeoutId)

        if (!response.ok) {
          const errorData = await response.json().catch(() => ({}))
          throw new ApiError(
            errorData.message || `HTTP ${response.status}: ${response.statusText}`,
            response.status,
            errorData.code,
            errorData.details
          )
        }

        // Handle empty responses
        const contentType = response.headers.get('content-type')
        if (contentType && contentType.includes('application/json')) {
          return await response.json()
        } else {
          return (await response.text()) as unknown as T
        }
      } catch (error) {
        lastError = error as Error
        
        // Don't retry on client errors (4xx) except for specific cases
        if (error instanceof ApiError && error.status >= 400 && error.status < 500) {
          if (![408, 429].includes(error.status)) {
            throw error
          }
        }

        // Don't retry on the last attempt
        if (attempt === this.config.retries) {
          throw error
        }

        // Exponential backoff
        const delay = Math.min(1000 * Math.pow(2, attempt), 10000)
        await new Promise(resolve => setTimeout(resolve, delay))
      }
    }

    throw lastError!
  }

  // HTTP Methods
  async get<T>(endpoint: string, params?: Record<string, any>): Promise<T> {
    const url = new URL(endpoint, this.baseURL)
    
    if (params) {
      Object.entries(params).forEach(([key, value]) => {
        if (value !== undefined && value !== null) {
          url.searchParams.append(key, String(value))
        }
      })
    }

    return this.makeRequest<T>(url.pathname + url.search)
  }

  async post<T>(endpoint: string, data?: any): Promise<T> {
    return this.makeRequest<T>(endpoint, {
      method: 'POST',
      body: data ? JSON.stringify(data) : undefined,
    })
  }

  async put<T>(endpoint: string, data?: any): Promise<T> {
    return this.makeRequest<T>(endpoint, {
      method: 'PUT',
      body: data ? JSON.stringify(data) : undefined,
    })
  }

  async patch<T>(endpoint: string, data?: any): Promise<T> {
    return this.makeRequest<T>(endpoint, {
      method: 'PATCH',
      body: data ? JSON.stringify(data) : undefined,
    })
  }

  async delete<T>(endpoint: string): Promise<T> {
    return this.makeRequest<T>(endpoint, {
      method: 'DELETE',
    })
  }

  // File upload
  async uploadFile<T>(endpoint: string, file: File, additionalData?: Record<string, any>): Promise<T> {
    const formData = new FormData()
    formData.append('file', file)
    
    if (additionalData) {
      Object.entries(additionalData).forEach(([key, value]) => {
        formData.append(key, String(value))
      })
    }

    const token = await this.getAuthToken()
    const headers: Record<string, string> = {}
    
    if (token) {
      headers.Authorization = `Bearer ${token}`
    }

    return this.makeRequest<T>(endpoint, {
      method: 'POST',
      body: formData,
      headers,
    })
  }
}

// Create a singleton instance
export const apiClient = new ApiClient()

// Meta Graph API v23.0 specific client with System User support
class MetaGraphApiClient extends ApiClient {
  private systemUserToken: string | null = null
  private tokenExpiresAt: number = 0

  constructor() {
    super({
      baseURL: 'https://graph.facebook.com/v23.0',
      timeout: 30000,
      retries: 3,
    })
  }

  private async getMetaToken(): Promise<string | null> {
    try {
      // Try to get System User token first (for production operations)
      if (await this.isSystemUserTokenValid()) {
        return this.systemUserToken
      }

      // Fallback to user session token for user-specific operations
      const session = await getSession()
      return session?.accessToken || null
    } catch (error) {
      console.error('Failed to get Meta token:', error)
      return null
    }
  }

  private async isSystemUserTokenValid(): Promise<boolean> {
    if (!this.systemUserToken || Date.now() >= this.tokenExpiresAt) {
      await this.refreshSystemUserToken()
    }
    return !!this.systemUserToken && Date.now() < this.tokenExpiresAt
  }

  private async refreshSystemUserToken(): Promise<void> {
    try {
      const appId = process.env.FACEBOOK_CLIENT_ID
      const appSecret = process.env.FACEBOOK_CLIENT_SECRET
      const systemUserId = process.env.META_SYSTEM_USER_ID

      if (!appId || !appSecret || !systemUserId) {
        throw new Error('Missing Meta credentials for System User authentication')
      }

      // Generate System User access token
      const response = await fetch(
        `https://graph.facebook.com/v23.0/${systemUserId}/access_tokens`,
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
          },
          body: new URLSearchParams({
            access_token: `${appId}|${appSecret}`,
            scope: [
              'ads_management',
              'ads_read', 
              'business_management',
              'instagram_basic',
              'instagram_manage_insights',
              'read_insights'
            ].join(','),
          }),
        }
      )

      if (!response.ok) {
        throw new Error(`Failed to refresh System User token: ${response.statusText}`)
      }

      const data = await response.json()
      this.systemUserToken = data.access_token
      // System User tokens don't expire, but we'll refresh every 24 hours for security
      this.tokenExpiresAt = Date.now() + (24 * 60 * 60 * 1000)
    } catch (error) {
      console.error('Failed to refresh System User token:', error)
      this.systemUserToken = null
      this.tokenExpiresAt = 0
    }
  }

  protected async makeRequest<T>(endpoint: string, options: RequestInit = {}): Promise<T> {
    const token = await this.getMetaToken()
    
    if (!token) {
      throw new ApiError('No valid Meta access token available', 401)
    }

    const url = `${this.config.baseURL}${endpoint}`
    const defaultHeaders: Record<string, string> = {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${token}`,
    }

    const config: RequestInit = {
      ...options,
      headers: {
        ...defaultHeaders,
        ...options.headers,
      },
    }

    return super.makeRequest<T>(endpoint, config)
  }

  // Business and Ad Account Management
  async getAdAccounts() {
    return this.get('/me/adaccounts', {
      fields: 'id,name,account_status,currency,timezone_name,business,owner,users,funding_source_details,spend_cap,amount_spent,balance,created_time,account_id,business_country_code,min_campaign_group_spend_cap,min_daily_budget,capabilities',
    })
  }

  async getBusinesses() {
    return this.get('/me/businesses', {
      fields: 'id,name,creation_time,timezone_id,primary_page,verification_status,permitted_roles',
    })
  }

  // Campaign Management (v23.0) with intelligent caching
  async getCampaigns(accountId: string, fields?: string[], limit: number = 100, useCache: boolean = true) {
    const params: Record<string, any> = {
      limit,
      fields: fields?.join(',') || 'id,name,objective,status,created_time,updated_time,start_time,stop_time,daily_budget,lifetime_budget,budget_remaining,configured_status,effective_status,account_id,bid_strategy,optimization_goal',
    }

    const cacheKey = `campaigns:${accountId}:${JSON.stringify(params)}`

    if (useCache) {
      const cached = await metaApiCache.get(cacheKey)
      if (cached) {
        logger.info('Cache hit for campaigns', { accountId, cacheKey })
        return cached
      }
    }

    const result = await this.get(`/act_${accountId}/campaigns`, params)

    if (useCache && result) {
      await metaApiCache.set(cacheKey, result, 'standard')
      logger.info('Cached campaigns data', { accountId, cacheKey })
    }

    return result
  }

  async getAdSets(accountId: string, campaignId?: string, fields?: string[], limit: number = 100, useCache: boolean = true) {
    const endpoint = campaignId ? `/${campaignId}/adsets` : `/act_${accountId}/adsets`
    const params: Record<string, any> = {
      limit,
      fields: fields?.join(',') || 'id,name,campaign_id,status,configured_status,effective_status,created_time,updated_time,start_time,end_time,daily_budget,lifetime_budget,budget_remaining,bid_amount,optimization_goal,billing_event,targeting',
    }

    const cacheKey = `adsets:${accountId}:${campaignId || 'all'}:${JSON.stringify(params)}`

    if (useCache) {
      const cached = await metaApiCache.get(cacheKey)
      if (cached) {
        logger.info('Cache hit for adsets', { accountId, campaignId, cacheKey })
        return cached
      }
    }

    const result = await this.get(endpoint, params)

    if (useCache && result) {
      await metaApiCache.set(cacheKey, result, 'standard')
      logger.info('Cached adsets data', { accountId, campaignId, cacheKey })
    }

    return result
  }

  async getAds(accountId: string, adsetId?: string, fields?: string[], limit: number = 100) {
    const endpoint = adsetId ? `/${adsetId}/ads` : `/act_${accountId}/ads`
    const params: Record<string, any> = {
      limit,
      fields: fields?.join(',') || 'id,name,adset_id,campaign_id,status,configured_status,effective_status,created_time,updated_time,creative,preview_shareable_link',
    }

    return this.get(endpoint, params)
  }

  // Insights API (v23.0) - Production ready with comprehensive metrics and intelligent caching
  async getCampaignInsights(
    campaignId: string,
    options: {
      fields?: string[]
      timeRange?: { since: string; until: string }
      breakdowns?: string[]
      actionBreakdowns?: string[]
      level?: 'campaign' | 'adset' | 'ad'
      limit?: number
      useCache?: boolean
    } = {}
  ) {
    const {
      fields = [
        'spend', 'impressions', 'clicks', 'ctr', 'cpc', 'cpm', 'cpp',
        'reach', 'frequency', 'actions', 'action_values', 'conversions',
        'conversion_values', 'cost_per_action_type', 'video_play_actions',
        'video_p25_watched_actions', 'video_p50_watched_actions',
        'video_p75_watched_actions', 'video_p100_watched_actions'
      ],
      timeRange,
      breakdowns,
      actionBreakdowns,
      level = 'campaign',
      limit = 1000,
      useCache = true
    } = options

    const params: Record<string, any> = {
      fields: fields.join(','),
      limit,
      level,
    }

    if (timeRange) {
      params.time_range = JSON.stringify(timeRange)
    }

    if (breakdowns && breakdowns.length > 0) {
      params.breakdowns = breakdowns.join(',')
    }

    if (actionBreakdowns && actionBreakdowns.length > 0) {
      params.action_breakdowns = actionBreakdowns.join(',')
    }

    // Use campaign insights cache for more sophisticated caching
    if (useCache) {
      const dateRange = timeRange ? `${timeRange.since}_${timeRange.until}` : 'default'
      const cached = await campaignInsightsCache.getCampaignInsights(campaignId, dateRange)
      if (cached) {
        logger.info('Cache hit for campaign insights', { campaignId, dateRange })
        return { data: [cached] }
      }
    }

    const result = await this.get(`/${campaignId}/insights`, params)

    // Store in specialized campaign insights cache
    if (useCache && result?.data?.[0]) {
      const dateRange = timeRange ? `${timeRange.since}_${timeRange.until}` : 'default'
      await campaignInsightsCache.setCampaignInsights(campaignId, dateRange, {
        campaignId,
        dateRange,
        lastUpdated: new Date().toISOString(),
        metrics: result.data[0],
        rawData: result.data[0]
      })
      logger.info('Cached campaign insights', { campaignId, dateRange })
    }

    return result
  }

  async getAccountInsights(
    accountId: string, 
    options: {
      fields?: string[]
      timeRange?: { since: string; until: string }
      breakdowns?: string[]
      actionBreakdowns?: string[]
      level?: 'account' | 'campaign' | 'adset' | 'ad'
      limit?: number
    } = {}
  ) {
    const {
      fields = [
        'spend', 'impressions', 'clicks', 'ctr', 'cpc', 'cpm', 'cpp',
        'reach', 'frequency', 'actions', 'action_values', 'conversions',
        'conversion_values', 'cost_per_action_type', 'unique_clicks',
        'unique_ctr', 'unique_link_clicks_ctr', 'cost_per_unique_click'
      ],
      timeRange,
      breakdowns,
      actionBreakdowns,
      level = 'campaign',
      limit = 1000
    } = options

    const params: Record<string, any> = {
      fields: fields.join(','),
      limit,
      level,
    }

    if (timeRange) {
      params.time_range = JSON.stringify(timeRange)
    }

    if (breakdowns && breakdowns.length > 0) {
      params.breakdowns = breakdowns.join(',')
    }

    if (actionBreakdowns && actionBreakdowns.length > 0) {
      params.action_breakdowns = actionBreakdowns.join(',')
    }

    return this.get(`/act_${accountId}/insights`, params)
  }

  // Instagram Integration (v23.0)
  async getInstagramAccounts() {
    return this.get('/me/accounts', {
      fields: 'id,name,instagram_business_account',
    })
  }

  async getInstagramInsights(
    instagramAccountId: string,
    metrics: string[] = ['impressions', 'reach', 'profile_views', 'website_clicks'],
    period: 'day' | 'week' | 'days_28' = 'day',
    since?: string,
    until?: string
  ) {
    const params: Record<string, any> = {
      metric: metrics.join(','),
      period,
    }

    if (since) params.since = since
    if (until) params.until = until

    return this.get(`/${instagramAccountId}/insights`, params)
  }

  // Pages API (v23.0)
  async getPages() {
    return this.get('/me/accounts', {
      fields: 'id,name,category,category_list,access_token,tasks,picture,cover,fan_count,link,location,phone,website,about,description,is_published,can_post,verification_status,instagram_business_account',
    })
  }

  async getPageInsights(
    pageId: string, 
    metrics: string[] = ['page_impressions', 'page_reach', 'page_engaged_users', 'page_fans'], 
    period: string = 'day', 
    since?: string, 
    until?: string
  ) {
    const params: Record<string, any> = {
      metric: metrics.join(','),
      period,
    }

    if (since) params.since = since
    if (until) params.until = until

    return this.get(`/${pageId}/insights`, params)
  }

  // Rate Limiting and Health Check
  async checkRateLimit() {
    try {
      const response = await this.get('/me', { fields: 'id' })
      return { status: 'healthy', data: response }
    } catch (error) {
      if (error instanceof ApiError && error.status === 429) {
        return { status: 'rate_limited', error: error.message }
      }
      return { status: 'error', error: error instanceof Error ? error.message : 'Unknown error' }
    }
  }

  // Batch Requests for Efficiency
  async batchRequest(requests: Array<{ method: string; relative_url: string }>) {
    return this.post('/', {
      batch: JSON.stringify(requests),
    })
  }
}

export const metaGraphApiClient = new MetaGraphApiClient()

// Legacy export for backward compatibility
export const facebookApiClient = metaGraphApiClient

// Error class for API errors
class ApiError extends Error {
  constructor(
    message: string,
    public status: number,
    public code?: string,
    public details?: any
  ) {
    super(message)
    this.name = 'ApiError'
  }
}

export { ApiError }

// Type definitions for common API responses
export interface PaginatedResponse<T> {
  data: T[]
  paging?: {
    cursors?: {
      before: string
      after: string
    }
    next?: string
    previous?: string
  }
  summary?: any
}

export interface FacebookPage {
  id: string
  name: string
  category: string
  category_list: Array<{
    id: string
    name: string
  }>
  access_token: string
  tasks: string[]
  picture?: {
    data: {
      height: number
      is_silhouette: boolean
      url: string
      width: number
    }
  }
  cover?: {
    cover_id: string
    offset_x: number
    offset_y: number
    source: string
    id: string
  }
  fan_count?: number
  link?: string
  location?: any
  phone?: string
  website?: string
  about?: string
  description?: string
  is_published?: boolean
  can_post?: boolean
  verification_status?: string
}

// Updated Meta Graph API v23.0 Types
export interface MetaCampaign {
  id: string
  name: string
  objective: string
  status: string
  created_time: string
  updated_time: string
  start_time?: string
  stop_time?: string
  daily_budget?: string
  lifetime_budget?: string
  budget_remaining?: string
  configured_status: string
  effective_status: string
  account_id: string
  bid_strategy?: string
  optimization_goal?: string
  spend_cap?: string
  issues_info?: Array<{
    error_code: number
    error_summary: string
    level: string
  }>
}

export interface MetaAdSet {
  id: string
  name: string
  campaign_id: string
  status: string
  configured_status: string
  effective_status: string
  created_time: string
  updated_time: string
  start_time?: string
  end_time?: string
  daily_budget?: string
  lifetime_budget?: string
  budget_remaining?: string
  bid_amount?: string
  optimization_goal?: string
  billing_event?: string
  targeting?: any
  issues_info?: Array<{
    error_code: number
    error_summary: string
    level: string
  }>
}

export interface MetaAd {
  id: string
  name: string
  adset_id: string
  campaign_id: string
  status: string
  configured_status: string
  effective_status: string
  created_time: string
  updated_time: string
  creative?: {
    id: string
    name: string
    title?: string
    body?: string
    image_url?: string
    video_id?: string
  }
  preview_shareable_link?: string
  issues_info?: Array<{
    error_code: number
    error_summary: string
    level: string
  }>
}

export interface MetaInsights {
  date_start: string
  date_stop: string
  spend: string
  impressions: string
  clicks: string
  ctr: string
  cpc: string
  cpm: string
  cpp: string
  reach: string
  frequency: string
  actions?: Array<{
    action_type: string
    value: string
  }>
  action_values?: Array<{
    action_type: string
    value: string
  }>
  conversions?: Array<{
    action_type: string
    value: string
  }>
  conversion_values?: Array<{
    action_type: string
    value: string
  }>
  cost_per_action_type?: Array<{
    action_type: string
    value: string
  }>
  video_play_actions?: Array<{
    action_type: string
    value: string
  }>
  video_p25_watched_actions?: Array<{
    action_type: string
    value: string
  }>
  video_p50_watched_actions?: Array<{
    action_type: string
    value: string
  }>
  video_p75_watched_actions?: Array<{
    action_type: string
    value: string
  }>
  video_p100_watched_actions?: Array<{
    action_type: string
    value: string
  }>
  unique_clicks?: string
  unique_ctr?: string
  unique_link_clicks_ctr?: string
  cost_per_unique_click?: string
}

export interface MetaAdAccount {
  id: string
  name: string
  account_status: number
  currency: string
  timezone_name: string
  business?: {
    id: string
    name: string
  }
  owner: string
  users?: Array<{
    id: string
    role: string
    permissions: string[]
  }>
  funding_source_details?: {
    id: string
    display_string: string
    type: number
  }
  spend_cap?: string
  amount_spent: string
  balance: string
  created_time: string
  account_id: string
  business_country_code?: string
  min_campaign_group_spend_cap?: string
  min_daily_budget?: number
  capabilities?: string[]
}

export interface MetaBusiness {
  id: string
  name: string
  creation_time: string
  timezone_id: string
  primary_page?: {
    id: string
    name: string
  }
  verification_status: string
  permitted_roles: string[]
}

// Legacy type aliases for backward compatibility
export interface FacebookCampaign extends MetaCampaign {}
export interface FacebookPage extends MetaPage {}

interface MetaPage {
  id: string
  name: string
  category: string
  category_list: Array<{
    id: string
    name: string
  }>
  access_token: string
  tasks: string[]
  picture?: {
    data: {
      height: number
      is_silhouette: boolean
      url: string
      width: number
    }
  }
  cover?: {
    cover_id: string
    offset_x: number
    offset_y: number
    source: string
    id: string
  }
  fan_count?: number
  link?: string
  location?: any
  phone?: string
  website?: string
  about?: string
  description?: string
  is_published?: boolean
  can_post?: boolean
  verification_status?: string
  instagram_business_account?: {
    id: string
    name: string
    username: string
  }
}