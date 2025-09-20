/**
 * Facebook Business SDK Integration
 * Production-ready Meta Marketing API client with comprehensive error handling
 */

import { FacebookAdsApi, AdAccount, Campaign, AdSet, Ad, User } from 'facebook-nodejs-business-sdk'
import { logger } from './logger'

interface FacebookSDKConfig {
  accessToken: string
  appId: string
  appSecret: string
  apiVersion?: string
  isDebug?: boolean
}

interface InsightsOptions {
  fields?: string[]
  timeRange?: {
    since: string
    until: string
  }
  breakdowns?: string[]
  actionBreakdowns?: string[]
  level?: 'account' | 'campaign' | 'adset' | 'ad'
  limit?: number
}

export class FacebookSDKClient {
  private api: FacebookAdsApi
  private initialized = false

  constructor(private config: FacebookSDKConfig) {
    this.api = FacebookAdsApi.init({
      accessToken: config.accessToken,
      appId: config.appId,
      appSecret: config.appSecret,
      version: config.apiVersion || 'v23.0',
      isDebug: config.isDebug || false,
    })
    this.initialized = true
  }

  // Initialization and health checks
  async checkApiHealth(): Promise<{ status: 'healthy' | 'error'; message?: string }> {
    try {
      await new User('me').get(['id', 'name'])
      return { status: 'healthy' }
    } catch (error: any) {
      logger.error('Facebook API health check failed:', error)
      return { 
        status: 'error', 
        message: error.message || 'Unknown API error' 
      }
    }
  }

  // Account Management
  async getAdAccounts(): Promise<any[]> {
    try {
      const user = new User('me')
      const accounts = await user.getAdAccounts([
        'id',
        'name', 
        'account_status',
        'currency',
        'timezone_name',
        'business',
        'owner',
        'users',
        'funding_source_details',
        'spend_cap',
        'amount_spent',
        'balance',
        'created_time',
        'account_id',
        'business_country_code',
        'min_campaign_group_spend_cap',
        'min_daily_budget',
        'capabilities'
      ])

      return accounts
    } catch (error: any) {
      logger.error('Failed to fetch ad accounts:', error)
      throw new Error(`Failed to fetch ad accounts: ${error.message}`)
    }
  }

  async getAccountDetails(accountId: string): Promise<any> {
    try {
      const account = new AdAccount(`act_${accountId}`)
      const details = await account.get([
        'id',
        'name',
        'account_status',
        'currency',
        'timezone_name',
        'business',
        'owner',
        'users',
        'funding_source_details',
        'spend_cap',
        'amount_spent',
        'balance',
        'created_time',
        'account_id',
        'business_country_code',
        'min_campaign_group_spend_cap',
        'min_daily_budget',
        'capabilities',
        'age_restrictions',
        'attribution_spec',
        'business_city',
        'business_country_code',
        'business_name',
        'business_state',
        'business_street',
        'business_street2',
        'business_zip',
        'can_create_brand_lift_study',
        'capabilities'
      ])

      return details
    } catch (error: any) {
      logger.error(`Failed to fetch account details for ${accountId}:`, error)
      throw new Error(`Failed to fetch account details: ${error.message}`)
    }
  }

  // Campaign Management
  async getCampaigns(accountId: string, options: { fields?: string[]; limit?: number } = {}): Promise<any[]> {
    try {
      const account = new AdAccount(`act_${accountId}`)
      
      const fields = options.fields || [
        'id',
        'name',
        'objective',
        'status',
        'created_time',
        'updated_time',
        'start_time',
        'stop_time',
        'daily_budget',
        'lifetime_budget',
        'budget_remaining',
        'configured_status',
        'effective_status',
        'account_id',
        'bid_strategy',
        'optimization_goal',
        'issues_info'
      ]

      const campaigns = await account.getCampaigns(fields, {
        limit: options.limit || 100
      })

      return campaigns
    } catch (error: any) {
      logger.error(`Failed to fetch campaigns for account ${accountId}:`, error)
      throw new Error(`Failed to fetch campaigns: ${error.message}`)
    }
  }

  async createCampaign(accountId: string, campaignData: any): Promise<any> {
    try {
      const account = new AdAccount(`act_${accountId}`)
      
      const campaign = await account.createCampaign([], campaignData)
      
      logger.info(`Campaign created successfully: ${campaign.id}`)
      return campaign
    } catch (error: any) {
      logger.error(`Failed to create campaign for account ${accountId}:`, error)
      throw new Error(`Failed to create campaign: ${error.message}`)
    }
  }

  async updateCampaign(campaignId: string, updates: any): Promise<any> {
    try {
      const campaign = new Campaign(campaignId)
      const result = await campaign.update(updates)
      
      logger.info(`Campaign updated successfully: ${campaignId}`)
      return result
    } catch (error: any) {
      logger.error(`Failed to update campaign ${campaignId}:`, error)
      throw new Error(`Failed to update campaign: ${error.message}`)
    }
  }

  async deleteCampaign(campaignId: string): Promise<boolean> {
    try {
      const campaign = new Campaign(campaignId)
      await campaign.update({ status: 'DELETED' })
      
      logger.info(`Campaign deleted successfully: ${campaignId}`)
      return true
    } catch (error: any) {
      logger.error(`Failed to delete campaign ${campaignId}:`, error)
      throw new Error(`Failed to delete campaign: ${error.message}`)
    }
  }

  // Ad Set Management
  async getAdSets(campaignId: string, options: { fields?: string[]; limit?: number } = {}): Promise<any[]> {
    try {
      const campaign = new Campaign(campaignId)
      
      const fields = options.fields || [
        'id',
        'name',
        'campaign_id',
        'status',
        'configured_status',
        'effective_status',
        'created_time',
        'updated_time',
        'start_time',
        'end_time',
        'daily_budget',
        'lifetime_budget',
        'budget_remaining',
        'bid_amount',
        'optimization_goal',
        'billing_event',
        'targeting'
      ]

      const adSets = await campaign.getAdSets(fields, {
        limit: options.limit || 100
      })

      return adSets
    } catch (error: any) {
      logger.error(`Failed to fetch ad sets for campaign ${campaignId}:`, error)
      throw new Error(`Failed to fetch ad sets: ${error.message}`)
    }
  }

  // Ad Management
  async getAds(adSetId: string, options: { fields?: string[]; limit?: number } = {}): Promise<any[]> {
    try {
      const adSet = new AdSet(adSetId)
      
      const fields = options.fields || [
        'id',
        'name',
        'adset_id',
        'campaign_id',
        'status',
        'configured_status',
        'effective_status',
        'created_time',
        'updated_time',
        'creative',
        'preview_shareable_link'
      ]

      const ads = await adSet.getAds(fields, {
        limit: options.limit || 100
      })

      return ads
    } catch (error: any) {
      logger.error(`Failed to fetch ads for ad set ${adSetId}:`, error)
      throw new Error(`Failed to fetch ads: ${error.message}`)
    }
  }

  // Insights and Analytics
  async getCampaignInsights(campaignId: string, options: InsightsOptions = {}): Promise<any> {
    try {
      const campaign = new Campaign(campaignId)
      
      const fields = options.fields || [
        'spend',
        'impressions',
        'clicks',
        'ctr',
        'cpc',
        'cpm',
        'cpp',
        'reach',
        'frequency',
        'actions',
        'action_values',
        'conversions',
        'conversion_values',
        'cost_per_action_type',
        'video_play_actions',
        'video_p25_watched_actions',
        'video_p50_watched_actions',
        'video_p75_watched_actions',
        'video_p100_watched_actions'
      ]

      const params: any = {
        fields,
        limit: options.limit || 1000,
        level: options.level || 'campaign'
      }

      if (options.timeRange) {
        params.time_range = options.timeRange
      }

      if (options.breakdowns && options.breakdowns.length > 0) {
        params.breakdowns = options.breakdowns
      }

      if (options.actionBreakdowns && options.actionBreakdowns.length > 0) {
        params.action_breakdowns = options.actionBreakdowns
      }

      const insights = await campaign.getInsights(fields, params)
      
      return insights
    } catch (error: any) {
      logger.error(`Failed to fetch campaign insights for ${campaignId}:`, error)
      throw new Error(`Failed to fetch campaign insights: ${error.message}`)
    }
  }

  async getAccountInsights(accountId: string, options: InsightsOptions = {}): Promise<any> {
    try {
      const account = new AdAccount(`act_${accountId}`)
      
      const fields = options.fields || [
        'spend',
        'impressions',
        'clicks',
        'ctr',
        'cpc',
        'cpm',
        'cpp',
        'reach',
        'frequency',
        'actions',
        'action_values',
        'conversions',
        'conversion_values',
        'cost_per_action_type',
        'unique_clicks',
        'unique_ctr',
        'unique_link_clicks_ctr',
        'cost_per_unique_click'
      ]

      const params: any = {
        fields,
        limit: options.limit || 1000,
        level: options.level || 'campaign'
      }

      if (options.timeRange) {
        params.time_range = options.timeRange
      }

      if (options.breakdowns && options.breakdowns.length > 0) {
        params.breakdowns = options.breakdowns
      }

      if (options.actionBreakdowns && options.actionBreakdowns.length > 0) {
        params.action_breakdowns = options.actionBreakdowns
      }

      const insights = await account.getInsights(fields, params)
      
      return insights
    } catch (error: any) {
      logger.error(`Failed to fetch account insights for ${accountId}:`, error)
      throw new Error(`Failed to fetch account insights: ${error.message}`)
    }
  }

  // Batch Operations for Performance
  async batchRequest(requests: Array<{ method: string; relative_url: string; body?: any }>): Promise<any> {
    try {
      const response = await this.api.call('POST', '', {
        batch: JSON.stringify(requests)
      })
      
      return response
    } catch (error: any) {
      logger.error('Batch request failed:', error)
      throw new Error(`Batch request failed: ${error.message}`)
    }
  }

  // Bulk campaign operations
  async bulkUpdateCampaigns(updates: Array<{ campaignId: string; data: any }>): Promise<any> {
    try {
      const batchRequests = updates.map(update => ({
        method: 'POST',
        relative_url: update.campaignId,
        body: JSON.stringify(update.data)
      }))

      const results = await this.batchRequest(batchRequests)
      
      logger.info(`Bulk updated ${updates.length} campaigns`)
      return results
    } catch (error: any) {
      logger.error('Bulk campaign update failed:', error)
      throw new Error(`Bulk campaign update failed: ${error.message}`)
    }
  }

  // Rate Limit Management
  async checkRateLimit(): Promise<{ 
    status: 'healthy' | 'rate_limited' | 'error'
    usage?: any
    resetTime?: number 
  }> {
    try {
      // Make a lightweight API call to check rate limits
      const response = await new User('me').get(['id'])
      
      // Extract rate limit headers if available
      const usage = this.api.getLastResponse()?.headers
      
      return {
        status: 'healthy',
        usage,
      }
    } catch (error: any) {
      if (error.code === 4 || error.code === 17) { // Rate limit errors
        return {
          status: 'rate_limited',
          resetTime: error.error_user_msg?.match(/retry after (\d+) seconds/) 
            ? Date.now() + parseInt(error.error_user_msg.match(/retry after (\d+) seconds/)[1]) * 1000
            : Date.now() + 3600000, // Default to 1 hour
        }
      }
      
      return {
        status: 'error'
      }
    }
  }

  // Utility methods
  updateAccessToken(accessToken: string): void {
    this.config.accessToken = accessToken
    this.api = FacebookAdsApi.init({
      accessToken,
      appId: this.config.appId,
      appSecret: this.config.appSecret,
      version: this.config.apiVersion || 'v23.0',
      isDebug: this.config.isDebug || false,
    })
  }

  getConfig(): FacebookSDKConfig {
    return { ...this.config }
  }

  isInitialized(): boolean {
    return this.initialized
  }
}

// Factory function to create SDK client
export function createFacebookSDK(config: FacebookSDKConfig): FacebookSDKClient {
  return new FacebookSDKClient(config)
}

// Global instance for server-side operations (with system user token)
let globalSDKInstance: FacebookSDKClient | null = null

export function getGlobalFacebookSDK(): FacebookSDKClient {
  if (!globalSDKInstance) {
    const config = {
      accessToken: process.env.META_SYSTEM_ACCESS_TOKEN || '',
      appId: process.env.FACEBOOK_CLIENT_ID || '',
      appSecret: process.env.FACEBOOK_CLIENT_SECRET || '',
      apiVersion: 'v23.0',
      isDebug: process.env.NODE_ENV === 'development',
    }

    if (!config.accessToken || !config.appId || !config.appSecret) {
      throw new Error('Missing Facebook SDK configuration. Please set META_SYSTEM_ACCESS_TOKEN, FACEBOOK_CLIENT_ID, and FACEBOOK_CLIENT_SECRET environment variables.')
    }

    globalSDKInstance = new FacebookSDKClient(config)
  }

  return globalSDKInstance
}

// Error handling utilities
export function isFacebookAPIError(error: any): boolean {
  return error && (
    error.error || 
    error.error_code || 
    (error.response && error.response.error)
  )
}

export function parseFacebookError(error: any): {
  code: number | string
  message: string
  type: string
  suggestion?: string
} {
  if (error.error) {
    return {
      code: error.error.code || 'unknown',
      message: error.error.message || error.message || 'Unknown Facebook API error',
      type: error.error.type || 'GraphAPIError',
      suggestion: error.error.error_user_msg || undefined,
    }
  }

  return {
    code: error.code || 'unknown',
    message: error.message || 'Unknown Facebook API error',
    type: error.type || 'UnknownError',
  }
}