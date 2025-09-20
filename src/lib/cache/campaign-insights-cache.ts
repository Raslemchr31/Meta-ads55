import { metaApiCache, CacheStrategy } from './meta-api-cache'
import { logger } from '@/lib/logger'
import { redisManager, RedisDatabase } from '@/lib/redis-manager'

export interface CampaignInsight {
  campaignId: string
  adAccountId: string
  metrics: {
    impressions: number
    clicks: number
    spend: number
    cpm: number
    cpc: number
    ctr: number
    roas: number
    conversions: number
    conversionRate: number
  }
  breakdown?: {
    byAge?: Record<string, any>
    byGender?: Record<string, any>
    byPlacement?: Record<string, any>
    byDevice?: Record<string, any>
    byCountry?: Record<string, any>
  }
  dateRange: {
    since: string
    until: string
  }
  lastUpdated: string
}

export interface OptimizationRecommendation {
  campaignId: string
  type: 'bid_adjustment' | 'budget_reallocation' | 'audience_expansion' | 'creative_refresh' | 'placement_optimization'
  priority: 'low' | 'medium' | 'high' | 'critical'
  impact: 'low' | 'medium' | 'high'
  confidence: number
  recommendation: string
  estimatedImprovement: {
    metric: string
    currentValue: number
    projectedValue: number
    improvementPercentage: number
  }
  implementationSteps: string[]
  generatedAt: string
}

export interface RealTimeBidData {
  campaignId: string
  adSetId: string
  currentBid: number
  recommendedBid: number
  competitiveIndex: number
  qualityScore: number
  estimatedReach: number
  bidAdjustmentReason: string
  lastUpdated: string
}

export class CampaignInsightsCache {
  private readonly CACHE_KEYS = {
    campaignInsights: (campaignId: string, dateRange: string) =>
      `campaign:insights:${campaignId}:${dateRange}`,
    campaignMetrics: (campaignId: string) =>
      `campaign:metrics:${campaignId}`,
    optimizationRecommendations: (campaignId: string) =>
      `campaign:optimization:${campaignId}`,
    realTimeBids: (adSetId: string) =>
      `bid:realtime:${adSetId}`,
    performanceAggregates: (adAccountId: string, period: string) =>
      `performance:aggregate:${adAccountId}:${period}`,
    competitorAnalysis: (campaignId: string) =>
      `competitor:analysis:${campaignId}`,
    audienceInsights: (campaignId: string, audienceId: string) =>
      `audience:insights:${campaignId}:${audienceId}`
  }

  async getCampaignInsights(
    campaignId: string,
    dateRange: string,
    forceRefresh = false
  ): Promise<CampaignInsight | null> {
    const cacheKey = this.CACHE_KEYS.campaignInsights(campaignId, dateRange)

    if (!forceRefresh) {
      const cached = await metaApiCache.get<CampaignInsight>(cacheKey, {
        strategy: 'standard',
        tags: [`campaign:${campaignId}`, 'insights'],
        dependencies: [`campaign:${campaignId}`]
      })

      if (cached) {
        logger.debug('Campaign insights cache hit', { campaignId, dateRange })
        return cached.data
      }
    }

    // Cache miss - this would typically fetch from Meta API
    logger.debug('Campaign insights cache miss', { campaignId, dateRange })
    return null
  }

  async setCampaignInsights(
    campaignId: string,
    dateRange: string,
    insights: CampaignInsight
  ): Promise<boolean> {
    const cacheKey = this.CACHE_KEYS.campaignInsights(campaignId, dateRange)

    // Determine cache strategy based on data freshness
    const dataAge = Date.now() - new Date(insights.lastUpdated).getTime()
    const strategy: CacheStrategy = dataAge < 300000 ? 'real-time' : 'standard' // 5 minutes

    const success = await metaApiCache.set(cacheKey, insights, {
      strategy,
      tags: [`campaign:${campaignId}`, 'insights', `account:${insights.adAccountId}`],
      dependencies: [`campaign:${campaignId}`, `account:${insights.adAccountId}`],
      priority: 8
    })

    if (success) {
      // Also update latest metrics cache
      await this.updateLatestMetrics(campaignId, insights.metrics)

      // Store time-series data for trending
      await this.storeTimeSeriesData(campaignId, insights)
    }

    return success
  }

  async getOptimizationRecommendations(campaignId: string): Promise<OptimizationRecommendation[]> {
    const cacheKey = this.CACHE_KEYS.optimizationRecommendations(campaignId)

    const cached = await metaApiCache.get<OptimizationRecommendation[]>(cacheKey, {
      strategy: 'conservative', // Recommendations should be fresh
      tags: [`campaign:${campaignId}`, 'optimization'],
      dependencies: [`campaign:${campaignId}`]
    })

    return cached?.data || []
  }

  async setOptimizationRecommendations(
    campaignId: string,
    recommendations: OptimizationRecommendation[]
  ): Promise<boolean> {
    const cacheKey = this.CACHE_KEYS.optimizationRecommendations(campaignId)

    return await metaApiCache.set(cacheKey, recommendations, {
      strategy: 'conservative',
      ttl: 900, // 15 minutes
      tags: [`campaign:${campaignId}`, 'optimization'],
      dependencies: [`campaign:${campaignId}`],
      priority: 9
    })
  }

  async getRealTimeBidData(adSetId: string): Promise<RealTimeBidData | null> {
    const cacheKey = this.CACHE_KEYS.realTimeBids(adSetId)

    const cached = await metaApiCache.get<RealTimeBidData>(cacheKey, {
      strategy: 'real-time',
      tags: [`adset:${adSetId}`, 'bidding'],
      dependencies: [`adset:${adSetId}`]
    })

    return cached?.data || null
  }

  async setRealTimeBidData(adSetId: string, bidData: RealTimeBidData): Promise<boolean> {
    const cacheKey = this.CACHE_KEYS.realTimeBids(adSetId)

    const success = await metaApiCache.set(cacheKey, bidData, {
      strategy: 'real-time',
      ttl: 30, // 30 seconds for real-time bidding
      tags: [`adset:${adSetId}`, 'bidding', `campaign:${bidData.campaignId}`],
      dependencies: [`adset:${adSetId}`, `campaign:${bidData.campaignId}`],
      priority: 10 // Highest priority
    })

    if (success) {
      // Trigger real-time update notification
      await this.notifyBidUpdate(adSetId, bidData)
    }

    return success
  }

  async getPerformanceAggregates(
    adAccountId: string,
    period: 'hour' | 'day' | 'week' | 'month'
  ): Promise<any> {
    const cacheKey = this.CACHE_KEYS.performanceAggregates(adAccountId, period)

    const cached = await metaApiCache.get(cacheKey, {
      strategy: period === 'hour' ? 'real-time' : 'standard',
      tags: [`account:${adAccountId}`, 'aggregates', period],
      dependencies: [`account:${adAccountId}`]
    })

    return cached?.data || null
  }

  async setPerformanceAggregates(
    adAccountId: string,
    period: 'hour' | 'day' | 'week' | 'month',
    data: any
  ): Promise<boolean> {
    const cacheKey = this.CACHE_KEYS.performanceAggregates(adAccountId, period)

    const ttlMap = {
      hour: 300,    // 5 minutes
      day: 3600,    // 1 hour
      week: 7200,   // 2 hours
      month: 14400  // 4 hours
    }

    return await metaApiCache.set(cacheKey, data, {
      strategy: period === 'hour' ? 'real-time' : 'standard',
      ttl: ttlMap[period],
      tags: [`account:${adAccountId}`, 'aggregates', period],
      dependencies: [`account:${adAccountId}`],
      priority: 7
    })
  }

  async invalidateCampaignCache(campaignId: string): Promise<void> {
    logger.info('Invalidating campaign cache', { campaignId })

    // Invalidate by tag
    await metaApiCache.invalidateByTag(`campaign:${campaignId}`)

    // Also invalidate dependency
    await metaApiCache.invalidateByDependency(`campaign:${campaignId}`)
  }

  async invalidateAccountCache(adAccountId: string): Promise<void> {
    logger.info('Invalidating account cache', { adAccountId })

    await metaApiCache.invalidateByTag(`account:${adAccountId}`)
    await metaApiCache.invalidateByDependency(`account:${adAccountId}`)
  }

  async warmUpCache(campaignIds: string[], dateRanges: string[]): Promise<void> {
    logger.info('Warming up campaign cache', {
      campaignCount: campaignIds.length,
      dateRanges
    })

    const warmupPromises = []

    for (const campaignId of campaignIds) {
      for (const dateRange of dateRanges) {
        // This would trigger actual data fetching in a real implementation
        warmupPromises.push(this.getCampaignInsights(campaignId, dateRange))
      }
    }

    try {
      await Promise.allSettled(warmupPromises)
      logger.info('Cache warmup completed')
    } catch (error) {
      logger.error('Cache warmup failed', {
        error: error instanceof Error ? error.message : 'Unknown error'
      })
    }
  }

  async getTopPerformingCampaigns(
    adAccountId: string,
    metric: string = 'roas',
    limit: number = 10
  ): Promise<any[]> {
    try {
      const client = redisManager.getConnection(RedisDatabase.CACHE)

      // Get top campaigns from sorted set
      const topCampaigns = await client.zrevrange(
        `leaderboard:${adAccountId}:${metric}`,
        0,
        limit - 1,
        'WITHSCORES'
      )

      const results = []
      for (let i = 0; i < topCampaigns.length; i += 2) {
        const campaignId = topCampaigns[i]
        const score = parseFloat(topCampaigns[i + 1])

        // Get cached campaign data
        const campaignData = await this.getCampaignInsights(campaignId, 'last_7_days')

        if (campaignData) {
          results.push({
            campaignId,
            score,
            insights: campaignData
          })
        }
      }

      return results

    } catch (error) {
      logger.error('Failed to get top performing campaigns', {
        adAccountId,
        metric,
        error: error instanceof Error ? error.message : 'Unknown error'
      })
      return []
    }
  }

  private async updateLatestMetrics(campaignId: string, metrics: any): Promise<void> {
    try {
      const client = redisManager.getConnection(RedisDatabase.CACHE)
      const metricsKey = this.CACHE_KEYS.campaignMetrics(campaignId)

      await client.hset(metricsKey, {
        impressions: metrics.impressions,
        clicks: metrics.clicks,
        spend: metrics.spend,
        cpm: metrics.cpm,
        cpc: metrics.cpc,
        ctr: metrics.ctr,
        roas: metrics.roas,
        conversions: metrics.conversions,
        conversionRate: metrics.conversionRate,
        lastUpdated: new Date().toISOString()
      })

      await client.expire(metricsKey, 3600) // 1 hour expiry

      // Update leaderboards for different metrics
      const adAccountId = 'default' // Would be extracted from campaign data
      await client.zadd(`leaderboard:${adAccountId}:roas`, metrics.roas || 0, campaignId)
      await client.zadd(`leaderboard:${adAccountId}:ctr`, metrics.ctr || 0, campaignId)
      await client.zadd(`leaderboard:${adAccountId}:conversions`, metrics.conversions || 0, campaignId)

    } catch (error) {
      logger.error('Failed to update latest metrics', {
        campaignId,
        error: error instanceof Error ? error.message : 'Unknown error'
      })
    }
  }

  private async storeTimeSeriesData(campaignId: string, insights: CampaignInsight): Promise<void> {
    try {
      const client = redisManager.getConnection(RedisDatabase.ANALYTICS)
      const timestamp = Date.now()

      // Store metrics as time series
      const timeSeriesData = {
        timestamp,
        metrics: insights.metrics,
        campaignId
      }

      // Add to time series
      await client.zadd(
        `timeseries:campaign:${campaignId}`,
        timestamp,
        JSON.stringify(timeSeriesData)
      )

      // Keep only last 30 days of data
      const thirtyDaysAgo = timestamp - (30 * 24 * 60 * 60 * 1000)
      await client.zremrangebyscore(
        `timeseries:campaign:${campaignId}`,
        0,
        thirtyDaysAgo
      )

      await client.expire(`timeseries:campaign:${campaignId}`, 30 * 24 * 60 * 60) // 30 days

    } catch (error) {
      logger.error('Failed to store time series data', {
        campaignId,
        error: error instanceof Error ? error.message : 'Unknown error'
      })
    }
  }

  private async notifyBidUpdate(adSetId: string, bidData: RealTimeBidData): Promise<void> {
    try {
      const client = redisManager.getConnection(RedisDatabase.REALTIME)

      // Publish real-time update
      await client.publish(`bid:updates:${adSetId}`, JSON.stringify({
        type: 'bid_update',
        adSetId,
        data: bidData,
        timestamp: Date.now()
      }))

      // Also publish to campaign channel
      await client.publish(`campaign:updates:${bidData.campaignId}`, JSON.stringify({
        type: 'bid_update',
        adSetId,
        data: bidData,
        timestamp: Date.now()
      }))

    } catch (error) {
      logger.error('Failed to notify bid update', {
        adSetId,
        error: error instanceof Error ? error.message : 'Unknown error'
      })
    }
  }
}

export const campaignInsightsCache = new CampaignInsightsCache()