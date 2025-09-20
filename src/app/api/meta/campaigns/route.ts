import { NextRequest, NextResponse } from 'next/server'
import { getServerSession } from 'next-auth'
import { authOptions } from '@/lib/auth'
import { metaGraphApiClient } from '@/lib/api-client'
import { databaseManager } from '@/lib/database'
import { cacheManager } from '@/lib/cache'
import { logger } from '@/lib/logger'
import { metaApiCache } from '@/lib/cache/meta-api-cache'
import { webSocketManager } from '@/lib/realtime/websocket-manager'
import { jobQueueManager } from '@/lib/jobs/job-queue-manager'
import { timeSeriesManager } from '@/lib/data/time-series-manager'
import { dataSyncService } from '@/lib/data/data-sync-service'

export async function GET(request: NextRequest) {
  const startTime = Date.now()
  const requestId = logger.logApiRequest('/api/meta/campaigns', 'GET')
  
  try {
    // Check authentication
    const session = await getServerSession(authOptions)
    if (!session) {
      logger.logApiResponse(requestId, '/api/meta/campaigns', 'GET', 401, Date.now() - startTime)
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
    }

    // Get query parameters
    const { searchParams } = new URL(request.url)
    const accountId = searchParams.get('account_id')
    const limit = parseInt(searchParams.get('limit') || '100')
    const status = searchParams.get('status')
    const objective = searchParams.get('objective')

    if (!accountId) {
      logger.logApiResponse(requestId, '/api/meta/campaigns', 'GET', 400, Date.now() - startTime)
      return NextResponse.json({ error: 'account_id parameter is required' }, { status: 400 })
    }

    // Check intelligent cache first
    const cacheKey = `campaigns:${accountId}:${status || 'all'}:${objective || 'all'}`
    let cachedData = await metaApiCache.get(cacheKey)

    if (cachedData) {
      logger.logCacheHit(cacheKey)

      // Filter cached data based on query parameters
      let filteredData = cachedData.data || cachedData
      if (status) {
        filteredData = filteredData.filter((campaign: any) => campaign.status === status)
      }
      if (objective) {
        filteredData = filteredData.filter((campaign: any) => campaign.objective === objective)
      }

      // Send real-time update to connected clients
      await webSocketManager.sendToUser(session.user.id, 'campaigns_loaded', {
        accountId,
        count: filteredData.length,
        fromCache: true,
        timestamp: new Date().toISOString()
      })

      logger.logApiResponse(requestId, '/api/meta/campaigns', 'GET', 200, Date.now() - startTime)
      return NextResponse.json({
        data: filteredData.slice(0, limit),
        total: filteredData.length,
        cached: true,
        cache_strategy: 'intelligent',
        updated_at: new Date().toISOString(),
      })
    }

    logger.logCacheMiss(cacheKey)

    // Fetch from Meta Graph API with intelligent caching
    logger.logMetaApiCall(`/act_${accountId}/campaigns`, 'GET', accountId)
    const campaignFields = [
      'id', 'name', 'objective', 'status', 'created_time', 'updated_time',
      'start_time', 'stop_time', 'daily_budget', 'lifetime_budget', 'budget_remaining',
      'configured_status', 'effective_status', 'account_id', 'bid_strategy',
      'optimization_goal', 'spend_cap', 'issues_info'
    ]

    const campaignsResponse = await metaGraphApiClient.getCampaigns(
      accountId,
      campaignFields,
      limit,
      true // Use cache
    )
    
    if (!campaignsResponse.data) {
      throw new Error('No campaigns data received from Meta API')
    }

    // Process and store campaign data
    const campaigns = campaignsResponse.data
    const processedCampaigns = []

    for (const campaign of campaigns) {
      try {
        // Store/update campaign in database
        await databaseManager.getConnection().then(async (pool) => {
          const query = `
            INSERT INTO campaigns (
              id, name, account_id, objective, status, configured_status, effective_status,
              daily_budget, lifetime_budget, budget_remaining, bid_strategy, optimization_goal,
              spend_cap, start_time, stop_time, created_time, updated_time, issues_info_json,
              last_sync_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())
            ON DUPLICATE KEY UPDATE
              name = VALUES(name), objective = VALUES(objective), status = VALUES(status),
              configured_status = VALUES(configured_status), effective_status = VALUES(effective_status),
              daily_budget = VALUES(daily_budget), lifetime_budget = VALUES(lifetime_budget),
              budget_remaining = VALUES(budget_remaining), bid_strategy = VALUES(bid_strategy),
              optimization_goal = VALUES(optimization_goal), spend_cap = VALUES(spend_cap),
              start_time = VALUES(start_time), stop_time = VALUES(stop_time),
              created_time = VALUES(created_time), updated_time = VALUES(updated_time),
              issues_info_json = VALUES(issues_info_json), last_sync_at = NOW(),
              updated_at = CURRENT_TIMESTAMP
          `

          const values = [
            campaign.id,
            campaign.name,
            accountId,
            campaign.objective || null,
            campaign.status,
            campaign.configured_status || null,
            campaign.effective_status || null,
            campaign.daily_budget ? parseFloat(campaign.daily_budget) : null,
            campaign.lifetime_budget ? parseFloat(campaign.lifetime_budget) : null,
            campaign.budget_remaining ? parseFloat(campaign.budget_remaining) : null,
            campaign.bid_strategy || null,
            campaign.optimization_goal || null,
            campaign.spend_cap ? parseFloat(campaign.spend_cap) : null,
            campaign.start_time || null,
            campaign.stop_time || null,
            campaign.created_time || null,
            campaign.updated_time || null,
            campaign.issues_info ? JSON.stringify(campaign.issues_info) : null,
          ]

          await pool.execute(query, values)
        })

        processedCampaigns.push({
          id: campaign.id,
          name: campaign.name,
          account_id: accountId,
          objective: campaign.objective,
          status: campaign.status,
          configured_status: campaign.configured_status,
          effective_status: campaign.effective_status,
          daily_budget: campaign.daily_budget,
          lifetime_budget: campaign.lifetime_budget,
          budget_remaining: campaign.budget_remaining,
          bid_strategy: campaign.bid_strategy,
          optimization_goal: campaign.optimization_goal,
          spend_cap: campaign.spend_cap,
          start_time: campaign.start_time,
          stop_time: campaign.stop_time,
          created_time: campaign.created_time,
          updated_time: campaign.updated_time,
          issues_info: campaign.issues_info,
        })

        logger.logDataSync('campaign', campaign.id, accountId, 1)
      } catch (dbError) {
        logger.error(`Failed to store campaign ${campaign.id}`, dbError, { 
          campaignId: campaign.id,
          accountId,
        })
        // Continue processing other campaigns even if one fails
      }
    }

    // Apply filters if specified
    let filteredCampaigns = processedCampaigns
    if (status) {
      filteredCampaigns = filteredCampaigns.filter(campaign => campaign.status === status)
    }
    if (objective) {
      filteredCampaigns = filteredCampaigns.filter(campaign => campaign.objective === objective)
    }

    const responseData = {
      data: filteredCampaigns,
      total: filteredCampaigns.length,
      account_id: accountId,
      filters: { status, objective },
      updated_at: new Date().toISOString(),
    }

    // Store in intelligent cache with automatic strategy selection
    await metaApiCache.set(cacheKey, responseData, 'standard')

    // Store time-series data for analytics
    await timeSeriesManager.addDataPoint(`campaigns:count:${accountId}`, {
      timestamp: Date.now(),
      value: processedCampaigns.length,
      metadata: {
        active: processedCampaigns.filter(c => c.status === 'ACTIVE').length,
        paused: processedCampaigns.filter(c => c.status === 'PAUSED').length,
        archived: processedCampaigns.filter(c => c.status === 'ARCHIVED').length
      }
    })

    // Trigger background sync job for detailed insights
    await jobQueueManager.addJob('campaign_sync', {
      adAccountId: accountId,
      syncType: 'incremental',
      timestamp: new Date().toISOString(),
      userId: session.user.id,
      metadata: {
        triggerSource: 'api_request',
        campaignIds: processedCampaigns.map(c => c.id)
      }
    }, { priority: 'normal' })

    // Send real-time update to connected clients
    await webSocketManager.sendToUser(session.user.id, 'campaigns_loaded', {
      accountId,
      count: filteredCampaigns.length,
      fromCache: false,
      timestamp: new Date().toISOString(),
      syncJobTriggered: true
    })

    // Sync with MySQL for data consistency
    await dataSyncService.syncEntity('campaigns', processedCampaigns, {
      conflictResolution: 'latest_timestamp',
      batchSize: 50
    })

    logger.logApiResponse(requestId, '/api/meta/campaigns', 'GET', 200, Date.now() - startTime, {
      accountId,
      campaignsCount: filteredCampaigns.length,
      totalCampaigns: processedCampaigns.length,
      cacheStrategy: 'intelligent',
      syncJobTriggered: true
    })

    return NextResponse.json({
      ...responseData,
      cache_strategy: 'intelligent',
      sync_job_triggered: true
    })

  } catch (error) {
    logger.error('Failed to fetch Meta campaigns', error, {
      requestId,
      endpoint: '/api/meta/campaigns',
      accountId: new URL(request.url).searchParams.get('account_id'),
    })

    logger.logApiResponse(requestId, '/api/meta/campaigns', 'GET', 500, Date.now() - startTime)

    return NextResponse.json(
      { 
        error: 'Failed to fetch campaigns',
        message: error instanceof Error ? error.message : 'Unknown error',
      },
      { status: 500 }
    )
  }
}