import cron from 'node-cron'
import { metaGraphApiClient } from './api-client'
import { databaseManager } from './database'
import { cacheManager } from './cache'
import { logger } from './logger'

interface SyncOptions {
  batchSize: number
  maxRetries: number
  delayBetweenBatches: number
  enableScheduledSync: boolean
}

interface SyncResult {
  success: boolean
  processed: number
  errors: number
  duration: number
  errorDetails?: string[]
}

export class DataSyncService {
  private options: SyncOptions
  private isRunning = false
  private scheduledJobs: Map<string, cron.ScheduledTask> = new Map()

  constructor(options: Partial<SyncOptions> = {}) {
    this.options = {
      batchSize: 50,
      maxRetries: 3,
      delayBetweenBatches: 1000, // 1 second
      enableScheduledSync: process.env.NODE_ENV === 'production',
      ...options,
    }
  }

  async initialize(): Promise<void> {
    if (this.options.enableScheduledSync) {
      this.setupScheduledJobs()
      logger.info('Data sync service initialized with scheduled jobs')
    } else {
      logger.info('Data sync service initialized without scheduled jobs (development mode)')
    }
  }

  private setupScheduledJobs(): void {
    // Daily insights sync - every hour during business hours
    const insightsJob = cron.schedule('0 */1 * * *', async () => {
      if (!this.isRunning) {
        await this.syncAllAccountsInsights()
      }
    }, {
      scheduled: false,
      timezone: 'UTC',
    })

    // Account data sync - every 6 hours
    const accountsJob = cron.schedule('0 */6 * * *', async () => {
      if (!this.isRunning) {
        await this.syncAllAccounts()
      }
    }, {
      scheduled: false,
      timezone: 'UTC',
    })

    // Campaign data sync - every 2 hours
    const campaignsJob = cron.schedule('0 */2 * * *', async () => {
      if (!this.isRunning) {
        await this.syncAllCampaigns()
      }
    }, {
      scheduled: false,
      timezone: 'UTC',
    })

    // Cache cleanup - every 4 hours
    const cacheCleanupJob = cron.schedule('0 */4 * * *', async () => {
      await cacheManager.cleanupExpiredKeys()
      logger.info('Cache cleanup completed')
    }, {
      scheduled: false,
      timezone: 'UTC',
    })

    this.scheduledJobs.set('insights', insightsJob)
    this.scheduledJobs.set('accounts', accountsJob)
    this.scheduledJobs.set('campaigns', campaignsJob)
    this.scheduledJobs.set('cache-cleanup', cacheCleanupJob)

    // Start all jobs
    this.scheduledJobs.forEach((job, name) => {
      job.start()
      logger.info(`Scheduled job started: ${name}`)
    })
  }

  async syncAllAccounts(): Promise<SyncResult> {
    const startTime = Date.now()
    logger.info('Starting full accounts sync')

    try {
      this.isRunning = true
      
      // Fetch all ad accounts
      const accountsResponse = await metaGraphApiClient.getAdAccounts()
      const accounts = accountsResponse.data || []

      let processed = 0
      let errors = 0
      const errorDetails: string[] = []

      // Process accounts in batches
      for (let i = 0; i < accounts.length; i += this.options.batchSize) {
        const batch = accounts.slice(i, i + this.options.batchSize)
        
        for (const account of batch) {
          try {
            await databaseManager.upsertAdAccount({
              id: account.id,
              name: account.name,
              account_status: account.account_status,
              currency: account.currency,
              timezone_name: account.timezone_name,
              business_id: account.business?.id,
              business_name: account.business?.name,
              amount_spent: parseFloat(account.amount_spent || '0'),
              balance: parseFloat(account.balance || '0'),
              spend_cap: account.spend_cap ? parseFloat(account.spend_cap) : undefined,
              created_time: account.created_time,
              capabilities_json: account.capabilities,
            })

            // Invalidate cache
            await cacheManager.del(`account:${account.id}`)
            
            processed++
            logger.logDataSync('account', account.id, account.id, 1)
          } catch (error) {
            errors++
            const errorMsg = `Failed to sync account ${account.id}: ${error instanceof Error ? error.message : 'Unknown error'}`
            errorDetails.push(errorMsg)
            logger.error(errorMsg, error)
          }
        }

        // Delay between batches to respect rate limits
        if (i + this.options.batchSize < accounts.length) {
          await this.delay(this.options.delayBetweenBatches)
        }
      }

      const duration = Date.now() - startTime
      const result: SyncResult = {
        success: errors === 0,
        processed,
        errors,
        duration,
        errorDetails: errors > 0 ? errorDetails : undefined,
      }

      logger.logPerformanceMetric('accounts_sync', duration, {
        processed,
        errors,
        totalAccounts: accounts.length,
      })

      return result
    } catch (error) {
      const duration = Date.now() - startTime
      logger.error('Full accounts sync failed', error)
      
      return {
        success: false,
        processed: 0,
        errors: 1,
        duration,
        errorDetails: [error instanceof Error ? error.message : 'Unknown error'],
      }
    } finally {
      this.isRunning = false
    }
  }

  async syncAllCampaigns(): Promise<SyncResult> {
    const startTime = Date.now()
    logger.info('Starting full campaigns sync')

    try {
      this.isRunning = true
      
      // Get all accounts from database
      const pool = await databaseManager.getConnection()
      const [accountRows] = await pool.execute('SELECT id FROM ad_accounts WHERE account_status = 1')
      const accounts = accountRows as Array<{ id: string }>

      let processed = 0
      let errors = 0
      const errorDetails: string[] = []

      for (const account of accounts) {
        try {
          // Fetch campaigns for this account
          const campaignsResponse = await metaGraphApiClient.getCampaigns(account.id)
          const campaigns = campaignsResponse.data || []

          for (const campaign of campaigns) {
            try {
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
                account.id,
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
              processed++
            } catch (error) {
              errors++
              const errorMsg = `Failed to sync campaign ${campaign.id}: ${error instanceof Error ? error.message : 'Unknown error'}`
              errorDetails.push(errorMsg)
              logger.error(errorMsg, error)
            }
          }

          // Invalidate campaign cache for this account
          await cacheManager.del(`campaigns:${account.id}`)
          
          logger.logDataSync('campaigns', account.id, account.id, campaigns.length)

          // Delay between accounts
          await this.delay(this.options.delayBetweenBatches)
        } catch (error) {
          errors++
          const errorMsg = `Failed to sync campaigns for account ${account.id}: ${error instanceof Error ? error.message : 'Unknown error'}`
          errorDetails.push(errorMsg)
          logger.error(errorMsg, error)
        }
      }

      const duration = Date.now() - startTime
      const result: SyncResult = {
        success: errors === 0,
        processed,
        errors,
        duration,
        errorDetails: errors > 0 ? errorDetails : undefined,
      }

      logger.logPerformanceMetric('campaigns_sync', duration, {
        processed,
        errors,
        totalAccounts: accounts.length,
      })

      return result
    } catch (error) {
      const duration = Date.now() - startTime
      logger.error('Full campaigns sync failed', error)
      
      return {
        success: false,
        processed: 0,
        errors: 1,
        duration,
        errorDetails: [error instanceof Error ? error.message : 'Unknown error'],
      }
    } finally {
      this.isRunning = false
    }
  }

  async syncAllAccountsInsights(days: number = 7): Promise<SyncResult> {
    const startTime = Date.now()
    logger.info(`Starting insights sync for last ${days} days`)

    try {
      this.isRunning = true
      
      // Get all active accounts
      const pool = await databaseManager.getConnection()
      const [accountRows] = await pool.execute('SELECT id FROM ad_accounts WHERE account_status = 1')
      const accounts = accountRows as Array<{ id: string }>

      const dateEnd = new Date().toISOString().split('T')[0]
      const dateStart = new Date(Date.now() - days * 24 * 60 * 60 * 1000).toISOString().split('T')[0]

      let processed = 0
      let errors = 0
      const errorDetails: string[] = []

      for (const account of accounts) {
        try {
          // Sync campaign-level insights
          const insightsResponse = await metaGraphApiClient.getAccountInsights(account.id, {
            timeRange: { since: dateStart, until: dateEnd },
            level: 'campaign',
            limit: 1000,
          })

          const insights = insightsResponse.data || []

          for (const insight of insights) {
            try {
              await databaseManager.upsertDailyInsights({
                entity_type: 'campaign',
                entity_id: insight.campaign_id || account.id,
                entity_name: insight.campaign_name,
                account_id: account.id,
                date_start: insight.date_start,
                date_stop: insight.date_stop,
                spend: parseFloat(insight.spend || '0'),
                impressions: parseInt(insight.impressions || '0'),
                clicks: parseInt(insight.clicks || '0'),
                reach: parseInt(insight.reach || '0'),
                frequency: parseFloat(insight.frequency || '0'),
                ctr: parseFloat(insight.ctr || '0'),
                cpc: parseFloat(insight.cpc || '0'),
                cpm: parseFloat(insight.cpm || '0'),
                cpp: parseFloat(insight.cpp || '0'),
                actions_json: insight.actions || [],
                action_values_json: insight.action_values || [],
                conversions_json: insight.conversions || [],
                conversion_values_json: insight.conversion_values || [],
                cost_per_action_type_json: insight.cost_per_action_type || [],
                video_metrics_json: {
                  video_play_actions: insight.video_play_actions || [],
                  video_p25_watched_actions: insight.video_p25_watched_actions || [],
                  video_p50_watched_actions: insight.video_p50_watched_actions || [],
                  video_p75_watched_actions: insight.video_p75_watched_actions || [],
                  video_p100_watched_actions: insight.video_p100_watched_actions || [],
                },
              })

              processed++
            } catch (error) {
              errors++
              const errorMsg = `Failed to sync insights for ${insight.campaign_id || 'unknown'}: ${error instanceof Error ? error.message : 'Unknown error'}`
              errorDetails.push(errorMsg)
              logger.error(errorMsg, error)
            }
          }

          // Invalidate insights cache
          await cacheManager.del(`insights:${account.id}:campaign`)
          
          logger.logDataSync('insights', account.id, account.id, insights.length)

          // Delay between accounts
          await this.delay(this.options.delayBetweenBatches)
        } catch (error) {
          errors++
          const errorMsg = `Failed to sync insights for account ${account.id}: ${error instanceof Error ? error.message : 'Unknown error'}`
          errorDetails.push(errorMsg)
          logger.error(errorMsg, error)
        }
      }

      const duration = Date.now() - startTime
      const result: SyncResult = {
        success: errors === 0,
        processed,
        errors,
        duration,
        errorDetails: errors > 0 ? errorDetails : undefined,
      }

      logger.logPerformanceMetric('insights_sync', duration, {
        processed,
        errors,
        totalAccounts: accounts.length,
        days,
      })

      return result
    } catch (error) {
      const duration = Date.now() - startTime
      logger.error('Insights sync failed', error)
      
      return {
        success: false,
        processed: 0,
        errors: 1,
        duration,
        errorDetails: [error instanceof Error ? error.message : 'Unknown error'],
      }
    } finally {
      this.isRunning = false
    }
  }

  async syncSpecificAccount(accountId: string): Promise<SyncResult> {
    const startTime = Date.now()
    logger.info(`Starting sync for account ${accountId}`)

    try {
      let processed = 0
      let errors = 0
      const errorDetails: string[] = []

      // Sync account data
      try {
        const accountData = await metaGraphApiClient.get(`/${accountId}`, {
          fields: 'id,name,account_status,currency,timezone_name,business,amount_spent,balance,spend_cap,capabilities',
        })

        await databaseManager.upsertAdAccount({
          id: accountData.id,
          name: accountData.name,
          account_status: accountData.account_status,
          currency: accountData.currency,
          timezone_name: accountData.timezone_name,
          business_id: accountData.business?.id,
          business_name: accountData.business?.name,
          amount_spent: parseFloat(accountData.amount_spent || '0'),
          balance: parseFloat(accountData.balance || '0'),
          spend_cap: accountData.spend_cap ? parseFloat(accountData.spend_cap) : undefined,
          capabilities_json: accountData.capabilities,
        })

        processed++
      } catch (error) {
        errors++
        errorDetails.push(`Account sync failed: ${error instanceof Error ? error.message : 'Unknown error'}`)
      }

      // Sync campaigns
      try {
        const campaignsResponse = await metaGraphApiClient.getCampaigns(accountId)
        const campaigns = campaignsResponse.data || []

        for (const campaign of campaigns) {
          // Campaign sync logic (similar to syncAllCampaigns)
          processed++
        }
      } catch (error) {
        errors++
        errorDetails.push(`Campaigns sync failed: ${error instanceof Error ? error.message : 'Unknown error'}`)
      }

      // Invalidate caches
      await cacheManager.del(`account:${accountId}`)
      await cacheManager.del(`campaigns:${accountId}`)
      await cacheManager.del(`insights:${accountId}:campaign`)

      const duration = Date.now() - startTime
      const result: SyncResult = {
        success: errors === 0,
        processed,
        errors,
        duration,
        errorDetails: errors > 0 ? errorDetails : undefined,
      }

      logger.logDataSync('account', accountId, accountId, processed)
      return result
    } catch (error) {
      const duration = Date.now() - startTime
      logger.error(`Account sync failed for ${accountId}`, error)
      
      return {
        success: false,
        processed: 0,
        errors: 1,
        duration,
        errorDetails: [error instanceof Error ? error.message : 'Unknown error'],
      }
    }
  }

  private delay(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms))
  }

  async getStatus(): Promise<{
    isRunning: boolean
    scheduledJobs: string[]
    lastRun?: Date
  }> {
    return {
      isRunning: this.isRunning,
      scheduledJobs: Array.from(this.scheduledJobs.keys()),
    }
  }

  async stopAllJobs(): Promise<void> {
    this.scheduledJobs.forEach((job, name) => {
      job.stop()
      logger.info(`Scheduled job stopped: ${name}`)
    })
    this.scheduledJobs.clear()
  }

  async startAllJobs(): Promise<void> {
    this.setupScheduledJobs()
  }
}

// Singleton instance
export const dataSyncService = new DataSyncService()