import { jobQueueManager, CampaignSyncJobData } from './job-queue-manager'
import { campaignInsightsCache } from '@/lib/cache/campaign-insights-cache'
import { metaApiCache } from '@/lib/cache/meta-api-cache'
import { redisManager, RedisDatabase } from '@/lib/redis-manager'
import { logger } from '@/lib/logger'
import { notificationSystem } from '@/lib/realtime/notification-system'

export interface SyncSchedule {
  id: string
  name: string
  adAccountId: string
  campaignIds?: string[] // If empty, sync all campaigns
  frequency: 'hourly' | 'daily' | 'weekly' | 'custom'
  customCron?: string // For custom frequency
  syncType: 'full' | 'incremental' | 'metrics_only'
  enabled: boolean
  lastRun?: string
  nextRun?: string
  settings: {
    autoRetry: boolean
    maxRetries: number
    notifyOnFailure: boolean
    notifyOnSuccess: boolean
    notificationUsers: string[]
    dataRetention: number // days
    optimizationEnabled: boolean
  }
}

export interface SyncResult {
  scheduleId: string
  success: boolean
  startTime: string
  endTime: string
  duration: number
  metrics: {
    campaignsSynced: number
    adSetsSynced: number
    adsSynced: number
    insightsUpdated: number
    apiCallsUsed: number
    errorsEncountered: number
  }
  errors?: Array<{
    entityType: 'campaign' | 'adset' | 'ad'
    entityId: string
    error: string
  }>
  warnings?: string[]
}

export class CampaignSyncScheduler {
  private schedules: Map<string, SyncSchedule> = new Map()
  private isRunning = false
  private syncInterval: NodeJS.Timeout | null = null

  async initialize(): Promise<void> {
    try {
      // Load existing schedules from Redis
      await this.loadSchedules()

      // Start the scheduler
      await this.startScheduler()

      logger.info('Campaign sync scheduler initialized successfully', {
        scheduleCount: this.schedules.size
      })

    } catch (error) {
      logger.error('Failed to initialize campaign sync scheduler', {
        error: error instanceof Error ? error.message : 'Unknown error'
      })
      throw error
    }
  }

  async createSchedule(schedule: Omit<SyncSchedule, 'id'>): Promise<string> {
    try {
      const scheduleId = `schedule_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`

      const newSchedule: SyncSchedule = {
        id: scheduleId,
        ...schedule,
        nextRun: this.calculateNextRun(schedule.frequency, schedule.customCron)
      }

      // Validate schedule
      if (!this.validateSchedule(newSchedule)) {
        throw new Error('Invalid schedule configuration')
      }

      // Store schedule
      this.schedules.set(scheduleId, newSchedule)
      await this.saveSchedule(newSchedule)

      logger.info('Campaign sync schedule created', {
        scheduleId,
        name: schedule.name,
        adAccountId: schedule.adAccountId,
        frequency: schedule.frequency
      })

      return scheduleId

    } catch (error) {
      logger.error('Failed to create sync schedule', {
        error: error instanceof Error ? error.message : 'Unknown error'
      })
      throw error
    }
  }

  async updateSchedule(scheduleId: string, updates: Partial<SyncSchedule>): Promise<boolean> {
    try {
      const existingSchedule = this.schedules.get(scheduleId)
      if (!existingSchedule) {
        return false
      }

      const updatedSchedule: SyncSchedule = {
        ...existingSchedule,
        ...updates,
        id: scheduleId // Ensure ID doesn't change
      }

      // Recalculate next run if frequency changed
      if (updates.frequency || updates.customCron) {
        updatedSchedule.nextRun = this.calculateNextRun(
          updatedSchedule.frequency,
          updatedSchedule.customCron
        )
      }

      // Validate updated schedule
      if (!this.validateSchedule(updatedSchedule)) {
        throw new Error('Invalid schedule configuration')
      }

      // Update in memory and Redis
      this.schedules.set(scheduleId, updatedSchedule)
      await this.saveSchedule(updatedSchedule)

      logger.info('Campaign sync schedule updated', {
        scheduleId,
        changes: Object.keys(updates)
      })

      return true

    } catch (error) {
      logger.error('Failed to update sync schedule', {
        scheduleId,
        error: error instanceof Error ? error.message : 'Unknown error'
      })
      return false
    }
  }

  async deleteSchedule(scheduleId: string): Promise<boolean> {
    try {
      const schedule = this.schedules.get(scheduleId)
      if (!schedule) {
        return false
      }

      // Remove from memory
      this.schedules.delete(scheduleId)

      // Remove from Redis
      const client = redisManager.getConnection(RedisDatabase.JOBS)
      await client.hdel('sync:schedules', scheduleId)

      logger.info('Campaign sync schedule deleted', { scheduleId })
      return true

    } catch (error) {
      logger.error('Failed to delete sync schedule', {
        scheduleId,
        error: error instanceof Error ? error.message : 'Unknown error'
      })
      return false
    }
  }

  async getSchedule(scheduleId: string): Promise<SyncSchedule | null> {
    return this.schedules.get(scheduleId) || null
  }

  async getAllSchedules(): Promise<SyncSchedule[]> {
    return Array.from(this.schedules.values())
  }

  async getSchedulesByAccount(adAccountId: string): Promise<SyncSchedule[]> {
    return Array.from(this.schedules.values()).filter(
      schedule => schedule.adAccountId === adAccountId
    )
  }

  async triggerManualSync(
    adAccountId: string,
    options: {
      campaignIds?: string[]
      syncType?: 'full' | 'incremental' | 'metrics_only'
      priority?: 'low' | 'normal' | 'high' | 'critical'
      userId?: string
    } = {}
  ): Promise<string | null> {
    try {
      const syncData: CampaignSyncJobData = {
        adAccountId,
        syncType: options.syncType || 'incremental',
        timestamp: new Date().toISOString(),
        userId: options.userId,
        metadata: {
          manualTrigger: true,
          campaignIds: options.campaignIds
        }
      }

      const job = await jobQueueManager.addJob('campaign_sync', syncData, {
        priority: options.priority || 'normal'
      })

      if (job) {
        logger.info('Manual campaign sync triggered', {
          jobId: job.id,
          adAccountId,
          syncType: syncData.syncType,
          userId: options.userId
        })

        return job.id as string
      }

      return null

    } catch (error) {
      logger.error('Failed to trigger manual sync', {
        adAccountId,
        error: error instanceof Error ? error.message : 'Unknown error'
      })
      return null
    }
  }

  async pauseSchedule(scheduleId: string): Promise<boolean> {
    try {
      const schedule = this.schedules.get(scheduleId)
      if (!schedule) return false

      schedule.enabled = false
      await this.saveSchedule(schedule)

      logger.info('Campaign sync schedule paused', { scheduleId })
      return true

    } catch (error) {
      logger.error('Failed to pause schedule', {
        scheduleId,
        error: error instanceof Error ? error.message : 'Unknown error'
      })
      return false
    }
  }

  async resumeSchedule(scheduleId: string): Promise<boolean> {
    try {
      const schedule = this.schedules.get(scheduleId)
      if (!schedule) return false

      schedule.enabled = true
      schedule.nextRun = this.calculateNextRun(schedule.frequency, schedule.customCron)
      await this.saveSchedule(schedule)

      logger.info('Campaign sync schedule resumed', { scheduleId })
      return true

    } catch (error) {
      logger.error('Failed to resume schedule', {
        scheduleId,
        error: error instanceof Error ? error.message : 'Unknown error'
      })
      return false
    }
  }

  async getSyncHistory(
    scheduleId?: string,
    limit: number = 50
  ): Promise<SyncResult[]> {
    try {
      const client = redisManager.getConnection(RedisDatabase.ANALYTICS)

      const key = scheduleId
        ? `sync:history:${scheduleId}`
        : 'sync:history:global'

      const results = await client.lrange(key, 0, limit - 1)

      return results.map(result => JSON.parse(result))

    } catch (error) {
      logger.error('Failed to get sync history', {
        scheduleId,
        error: error instanceof Error ? error.message : 'Unknown error'
      })
      return []
    }
  }

  private async startScheduler(): Promise<void> {
    if (this.isRunning) return

    this.isRunning = true

    // Check for due schedules every minute
    this.syncInterval = setInterval(async () => {
      await this.checkAndExecuteSchedules()
    }, 60000) // 1 minute

    logger.info('Campaign sync scheduler started')
  }

  private async stopScheduler(): Promise<void> {
    if (this.syncInterval) {
      clearInterval(this.syncInterval)
      this.syncInterval = null
    }

    this.isRunning = false
    logger.info('Campaign sync scheduler stopped')
  }

  private async checkAndExecuteSchedules(): Promise<void> {
    const now = new Date()

    for (const [scheduleId, schedule] of this.schedules) {
      if (!schedule.enabled || !schedule.nextRun) continue

      const nextRunTime = new Date(schedule.nextRun)

      if (now >= nextRunTime) {
        await this.executeSchedule(schedule)
      }
    }
  }

  private async executeSchedule(schedule: SyncSchedule): Promise<void> {
    try {
      logger.info('Executing scheduled sync', {
        scheduleId: schedule.id,
        name: schedule.name,
        adAccountId: schedule.adAccountId
      })

      const syncData: CampaignSyncJobData = {
        adAccountId: schedule.adAccountId,
        syncType: schedule.syncType,
        timestamp: new Date().toISOString(),
        metadata: {
          scheduleId: schedule.id,
          scheduleName: schedule.name,
          campaignIds: schedule.campaignIds
        }
      }

      const job = await jobQueueManager.addJob('campaign_sync', syncData, {
        priority: 'normal'
      })

      if (job) {
        // Update schedule with last run and next run
        schedule.lastRun = new Date().toISOString()
        schedule.nextRun = this.calculateNextRun(schedule.frequency, schedule.customCron)

        await this.saveSchedule(schedule)

        // Store execution record
        await this.recordScheduleExecution(schedule, job.id as string, 'started')

        logger.info('Scheduled sync job created', {
          scheduleId: schedule.id,
          jobId: job.id,
          nextRun: schedule.nextRun
        })
      }

    } catch (error) {
      logger.error('Failed to execute scheduled sync', {
        scheduleId: schedule.id,
        error: error instanceof Error ? error.message : 'Unknown error'
      })

      // Send failure notification if configured
      if (schedule.settings.notifyOnFailure && schedule.settings.notificationUsers.length > 0) {
        await notificationSystem.sendNotification(
          'campaign_performance_alert',
          schedule.settings.notificationUsers,
          {
            scheduleName: schedule.name,
            error: error instanceof Error ? error.message : 'Unknown error',
            adAccountId: schedule.adAccountId
          },
          {
            priority: 'high',
            customTitle: 'Scheduled Sync Failed',
            customMessage: `Failed to execute scheduled sync "${schedule.name}": ${error instanceof Error ? error.message : 'Unknown error'}`
          }
        )
      }
    }
  }

  private calculateNextRun(frequency: string, customCron?: string): string {
    const now = new Date()

    switch (frequency) {
      case 'hourly':
        return new Date(now.getTime() + 60 * 60 * 1000).toISOString()

      case 'daily':
        const tomorrow = new Date(now)
        tomorrow.setDate(tomorrow.getDate() + 1)
        tomorrow.setHours(0, 0, 0, 0)
        return tomorrow.toISOString()

      case 'weekly':
        const nextWeek = new Date(now)
        nextWeek.setDate(nextWeek.getDate() + 7)
        nextWeek.setHours(0, 0, 0, 0)
        return nextWeek.toISOString()

      case 'custom':
        if (customCron) {
          // Simple cron parsing - in production, use a proper cron library
          return new Date(now.getTime() + 24 * 60 * 60 * 1000).toISOString()
        }
        break
    }

    // Default to 1 hour if can't calculate
    return new Date(now.getTime() + 60 * 60 * 1000).toISOString()
  }

  private validateSchedule(schedule: SyncSchedule): boolean {
    // Basic validation - enhance as needed
    if (!schedule.name || !schedule.adAccountId) {
      return false
    }

    if (schedule.frequency === 'custom' && !schedule.customCron) {
      return false
    }

    if (schedule.settings.maxRetries < 0 || schedule.settings.dataRetention < 1) {
      return false
    }

    return true
  }

  private async loadSchedules(): Promise<void> {
    try {
      const client = redisManager.getConnection(RedisDatabase.JOBS)
      const scheduleData = await client.hgetall('sync:schedules')

      for (const [scheduleId, data] of Object.entries(scheduleData)) {
        try {
          const schedule: SyncSchedule = JSON.parse(data)
          this.schedules.set(scheduleId, schedule)
        } catch (error) {
          logger.warn('Failed to parse schedule data', { scheduleId })
        }
      }

      logger.info('Loaded sync schedules', { count: this.schedules.size })

    } catch (error) {
      logger.error('Failed to load schedules', {
        error: error instanceof Error ? error.message : 'Unknown error'
      })
    }
  }

  private async saveSchedule(schedule: SyncSchedule): Promise<void> {
    try {
      const client = redisManager.getConnection(RedisDatabase.JOBS)
      await client.hset('sync:schedules', schedule.id, JSON.stringify(schedule))

    } catch (error) {
      logger.error('Failed to save schedule', {
        scheduleId: schedule.id,
        error: error instanceof Error ? error.message : 'Unknown error'
      })
    }
  }

  private async recordScheduleExecution(
    schedule: SyncSchedule,
    jobId: string,
    status: 'started' | 'completed' | 'failed'
  ): Promise<void> {
    try {
      const client = redisManager.getConnection(RedisDatabase.ANALYTICS)

      const execution = {
        scheduleId: schedule.id,
        scheduleName: schedule.name,
        jobId,
        status,
        timestamp: new Date().toISOString(),
        adAccountId: schedule.adAccountId,
        syncType: schedule.syncType
      }

      // Store in schedule-specific history
      await client.lpush(
        `sync:history:${schedule.id}`,
        JSON.stringify(execution)
      )
      await client.ltrim(`sync:history:${schedule.id}`, 0, 99) // Keep last 100
      await client.expire(`sync:history:${schedule.id}`, 90 * 24 * 60 * 60) // 90 days

      // Store in global history
      await client.lpush('sync:history:global', JSON.stringify(execution))
      await client.ltrim('sync:history:global', 0, 999) // Keep last 1000
      await client.expire('sync:history:global', 90 * 24 * 60 * 60) // 90 days

    } catch (error) {
      logger.error('Failed to record schedule execution', {
        scheduleId: schedule.id,
        error: error instanceof Error ? error.message : 'Unknown error'
      })
    }
  }

  // Cleanup method
  async shutdown(): Promise<void> {
    await this.stopScheduler()
    this.schedules.clear()
    logger.info('Campaign sync scheduler shut down')
  }
}

export const campaignSyncScheduler = new CampaignSyncScheduler()