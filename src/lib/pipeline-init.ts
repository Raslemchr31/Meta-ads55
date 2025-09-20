import { logger } from './logger'
import { redisManager } from './redis-manager'
import { metaApiCache } from './cache/meta-api-cache'
import { campaignInsightsCache } from './cache/campaign-insights-cache'
import { webSocketManager } from './realtime/websocket-manager'
import { notificationSystem } from './realtime/notification-system'
import { jobQueueManager } from './jobs/job-queue-manager'
import { campaignSyncScheduler } from './jobs/campaign-sync-scheduler'
import { timeSeriesManager } from './data/time-series-manager'
import { dataSyncService } from './data/data-sync-service'

export interface PipelineStatus {
  redis: 'connected' | 'disconnected' | 'error'
  caches: 'initialized' | 'error'
  websockets: 'running' | 'stopped' | 'error'
  jobs: 'running' | 'stopped' | 'error'
  timeSeries: 'initialized' | 'error'
  dataSync: 'running' | 'stopped' | 'error'
  overall: 'healthy' | 'degraded' | 'critical'
}

export class DataPipelineManager {
  private isInitialized = false
  private components: Map<string, any> = new Map()
  private status: PipelineStatus = {
    redis: 'disconnected',
    caches: 'error',
    websockets: 'stopped',
    jobs: 'stopped',
    timeSeries: 'error',
    dataSync: 'stopped',
    overall: 'critical'
  }

  async initialize(): Promise<void> {
    if (this.isInitialized) {
      logger.warn('Data pipeline already initialized')
      return
    }

    logger.info('Initializing Meta Ads Intelligence Data Pipeline...')

    try {
      // 1. Initialize Redis connections
      await this.initializeRedis()

      // 2. Initialize cache systems
      await this.initializeCaches()

      // 3. Initialize time-series manager
      await this.initializeTimeSeries()

      // 4. Initialize job queue and scheduler
      await this.initializeJobSystem()

      // 5. Initialize WebSocket manager
      await this.initializeWebSockets()

      // 6. Initialize data sync service
      await this.initializeDataSync()

      // 7. Initialize notification system
      await this.initializeNotifications()

      this.isInitialized = true
      this.updateOverallStatus()

      logger.info('Data pipeline initialized successfully', {
        status: this.status,
        components: Array.from(this.components.keys())
      })

    } catch (error) {
      logger.error('Failed to initialize data pipeline', error)
      this.status.overall = 'critical'
      throw new Error(`Pipeline initialization failed: ${error instanceof Error ? error.message : 'Unknown error'}`)
    }
  }

  private async initializeRedis(): Promise<void> {
    try {
      await redisManager.initialize()

      // Test all database connections
      const databases = [
        'sessions',
        'preferences',
        'cache',
        'rateLimiting',
        'jobs',
        'analytics'
      ]

      for (const db of databases) {
        const client = redisManager.getConnection(db as any)
        await client.ping()
      }

      this.status.redis = 'connected'
      this.components.set('redis', redisManager)
      logger.info('Redis connections established for all databases')

    } catch (error) {
      this.status.redis = 'error'
      logger.error('Failed to initialize Redis', error)
      throw error
    }
  }

  private async initializeCaches(): Promise<void> {
    try {
      await metaApiCache.initialize()
      await campaignInsightsCache.initialize()

      this.status.caches = 'initialized'
      this.components.set('metaApiCache', metaApiCache)
      this.components.set('campaignInsightsCache', campaignInsightsCache)
      logger.info('Cache systems initialized')

    } catch (error) {
      this.status.caches = 'error'
      logger.error('Failed to initialize caches', error)
      throw error
    }
  }

  private async initializeTimeSeries(): Promise<void> {
    try {
      await timeSeriesManager.initialize()

      this.status.timeSeries = 'initialized'
      this.components.set('timeSeriesManager', timeSeriesManager)
      logger.info('Time-series manager initialized')

    } catch (error) {
      this.status.timeSeries = 'error'
      logger.error('Failed to initialize time-series manager', error)
      throw error
    }
  }

  private async initializeJobSystem(): Promise<void> {
    try {
      await jobQueueManager.initialize()
      await campaignSyncScheduler.initialize()

      this.status.jobs = 'running'
      this.components.set('jobQueueManager', jobQueueManager)
      this.components.set('campaignSyncScheduler', campaignSyncScheduler)
      logger.info('Job system initialized')

    } catch (error) {
      this.status.jobs = 'error'
      logger.error('Failed to initialize job system', error)
      throw error
    }
  }

  private async initializeWebSockets(): Promise<void> {
    try {
      // WebSocket will be initialized when server starts
      // We just prepare the manager here
      this.status.websockets = 'running'
      this.components.set('webSocketManager', webSocketManager)
      logger.info('WebSocket manager prepared')

    } catch (error) {
      this.status.websockets = 'error'
      logger.error('Failed to prepare WebSocket manager', error)
      throw error
    }
  }

  private async initializeDataSync(): Promise<void> {
    try {
      await dataSyncService.initialize()

      this.status.dataSync = 'running'
      this.components.set('dataSyncService', dataSyncService)
      logger.info('Data sync service initialized')

    } catch (error) {
      this.status.dataSync = 'error'
      logger.error('Failed to initialize data sync service', error)
      throw error
    }
  }

  private async initializeNotifications(): Promise<void> {
    try {
      await notificationSystem.initialize()

      this.components.set('notificationSystem', notificationSystem)
      logger.info('Notification system initialized')

    } catch (error) {
      logger.error('Failed to initialize notification system', error)
      throw error
    }
  }

  private updateOverallStatus(): void {
    const criticalComponents = ['redis', 'caches', 'timeSeries']
    const hasErrors = Object.values(this.status).some(status => status === 'error')
    const hasCriticalErrors = criticalComponents.some(comp => this.status[comp as keyof PipelineStatus] === 'error')

    if (hasCriticalErrors) {
      this.status.overall = 'critical'
    } else if (hasErrors) {
      this.status.overall = 'degraded'
    } else {
      this.status.overall = 'healthy'
    }
  }

  async setupWebSocketServer(server: any): Promise<void> {
    try {
      await webSocketManager.initialize(server)
      this.status.websockets = 'running'
      logger.info('WebSocket server initialized successfully')
    } catch (error) {
      this.status.websockets = 'error'
      logger.error('Failed to initialize WebSocket server', error)
    }
  }

  getStatus(): PipelineStatus {
    return { ...this.status }
  }

  getComponents(): string[] {
    return Array.from(this.components.keys())
  }

  async healthCheck(): Promise<{
    status: PipelineStatus
    timestamp: string
    details: Record<string, any>
  }> {
    const details: Record<string, any> = {}

    // Check Redis
    try {
      const client = redisManager.getConnection('cache')
      await client.ping()
      this.status.redis = 'connected'
      details.redis = { status: 'ok', latency: 'low' }
    } catch (error) {
      this.status.redis = 'error'
      details.redis = { status: 'error', error: error instanceof Error ? error.message : 'Unknown' }
    }

    // Check job queue
    try {
      const stats = await jobQueueManager.getQueueStats()
      details.jobs = {
        status: 'ok',
        queues: stats.length,
        totalJobs: stats.reduce((sum, q) => sum + q.waiting + q.active + q.completed + q.failed, 0)
      }
    } catch (error) {
      this.status.jobs = 'error'
      details.jobs = { status: 'error', error: error instanceof Error ? error.message : 'Unknown' }
    }

    // Check time-series
    try {
      const tsStats = await timeSeriesManager.getStats()
      details.timeSeries = { status: 'ok', ...tsStats }
    } catch (error) {
      this.status.timeSeries = 'error'
      details.timeSeries = { status: 'error', error: error instanceof Error ? error.message : 'Unknown' }
    }

    this.updateOverallStatus()

    return {
      status: this.getStatus(),
      timestamp: new Date().toISOString(),
      details
    }
  }

  async shutdown(): Promise<void> {
    logger.info('Shutting down data pipeline...')

    try {
      // Shutdown in reverse order
      if (this.components.has('campaignSyncScheduler')) {
        await campaignSyncScheduler.shutdown()
      }

      if (this.components.has('jobQueueManager')) {
        await jobQueueManager.shutdown()
      }

      if (this.components.has('dataSyncService')) {
        await dataSyncService.shutdown()
      }

      if (this.components.has('webSocketManager')) {
        await webSocketManager.shutdown()
      }

      if (this.components.has('redis')) {
        await redisManager.shutdown()
      }

      this.isInitialized = false
      this.components.clear()

      this.status = {
        redis: 'disconnected',
        caches: 'error',
        websockets: 'stopped',
        jobs: 'stopped',
        timeSeries: 'error',
        dataSync: 'stopped',
        overall: 'critical'
      }

      logger.info('Data pipeline shut down successfully')

    } catch (error) {
      logger.error('Error during pipeline shutdown', error)
      throw error
    }
  }

  // Utility methods for monitoring
  async getCacheStats(): Promise<Record<string, any>> {
    const stats: Record<string, any> = {}

    try {
      stats.metaApiCache = await metaApiCache.getStats()
    } catch (error) {
      stats.metaApiCache = { error: error instanceof Error ? error.message : 'Unknown' }
    }

    try {
      stats.campaignInsightsCache = await campaignInsightsCache.getStats()
    } catch (error) {
      stats.campaignInsightsCache = { error: error instanceof Error ? error.message : 'Unknown' }
    }

    return stats
  }

  async getJobStats(): Promise<any[]> {
    try {
      return await jobQueueManager.getQueueStats()
    } catch (error) {
      logger.error('Failed to get job stats', error)
      return []
    }
  }

  async getWebSocketStats(): Promise<Record<string, any>> {
    try {
      return webSocketManager.getStats()
    } catch (error) {
      logger.error('Failed to get WebSocket stats', error)
      return { error: error instanceof Error ? error.message : 'Unknown' }
    }
  }
}

// Create singleton instance
export const dataPipelineManager = new DataPipelineManager()

// Helper function to ensure pipeline is initialized
export async function ensurePipelineInitialized(): Promise<void> {
  const status = dataPipelineManager.getStatus()
  if (status.overall === 'critical') {
    await dataPipelineManager.initialize()
  }
}

// Express middleware to check pipeline health
export function pipelineHealthMiddleware() {
  return async (req: any, res: any, next: any) => {
    const status = dataPipelineManager.getStatus()

    if (status.overall === 'critical') {
      return res.status(503).json({
        error: 'Data pipeline unavailable',
        status: status.overall,
        message: 'Pipeline is in critical state. Please check system status.'
      })
    }

    // Add pipeline status to request context
    req.pipelineStatus = status
    next()
  }
}