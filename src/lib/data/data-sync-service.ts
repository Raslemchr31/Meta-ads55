import { redisManager, RedisDatabase } from '@/lib/redis-manager'
import { timeSeriesManager, PerformanceMetrics, EventData } from './time-series-manager'
import { campaignInsightsCache } from '@/lib/cache/campaign-insights-cache'
import { logger } from '@/lib/logger'
import { webSocketManager } from '@/lib/realtime/websocket-manager'

export interface SyncConfig {
  batchSize: number
  syncInterval: number // seconds
  enableRealTimeSync: boolean
  enableCompression: boolean
  retryAttempts: number
  retryDelay: number // seconds
}

export interface SyncStats {
  lastSyncTime: string
  totalRecordsSynced: number
  successfulSyncs: number
  failedSyncs: number
  averageSyncDuration: number
  pendingOperations: number
  cacheHitRate: number
  compressionRatio: number
}

export interface DataEntity {
  id: string
  type: 'campaign' | 'adset' | 'ad' | 'account' | 'user'
  data: Record<string, any>
  timestamp: number
  version: number
  checksum?: string
}

export interface SyncOperation {
  id: string
  operation: 'create' | 'update' | 'delete'
  entity: DataEntity
  timestamp: number
  status: 'pending' | 'processing' | 'completed' | 'failed'
  retryCount: number
  error?: string
}

export interface ConflictResolution {
  strategy: 'mysql_wins' | 'redis_wins' | 'latest_timestamp' | 'merge' | 'manual'
  mergeFields?: string[]
  conflictHandlers?: Record<string, (mysqlValue: any, redisValue: any) => any>
}

export class DataSyncService {
  private readonly DEFAULT_CONFIG: SyncConfig = {
    batchSize: 100,
    syncInterval: 300, // 5 minutes
    enableRealTimeSync: true,
    enableCompression: true,
    retryAttempts: 3,
    retryDelay: 60 // 1 minute
  }

  private config: SyncConfig
  private syncInterval: NodeJS.Timeout | null = null
  private pendingOperations: Map<string, SyncOperation> = new Map()
  private isRunning = false

  constructor(config?: Partial<SyncConfig>) {
    this.config = { ...this.DEFAULT_CONFIG, ...config }
  }

  async initialize(): Promise<void> {
    try {
      // Load pending operations from Redis
      await this.loadPendingOperations()

      // Start sync scheduler if enabled
      if (this.config.syncInterval > 0) {
        await this.startScheduler()
      }

      logger.info('Data sync service initialized', {
        config: this.config,
        pendingOperations: this.pendingOperations.size
      })

    } catch (error) {
      logger.error('Failed to initialize data sync service', {
        error: error instanceof Error ? error.message : 'Unknown error'
      })
      throw error
    }
  }

  async syncCampaignToRedis(campaignData: any): Promise<boolean> {
    try {
      const entity: DataEntity = {
        id: campaignData.id,
        type: 'campaign',
        data: campaignData,
        timestamp: Date.now(),
        version: campaignData.version || 1
      }

      // Calculate checksum for integrity
      entity.checksum = this.calculateChecksum(entity.data)

      // Store in Redis cache
      const cacheSuccess = await this.storeCampaignInCache(entity)

      // Store performance metrics in time series
      if (campaignData.insights) {
        const metricsSuccess = await this.storePerformanceMetrics(entity)

        if (!metricsSuccess) {
          logger.warn('Failed to store performance metrics', { campaignId: entity.id })
        }
      }

      // Record sync operation
      await this.recordSyncOperation('update', entity, cacheSuccess)

      // Send real-time update if enabled
      if (this.config.enableRealTimeSync && cacheSuccess) {
        await this.sendRealTimeUpdate(entity, 'update')
      }

      return cacheSuccess

    } catch (error) {
      logger.error('Failed to sync campaign to Redis', {
        campaignId: campaignData.id,
        error: error instanceof Error ? error.message : 'Unknown error'
      })
      return false
    }
  }

  async syncCampaignFromRedis(campaignId: string): Promise<any | null> {
    try {
      // Get from cache first
      const cachedData = await campaignInsightsCache.getCampaignInsights(campaignId, 'current')

      if (cachedData) {
        logger.debug('Campaign data retrieved from Redis cache', { campaignId })
        return cachedData
      }

      // If not in cache, might need to sync from MySQL
      logger.debug('Campaign data not found in Redis cache', { campaignId })
      return null

    } catch (error) {
      logger.error('Failed to sync campaign from Redis', {
        campaignId,
        error: error instanceof Error ? error.message : 'Unknown error'
      })
      return null
    }
  }

  async handleDataConflict(
    mysqlData: DataEntity,
    redisData: DataEntity,
    resolution: ConflictResolution
  ): Promise<DataEntity> {
    try {
      logger.info('Handling data conflict', {
        entityId: mysqlData.id,
        entityType: mysqlData.type,
        strategy: resolution.strategy,
        mysqlVersion: mysqlData.version,
        redisVersion: redisData.version
      })

      switch (resolution.strategy) {
        case 'mysql_wins':
          return mysqlData

        case 'redis_wins':
          return redisData

        case 'latest_timestamp':
          return mysqlData.timestamp > redisData.timestamp ? mysqlData : redisData

        case 'merge':
          return this.mergeEntities(mysqlData, redisData, resolution.mergeFields)

        case 'manual':
          // Store conflict for manual resolution
          await this.storeConflictForManualResolution(mysqlData, redisData)
          return mysqlData // Default to MySQL for now

        default:
          logger.warn('Unknown conflict resolution strategy', { strategy: resolution.strategy })
          return mysqlData
      }

    } catch (error) {
      logger.error('Failed to handle data conflict', {
        entityId: mysqlData.id,
        error: error instanceof Error ? error.message : 'Unknown error'
      })
      return mysqlData // Default to MySQL on error
    }
  }

  async invalidateCache(entityType: string, entityId: string): Promise<void> {
    try {
      switch (entityType) {
        case 'campaign':
          await campaignInsightsCache.invalidateCampaignCache(entityId)
          break

        case 'account':
          await campaignInsightsCache.invalidateAccountCache(entityId)
          break

        default:
          // Generic cache invalidation
          const client = redisManager.getConnection(RedisDatabase.CACHE)
          await client.del(`cache:${entityType}:${entityId}`)
      }

      // Send invalidation event
      await this.sendCacheInvalidationEvent(entityType, entityId)

      logger.debug('Cache invalidated', { entityType, entityId })

    } catch (error) {
      logger.error('Failed to invalidate cache', {
        entityType,
        entityId,
        error: error instanceof Error ? error.message : 'Unknown error'
      })
    }
  }

  async batchSync(entities: DataEntity[]): Promise<{ successful: number; failed: number }> {
    try {
      const results = { successful: 0, failed: 0 }
      const batches = this.chunkArray(entities, this.config.batchSize)

      for (const batch of batches) {
        const batchPromises = batch.map(async (entity) => {
          try {
            switch (entity.type) {
              case 'campaign':
                const success = await this.syncCampaignToRedis(entity.data)
                return success ? 'success' : 'failed'

              default:
                return await this.syncGenericEntity(entity) ? 'success' : 'failed'
            }
          } catch (error) {
            logger.error('Batch sync entity failed', {
              entityId: entity.id,
              entityType: entity.type,
              error: error instanceof Error ? error.message : 'Unknown error'
            })
            return 'failed'
          }
        })

        const batchResults = await Promise.allSettled(batchPromises)

        batchResults.forEach(result => {
          if (result.status === 'fulfilled' && result.value === 'success') {
            results.successful++
          } else {
            results.failed++
          }
        })

        // Small delay between batches to prevent overwhelming the system
        if (batches.length > 1) {
          await new Promise(resolve => setTimeout(resolve, 100))
        }
      }

      logger.info('Batch sync completed', {
        totalEntities: entities.length,
        successful: results.successful,
        failed: results.failed
      })

      return results

    } catch (error) {
      logger.error('Failed to perform batch sync', {
        entityCount: entities.length,
        error: error instanceof Error ? error.message : 'Unknown error'
      })
      return { successful: 0, failed: entities.length }
    }
  }

  async getSyncStats(): Promise<SyncStats> {
    try {
      const client = redisManager.getConnection(RedisDatabase.ANALYTICS)

      // Get sync statistics from Redis
      const stats = await client.hmget(
        'sync:stats',
        'lastSyncTime',
        'totalRecordsSynced',
        'successfulSyncs',
        'failedSyncs',
        'totalSyncDuration'
      )

      const totalRecordsSynced = parseInt(stats[1] || '0')
      const successfulSyncs = parseInt(stats[2] || '0')
      const failedSyncs = parseInt(stats[3] || '0')
      const totalSyncDuration = parseFloat(stats[4] || '0')

      // Calculate cache hit rate
      const cacheStats = await campaignInsightsCache.getStats?.() || { hitRate: 0 }

      return {
        lastSyncTime: stats[0] || 'Never',
        totalRecordsSynced,
        successfulSyncs,
        failedSyncs,
        averageSyncDuration: successfulSyncs > 0 ? totalSyncDuration / successfulSyncs : 0,
        pendingOperations: this.pendingOperations.size,
        cacheHitRate: cacheStats.hitRate || 0,
        compressionRatio: this.config.enableCompression ? 0.7 : 1.0 // Estimated
      }

    } catch (error) {
      logger.error('Failed to get sync stats', {
        error: error instanceof Error ? error.message : 'Unknown error'
      })

      return {
        lastSyncTime: 'Error',
        totalRecordsSynced: 0,
        successfulSyncs: 0,
        failedSyncs: 0,
        averageSyncDuration: 0,
        pendingOperations: this.pendingOperations.size,
        cacheHitRate: 0,
        compressionRatio: 1.0
      }
    }
  }

  async processPendingOperations(): Promise<void> {
    if (this.pendingOperations.size === 0) {
      return
    }

    logger.info('Processing pending sync operations', {
      count: this.pendingOperations.size
    })

    for (const [operationId, operation] of this.pendingOperations) {
      try {
        if (operation.status === 'processing') {
          continue // Skip operations already being processed
        }

        operation.status = 'processing'

        const success = await this.executeOperation(operation)

        if (success) {
          operation.status = 'completed'
          this.pendingOperations.delete(operationId)
        } else {
          operation.status = 'failed'
          operation.retryCount++

          if (operation.retryCount >= this.config.retryAttempts) {
            logger.error('Operation failed after max retries', {
              operationId,
              operation: operation.operation,
              entityId: operation.entity.id
            })
            this.pendingOperations.delete(operationId)
          } else {
            // Schedule retry
            setTimeout(() => {
              operation.status = 'pending'
            }, this.config.retryDelay * 1000)
          }
        }

      } catch (error) {
        logger.error('Failed to process pending operation', {
          operationId,
          error: error instanceof Error ? error.message : 'Unknown error'
        })
        operation.status = 'failed'
        operation.error = error instanceof Error ? error.message : 'Unknown error'
      }
    }

    // Save updated pending operations
    await this.savePendingOperations()
  }

  private async startScheduler(): Promise<void> {
    if (this.isRunning) return

    this.isRunning = true

    this.syncInterval = setInterval(async () => {
      try {
        await this.processPendingOperations()
        await this.performScheduledSync()
      } catch (error) {
        logger.error('Scheduled sync error', {
          error: error instanceof Error ? error.message : 'Unknown error'
        })
      }
    }, this.config.syncInterval * 1000)

    logger.info('Data sync scheduler started', {
      interval: this.config.syncInterval
    })
  }

  private async performScheduledSync(): Promise<void> {
    // This would typically query MySQL for recent changes and sync them to Redis
    // Implementation depends on your specific MySQL schema and change tracking mechanism

    logger.debug('Performing scheduled sync check')

    // Example: Get recently modified campaigns
    // const recentCampaigns = await this.getRecentlyModifiedCampaigns()
    // await this.batchSync(recentCampaigns)
  }

  private async storeCampaignInCache(entity: DataEntity): Promise<boolean> {
    try {
      // Transform entity data to campaign insights format
      const insights = this.transformToCampaignInsights(entity.data)

      if (insights) {
        return await campaignInsightsCache.setCampaignInsights(
          entity.id,
          'current',
          insights
        )
      }

      return false

    } catch (error) {
      logger.error('Failed to store campaign in cache', {
        entityId: entity.id,
        error: error instanceof Error ? error.message : 'Unknown error'
      })
      return false
    }
  }

  private async storePerformanceMetrics(entity: DataEntity): Promise<boolean> {
    try {
      if (entity.type !== 'campaign' || !entity.data.insights) {
        return false
      }

      const metrics: PerformanceMetrics = {
        campaignId: entity.id,
        timestamp: entity.timestamp,
        metrics: entity.data.insights.metrics || {},
        breakdown: entity.data.insights.breakdown
      }

      return await timeSeriesManager.storePerformanceMetrics(metrics)

    } catch (error) {
      logger.error('Failed to store performance metrics', {
        entityId: entity.id,
        error: error instanceof Error ? error.message : 'Unknown error'
      })
      return false
    }
  }

  private async recordSyncOperation(
    operation: 'create' | 'update' | 'delete',
    entity: DataEntity,
    success: boolean
  ): Promise<void> {
    try {
      const syncOperation: SyncOperation = {
        id: `sync_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
        operation,
        entity,
        timestamp: Date.now(),
        status: success ? 'completed' : 'failed',
        retryCount: 0
      }

      if (!success) {
        this.pendingOperations.set(syncOperation.id, syncOperation)
      }

      // Record sync event
      const eventData: EventData = {
        eventType: 'data_sync',
        entityId: entity.id,
        entityType: entity.type,
        timestamp: Date.now(),
        data: {
          operation,
          success,
          version: entity.version,
          checksum: entity.checksum
        }
      }

      await timeSeriesManager.storeEvent(eventData)

      // Update sync statistics
      await this.updateSyncStats(success)

    } catch (error) {
      logger.error('Failed to record sync operation', {
        operation,
        entityId: entity.id,
        error: error instanceof Error ? error.message : 'Unknown error'
      })
    }
  }

  private async sendRealTimeUpdate(entity: DataEntity, operation: string): Promise<void> {
    try {
      await webSocketManager.sendRealTimeUpdate({
        type: 'campaign_update',
        entityId: entity.id,
        entityType: entity.type,
        data: {
          operation,
          entity: entity.data,
          timestamp: entity.timestamp,
          version: entity.version
        },
        timestamp: new Date().toISOString()
      })

    } catch (error) {
      logger.error('Failed to send real-time update', {
        entityId: entity.id,
        error: error instanceof Error ? error.message : 'Unknown error'
      })
    }
  }

  private mergeEntities(
    entity1: DataEntity,
    entity2: DataEntity,
    mergeFields?: string[]
  ): DataEntity {
    const merged: DataEntity = {
      ...entity1,
      timestamp: Math.max(entity1.timestamp, entity2.timestamp),
      version: Math.max(entity1.version, entity2.version)
    }

    if (mergeFields) {
      // Merge only specified fields
      for (const field of mergeFields) {
        if (entity2.data[field] !== undefined) {
          merged.data[field] = entity2.data[field]
        }
      }
    } else {
      // Merge all fields, with entity2 taking precedence
      merged.data = { ...entity1.data, ...entity2.data }
    }

    merged.checksum = this.calculateChecksum(merged.data)
    return merged
  }

  private async storeConflictForManualResolution(
    entity1: DataEntity,
    entity2: DataEntity
  ): Promise<void> {
    try {
      const client = redisManager.getConnection(RedisDatabase.CACHE)

      const conflict = {
        id: `conflict_${Date.now()}_${entity1.id}`,
        entityId: entity1.id,
        entityType: entity1.type,
        entity1,
        entity2,
        createdAt: new Date().toISOString(),
        status: 'pending'
      }

      await client.lpush('data:conflicts', JSON.stringify(conflict))
      await client.expire('data:conflicts', 30 * 24 * 60 * 60) // 30 days

      logger.info('Data conflict stored for manual resolution', {
        conflictId: conflict.id,
        entityId: entity1.id
      })

    } catch (error) {
      logger.error('Failed to store conflict for manual resolution', {
        entityId: entity1.id,
        error: error instanceof Error ? error.message : 'Unknown error'
      })
    }
  }

  private async sendCacheInvalidationEvent(entityType: string, entityId: string): Promise<void> {
    try {
      const client = redisManager.getConnection(RedisDatabase.REALTIME)

      await client.publish('cache:invalidation', JSON.stringify({
        entityType,
        entityId,
        timestamp: Date.now()
      }))

    } catch (error) {
      logger.error('Failed to send cache invalidation event', {
        entityType,
        entityId,
        error: error instanceof Error ? error.message : 'Unknown error'
      })
    }
  }

  private async syncGenericEntity(entity: DataEntity): Promise<boolean> {
    try {
      const client = redisManager.getConnection(RedisDatabase.CACHE)

      const key = `entity:${entity.type}:${entity.id}`
      const data = this.config.enableCompression
        ? this.compressData(entity)
        : JSON.stringify(entity)

      await client.set(key, data, 'EX', 86400) // 24 hours default TTL

      return true

    } catch (error) {
      logger.error('Failed to sync generic entity', {
        entityId: entity.id,
        entityType: entity.type,
        error: error instanceof Error ? error.message : 'Unknown error'
      })
      return false
    }
  }

  private async executeOperation(operation: SyncOperation): Promise<boolean> {
    try {
      switch (operation.operation) {
        case 'create':
        case 'update':
          return await this.syncGenericEntity(operation.entity)

        case 'delete':
          return await this.deleteEntity(operation.entity)

        default:
          return false
      }

    } catch (error) {
      logger.error('Failed to execute operation', {
        operationId: operation.id,
        error: error instanceof Error ? error.message : 'Unknown error'
      })
      return false
    }
  }

  private async deleteEntity(entity: DataEntity): Promise<boolean> {
    try {
      await this.invalidateCache(entity.type, entity.id)

      // Delete from time series if applicable
      if (entity.type === 'campaign') {
        await timeSeriesManager.deleteTimeSeries(`campaign:${entity.id}`)
      }

      return true

    } catch (error) {
      logger.error('Failed to delete entity', {
        entityId: entity.id,
        entityType: entity.type,
        error: error instanceof Error ? error.message : 'Unknown error'
      })
      return false
    }
  }

  private transformToCampaignInsights(campaignData: any): any {
    // Transform MySQL campaign data to the format expected by campaign insights cache
    // This is a simplified transformation - adjust based on your data structure

    if (!campaignData.insights) {
      return null
    }

    return {
      campaignId: campaignData.id,
      adAccountId: campaignData.account_id,
      metrics: campaignData.insights.metrics,
      breakdown: campaignData.insights.breakdown,
      dateRange: campaignData.insights.date_range,
      lastUpdated: new Date().toISOString()
    }
  }

  private calculateChecksum(data: any): string {
    // Simple checksum calculation - use a proper hash function in production
    const str = JSON.stringify(data)
    let hash = 0
    for (let i = 0; i < str.length; i++) {
      const char = str.charCodeAt(i)
      hash = ((hash << 5) - hash) + char
      hash = hash & hash // Convert to 32-bit integer
    }
    return Math.abs(hash).toString(36)
  }

  private compressData(data: any): string {
    // Simple compression simulation - use proper compression in production
    const jsonStr = JSON.stringify(data)
    return Buffer.from(jsonStr).toString('base64')
  }

  private chunkArray<T>(array: T[], size: number): T[][] {
    const chunks = []
    for (let i = 0; i < array.length; i += size) {
      chunks.push(array.slice(i, i + size))
    }
    return chunks
  }

  private async loadPendingOperations(): Promise<void> {
    try {
      const client = redisManager.getConnection(RedisDatabase.JOBS)
      const operations = await client.lrange('sync:pending_operations', 0, -1)

      for (const operationData of operations) {
        try {
          const operation: SyncOperation = JSON.parse(operationData)
          this.pendingOperations.set(operation.id, operation)
        } catch (parseError) {
          logger.warn('Failed to parse pending operation', { operationData })
        }
      }

      logger.info('Loaded pending operations', { count: this.pendingOperations.size })

    } catch (error) {
      logger.error('Failed to load pending operations', {
        error: error instanceof Error ? error.message : 'Unknown error'
      })
    }
  }

  private async savePendingOperations(): Promise<void> {
    try {
      const client = redisManager.getConnection(RedisDatabase.JOBS)

      // Clear existing operations
      await client.del('sync:pending_operations')

      // Save current operations
      if (this.pendingOperations.size > 0) {
        const operations = Array.from(this.pendingOperations.values()).map(op => JSON.stringify(op))
        await client.lpush('sync:pending_operations', ...operations)
        await client.expire('sync:pending_operations', 7 * 24 * 60 * 60) // 7 days
      }

    } catch (error) {
      logger.error('Failed to save pending operations', {
        error: error instanceof Error ? error.message : 'Unknown error'
      })
    }
  }

  private async updateSyncStats(success: boolean): Promise<void> {
    try {
      const client = redisManager.getConnection(RedisDatabase.ANALYTICS)

      await client.hmset('sync:stats', {
        lastSyncTime: new Date().toISOString(),
        ...(success ? { successfulSyncs: 1 } : { failedSyncs: 1 })
      })

      await client.hincrby('sync:stats', 'totalRecordsSynced', 1)

    } catch (error) {
      // Silent fail for stats
    }
  }

  async shutdown(): Promise<void> {
    this.isRunning = false

    if (this.syncInterval) {
      clearInterval(this.syncInterval)
      this.syncInterval = null
    }

    // Save any pending operations
    await this.savePendingOperations()

    logger.info('Data sync service shut down')
  }
}

export const dataSyncService = new DataSyncService()