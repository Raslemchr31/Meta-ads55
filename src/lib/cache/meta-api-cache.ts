import { redisManager, RedisDatabase } from '@/lib/redis-manager'
import { logger } from '@/lib/logger'
import { z } from 'zod'

export type CacheStrategy = 'standard' | 'aggressive' | 'conservative' | 'real-time'

export interface CacheConfig {
  strategy: CacheStrategy
  ttl: number
  maxSize?: number
  compressionEnabled?: boolean
  autoRefresh?: boolean
  refreshInterval?: number
}

export interface MetaApiCacheOptions {
  cacheKey: string
  ttl?: number
  strategy?: CacheStrategy
  tags?: string[]
  dependencies?: string[]
  priority?: number
}

export interface CachedData<T = any> {
  data: T
  metadata: {
    cachedAt: string
    expiresAt: string
    strategy: CacheStrategy
    tags: string[]
    dependencies: string[]
    hitCount: number
    lastAccessed: string
    priority: number
    size: number
    compressed: boolean
  }
}

export interface CacheStats {
  hitRate: number
  missRate: number
  totalHits: number
  totalMisses: number
  totalKeys: number
  memoryUsage: number
  averageResponseTime: number
  quotaUtilization: number
}

const cacheConfigSchema = z.object({
  strategy: z.enum(['standard', 'aggressive', 'conservative', 'real-time']),
  ttl: z.number().positive(),
  maxSize: z.number().positive().optional(),
  compressionEnabled: z.boolean().optional().default(false),
  autoRefresh: z.boolean().optional().default(false),
  refreshInterval: z.number().positive().optional()
})

export class MetaApiCache {
  private readonly DEFAULT_CONFIGS: Record<CacheStrategy, CacheConfig> = {
    standard: {
      strategy: 'standard',
      ttl: 3600, // 1 hour
      compressionEnabled: true,
      autoRefresh: false
    },
    aggressive: {
      strategy: 'aggressive',
      ttl: 7200, // 2 hours
      compressionEnabled: true,
      autoRefresh: true,
      refreshInterval: 1800 // 30 minutes
    },
    conservative: {
      strategy: 'conservative',
      ttl: 900, // 15 minutes
      compressionEnabled: false,
      autoRefresh: false
    },
    'real-time': {
      strategy: 'real-time',
      ttl: 60, // 1 minute
      compressionEnabled: false,
      autoRefresh: true,
      refreshInterval: 30 // 30 seconds
    }
  }

  private quotaTracker: Map<string, { count: number; resetTime: number }> = new Map()

  async get<T>(key: string, options?: Partial<MetaApiCacheOptions>): Promise<CachedData<T> | null> {
    try {
      const client = redisManager.getConnection(RedisDatabase.CACHE)
      const fullKey = this.buildCacheKey(key, options)

      // Check if key exists
      const exists = await client.exists(fullKey)
      if (!exists) {
        await this.recordCacheMiss(key)
        return null
      }

      // Get cached data
      const cachedDataStr = await client.get(fullKey)
      if (!cachedDataStr) {
        await this.recordCacheMiss(key)
        return null
      }

      // Parse cached data
      const cachedData: CachedData<T> = JSON.parse(cachedDataStr)

      // Decompress if needed
      if (cachedData.metadata.compressed) {
        cachedData.data = await this.decompress(cachedData.data)
      }

      // Update access metadata
      cachedData.metadata.hitCount++
      cachedData.metadata.lastAccessed = new Date().toISOString()

      // Save updated metadata
      await client.set(fullKey, JSON.stringify(cachedData), {
        EX: Math.ceil((new Date(cachedData.metadata.expiresAt).getTime() - Date.now()) / 1000)
      })

      // Record cache hit
      await this.recordCacheHit(key)

      logger.debug('Cache hit', {
        key: fullKey,
        strategy: cachedData.metadata.strategy,
        hitCount: cachedData.metadata.hitCount
      })

      return cachedData

    } catch (error) {
      logger.error('Cache get error', {
        key,
        error: error instanceof Error ? error.message : 'Unknown error'
      })
      await this.recordCacheMiss(key)
      return null
    }
  }

  async set<T>(
    key: string,
    data: T,
    options?: MetaApiCacheOptions
  ): Promise<boolean> {
    try {
      const client = redisManager.getConnection(RedisDatabase.CACHE)
      const config = this.getConfigForStrategy(options?.strategy || 'standard')
      const fullKey = this.buildCacheKey(key, options)

      // Calculate TTL
      const ttl = options?.ttl || config.ttl
      const expiresAt = new Date(Date.now() + ttl * 1000).toISOString()

      // Prepare cached data
      let processedData = data
      let compressed = false

      // Compress data if enabled and data is large enough
      if (config.compressionEnabled && this.shouldCompress(data)) {
        processedData = await this.compress(data)
        compressed = true
      }

      const cachedData: CachedData<T> = {
        data: processedData,
        metadata: {
          cachedAt: new Date().toISOString(),
          expiresAt,
          strategy: config.strategy,
          tags: options?.tags || [],
          dependencies: options?.dependencies || [],
          hitCount: 0,
          lastAccessed: new Date().toISOString(),
          priority: options?.priority || 5,
          size: this.calculateSize(data),
          compressed
        }
      }

      // Store in cache
      await client.set(fullKey, JSON.stringify(cachedData), { EX: ttl })

      // Add to tag indices
      if (options?.tags) {
        for (const tag of options.tags) {
          await client.sadd(`cache:tag:${tag}`, fullKey)
          await client.expire(`cache:tag:${tag}`, ttl)
        }
      }

      // Add to dependency tracking
      if (options?.dependencies) {
        for (const dep of options.dependencies) {
          await client.sadd(`cache:dep:${dep}`, fullKey)
          await client.expire(`cache:dep:${dep}`, ttl)
        }
      }

      // Schedule auto-refresh if enabled
      if (config.autoRefresh && config.refreshInterval) {
        await this.scheduleRefresh(fullKey, config.refreshInterval)
      }

      logger.debug('Cache set', {
        key: fullKey,
        strategy: config.strategy,
        ttl,
        compressed,
        size: cachedData.metadata.size
      })

      return true

    } catch (error) {
      logger.error('Cache set error', {
        key,
        error: error instanceof Error ? error.message : 'Unknown error'
      })
      return false
    }
  }

  async invalidate(pattern: string): Promise<number> {
    try {
      const client = redisManager.getConnection(RedisDatabase.CACHE)
      const keys = await client.keys(pattern)

      if (keys.length === 0) {
        return 0
      }

      const deletedCount = await client.del(...keys)

      logger.info('Cache invalidated', {
        pattern,
        keysDeleted: deletedCount
      })

      return deletedCount

    } catch (error) {
      logger.error('Cache invalidation error', {
        pattern,
        error: error instanceof Error ? error.message : 'Unknown error'
      })
      return 0
    }
  }

  async invalidateByTag(tag: string): Promise<number> {
    try {
      const client = redisManager.getConnection(RedisDatabase.CACHE)
      const tagKey = `cache:tag:${tag}`

      // Get all keys with this tag
      const keys = await client.smembers(tagKey)

      if (keys.length === 0) {
        return 0
      }

      // Delete all keys
      const deletedCount = await client.del(...keys)

      // Clean up tag index
      await client.del(tagKey)

      logger.info('Cache invalidated by tag', {
        tag,
        keysDeleted: deletedCount
      })

      return deletedCount

    } catch (error) {
      logger.error('Cache tag invalidation error', {
        tag,
        error: error instanceof Error ? error.message : 'Unknown error'
      })
      return 0
    }
  }

  async invalidateByDependency(dependency: string): Promise<number> {
    try {
      const client = redisManager.getConnection(RedisDatabase.CACHE)
      const depKey = `cache:dep:${dependency}`

      // Get all keys dependent on this
      const keys = await client.smembers(depKey)

      if (keys.length === 0) {
        return 0
      }

      // Delete all dependent keys
      const deletedCount = await client.del(...keys)

      // Clean up dependency index
      await client.del(depKey)

      logger.info('Cache invalidated by dependency', {
        dependency,
        keysDeleted: deletedCount
      })

      return deletedCount

    } catch (error) {
      logger.error('Cache dependency invalidation error', {
        dependency,
        error: error instanceof Error ? error.message : 'Unknown error'
      })
      return 0
    }
  }

  async getStats(): Promise<CacheStats> {
    try {
      const client = redisManager.getConnection(RedisDatabase.CACHE)

      // Get cache statistics
      const statsData = await client.hmget(
        'cache:stats',
        'totalHits',
        'totalMisses',
        'totalResponseTime'
      )

      const totalHits = parseInt(statsData[0] || '0', 10)
      const totalMisses = parseInt(statsData[1] || '0', 10)
      const totalResponseTime = parseFloat(statsData[2] || '0')

      const totalRequests = totalHits + totalMisses
      const hitRate = totalRequests > 0 ? (totalHits / totalRequests) * 100 : 0
      const missRate = totalRequests > 0 ? (totalMisses / totalRequests) * 100 : 0

      // Get total keys
      const allKeys = await client.keys('cache:data:*')
      const totalKeys = allKeys.length

      // Get memory usage
      const memoryInfo = await client.memory('usage', 'cache:*')
      const memoryUsage = Array.isArray(memoryInfo) ? memoryInfo.reduce((sum, usage) => sum + (usage || 0), 0) : 0

      // Get quota utilization
      const quotaUtilization = this.calculateQuotaUtilization()

      return {
        hitRate: Math.round(hitRate * 100) / 100,
        missRate: Math.round(missRate * 100) / 100,
        totalHits,
        totalMisses,
        totalKeys,
        memoryUsage,
        averageResponseTime: totalRequests > 0 ? Math.round((totalResponseTime / totalRequests) * 100) / 100 : 0,
        quotaUtilization: Math.round(quotaUtilization * 100) / 100
      }

    } catch (error) {
      logger.error('Failed to get cache stats', {
        error: error instanceof Error ? error.message : 'Unknown error'
      })

      return {
        hitRate: 0,
        missRate: 0,
        totalHits: 0,
        totalMisses: 0,
        totalKeys: 0,
        memoryUsage: 0,
        averageResponseTime: 0,
        quotaUtilization: 0
      }
    }
  }

  async trackApiQuota(endpoint: string, quotaUsed: number = 1): Promise<{ remaining: number; resetTime: number }> {
    try {
      const client = redisManager.getConnection(RedisDatabase.CACHE)
      const quotaKey = `quota:${endpoint}`
      const now = Date.now()
      const hourStart = Math.floor(now / (60 * 60 * 1000)) * (60 * 60 * 1000)
      const resetTime = hourStart + (60 * 60 * 1000) // Next hour

      // Get current quota usage
      const currentUsage = await client.incr(`${quotaKey}:${hourStart}`)
      await client.expire(`${quotaKey}:${hourStart}`, 3600) // Expire after 1 hour

      // Update tracker
      this.quotaTracker.set(endpoint, {
        count: currentUsage,
        resetTime
      })

      // Default Meta API limits (can be configured per endpoint)
      const defaultLimit = 200 // requests per hour
      const remaining = Math.max(0, defaultLimit - currentUsage)

      logger.debug('API quota tracked', {
        endpoint,
        currentUsage,
        remaining,
        resetTime: new Date(resetTime).toISOString()
      })

      return { remaining, resetTime }

    } catch (error) {
      logger.error('API quota tracking error', {
        endpoint,
        error: error instanceof Error ? error.message : 'Unknown error'
      })
      return { remaining: 100, resetTime: Date.now() + 3600000 } // Fallback
    }
  }

  async shouldThrottle(endpoint: string): Promise<{ shouldThrottle: boolean; waitTime: number }> {
    const tracker = this.quotaTracker.get(endpoint)

    if (!tracker) {
      return { shouldThrottle: false, waitTime: 0 }
    }

    // Basic throttling logic - can be enhanced
    const defaultLimit = 200
    const usagePercent = (tracker.count / defaultLimit) * 100

    if (usagePercent >= 90) {
      // Throttle aggressively when near limit
      const waitTime = Math.min(300000, (usagePercent - 90) * 10000) // Max 5 minutes
      return { shouldThrottle: true, waitTime }
    }

    if (usagePercent >= 75) {
      // Light throttling when approaching limit
      const waitTime = (usagePercent - 75) * 1000 // Up to 15 seconds
      return { shouldThrottle: true, waitTime }
    }

    return { shouldThrottle: false, waitTime: 0 }
  }

  private buildCacheKey(key: string, options?: Partial<MetaApiCacheOptions>): string {
    const strategy = options?.strategy || 'standard'
    return `cache:data:${strategy}:${key}`
  }

  private getConfigForStrategy(strategy: CacheStrategy): CacheConfig {
    return this.DEFAULT_CONFIGS[strategy]
  }

  private shouldCompress(data: any): boolean {
    const size = this.calculateSize(data)
    return size > 10240 // Compress if larger than 10KB
  }

  private calculateSize(data: any): number {
    return new Blob([JSON.stringify(data)]).size
  }

  private async compress(data: any): Promise<string> {
    // Simple compression simulation - in production, use proper compression
    const jsonStr = JSON.stringify(data)
    return Buffer.from(jsonStr).toString('base64')
  }

  private async decompress(compressedData: string): Promise<any> {
    // Simple decompression simulation
    const jsonStr = Buffer.from(compressedData, 'base64').toString()
    return JSON.parse(jsonStr)
  }

  private async recordCacheHit(key: string): Promise<void> {
    try {
      const client = redisManager.getConnection(RedisDatabase.CACHE)
      await client.hincrby('cache:stats', 'totalHits', 1)
    } catch (error) {
      // Silently fail for stats recording
    }
  }

  private async recordCacheMiss(key: string): Promise<void> {
    try {
      const client = redisManager.getConnection(RedisDatabase.CACHE)
      await client.hincrby('cache:stats', 'totalMisses', 1)
    } catch (error) {
      // Silently fail for stats recording
    }
  }

  private async scheduleRefresh(key: string, interval: number): Promise<void> {
    try {
      const client = redisManager.getConnection(RedisDatabase.JOBS)

      // Add to refresh queue (this would integrate with the job queue system)
      await client.zadd(
        'cache:refresh:schedule',
        Date.now() + interval * 1000,
        key
      )
    } catch (error) {
      logger.error('Failed to schedule cache refresh', {
        key,
        error: error instanceof Error ? error.message : 'Unknown error'
      })
    }
  }

  private calculateQuotaUtilization(): number {
    if (this.quotaTracker.size === 0) return 0

    let totalUtilization = 0
    let count = 0

    for (const [endpoint, tracker] of this.quotaTracker) {
      const defaultLimit = 200
      const utilization = (tracker.count / defaultLimit) * 100
      totalUtilization += Math.min(100, utilization)
      count++
    }

    return count > 0 ? totalUtilization / count : 0
  }
}

export const metaApiCache = new MetaApiCache()