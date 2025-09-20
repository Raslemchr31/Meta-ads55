import Redis, { RedisOptions, Cluster, ClusterOptions } from 'ioredis'
import { logger } from './logger'

interface RedisManagerConfig {
  sentinels: Array<{ host: string; port: number }>
  masterName: string
  password: string
  username?: string
  keyPrefix?: string
  retryDelayOnFailover: number
  maxRetriesPerRequest: number
  lazyConnect: boolean
  tls?: {
    cert: string
    key: string
    ca: string
  }
}

interface DatabaseConfig {
  db: number
  name: string
  description: string
  defaultTTL: number
  keyPattern: string
}

export enum RedisDatabase {
  SESSIONS = 0,      // Session storage (authentication, JWT tokens)
  USER_PREFS = 1,    // User preferences and settings
  CACHE = 2,         // Real-time cache (API responses, Meta Graph data)
  RATE_LIMITING = 3, // Rate limiting and security tracking
  JOB_QUEUE = 4,     // Background job queues
  ANALYTICS = 5      // Analytics and temporary data
}

const DATABASE_CONFIGS: Record<RedisDatabase, DatabaseConfig> = {
  [RedisDatabase.SESSIONS]: {
    db: 0,
    name: 'sessions',
    description: 'Session storage and authentication',
    defaultTTL: 30 * 24 * 60 * 60, // 30 days
    keyPattern: 'session:*'
  },
  [RedisDatabase.USER_PREFS]: {
    db: 1,
    name: 'user_preferences',
    description: 'User preferences and settings',
    defaultTTL: 365 * 24 * 60 * 60, // 1 year
    keyPattern: 'user:*'
  },
  [RedisDatabase.CACHE]: {
    db: 2,
    name: 'api_cache',
    description: 'API responses and Meta Graph data cache',
    defaultTTL: 60 * 60, // 1 hour
    keyPattern: 'cache:*'
  },
  [RedisDatabase.RATE_LIMITING]: {
    db: 3,
    name: 'rate_limiting',
    description: 'Rate limiting and security tracking',
    defaultTTL: 60 * 60, // 1 hour
    keyPattern: 'rate:*'
  },
  [RedisDatabase.JOB_QUEUE]: {
    db: 4,
    name: 'job_queue',
    description: 'Background job queues and task management',
    defaultTTL: 7 * 24 * 60 * 60, // 7 days
    keyPattern: 'job:*'
  },
  [RedisDatabase.ANALYTICS]: {
    db: 5,
    name: 'analytics',
    description: 'Analytics and temporary data',
    defaultTTL: 24 * 60 * 60, // 24 hours
    keyPattern: 'analytics:*'
  }
}

export class RedisManager {
  private connections: Map<RedisDatabase, Redis> = new Map()
  private config: RedisManagerConfig
  private isInitialized = false
  private healthCheckInterval?: NodeJS.Timeout

  constructor() {
    this.config = {
      sentinels: [
        { host: process.env.REDIS_SENTINEL_1_HOST || 'redis-sentinel-1', port: parseInt(process.env.REDIS_SENTINEL_1_PORT || '26379') },
        { host: process.env.REDIS_SENTINEL_2_HOST || 'redis-sentinel-2', port: parseInt(process.env.REDIS_SENTINEL_2_PORT || '26380') },
        { host: process.env.REDIS_SENTINEL_3_HOST || 'redis-sentinel-3', port: parseInt(process.env.REDIS_SENTINEL_3_PORT || '26381') }
      ],
      masterName: process.env.REDIS_MASTER_NAME || 'meta-ads-master',
      password: process.env.REDIS_PASSWORD || 'MetaAds2024!SecureRedis#Production$',
      username: process.env.REDIS_USERNAME || 'meta-ads-app',
      keyPrefix: process.env.REDIS_KEY_PREFIX || 'meta-ads:',
      retryDelayOnFailover: 100,
      maxRetriesPerRequest: 3,
      lazyConnect: true,
      tls: process.env.REDIS_TLS_ENABLED === 'true' ? {
        cert: process.env.REDIS_TLS_CERT || '/etc/redis/tls/redis.crt',
        key: process.env.REDIS_TLS_KEY || '/etc/redis/tls/redis.key',
        ca: process.env.REDIS_TLS_CA || '/etc/redis/tls/ca.crt'
      } : undefined
    }
  }

  async initialize(): Promise<void> {
    if (this.isInitialized) {
      logger.warn('Redis manager already initialized')
      return
    }

    try {
      // Initialize connections for each database
      for (const [database, dbConfig] of Object.entries(DATABASE_CONFIGS)) {
        const db = parseInt(database) as RedisDatabase
        await this.createConnection(db, dbConfig)
      }

      // Start health check monitoring
      this.startHealthChecking()

      this.isInitialized = true
      logger.info('Redis manager initialized successfully', {
        databases: Object.keys(DATABASE_CONFIGS).length,
        sentinels: this.config.sentinels.length
      })
    } catch (error) {
      logger.error('Failed to initialize Redis manager', error)
      throw error
    }
  }

  private async createConnection(database: RedisDatabase, dbConfig: DatabaseConfig): Promise<void> {
    const connectionOptions: RedisOptions = {
      sentinels: this.config.sentinels,
      name: this.config.masterName,
      password: this.config.password,
      username: this.config.username,
      db: dbConfig.db,
      keyPrefix: this.config.keyPrefix,
      retryDelayOnFailover: this.config.retryDelayOnFailover,
      maxRetriesPerRequest: this.config.maxRetriesPerRequest,
      lazyConnect: this.config.lazyConnect,
      connectTimeout: 10000,
      commandTimeout: 5000,
      // Connection pool settings
      family: 4,
      keepAlive: true,
      // Reconnection settings
      reconnectOnError: (err) => {
        const targetError = 'READONLY'
        return err.message.includes(targetError)
      },
      retryDelayOnReconnect: (times) => Math.min(times * 50, 2000),
      maxRetriesPerRequest: 3,
      // TLS configuration
      tls: this.config.tls,
      // Sentinel specific options
      sentinelRetryDelayOnFailover: 200,
      enableReadyCheck: true,
      maxRetriesPerRequest: 3
    }

    const connection = new Redis(connectionOptions)

    // Connection event handlers
    connection.on('connect', () => {
      logger.info(`Redis connected to database ${database} (${dbConfig.name})`)
    })

    connection.on('ready', () => {
      logger.info(`Redis ready for database ${database} (${dbConfig.name})`)
    })

    connection.on('error', (error) => {
      logger.error(`Redis error for database ${database} (${dbConfig.name})`, error)
    })

    connection.on('close', () => {
      logger.warn(`Redis connection closed for database ${database} (${dbConfig.name})`)
    })

    connection.on('reconnecting', () => {
      logger.info(`Redis reconnecting for database ${database} (${dbConfig.name})`)
    })

    connection.on('end', () => {
      logger.warn(`Redis connection ended for database ${database} (${dbConfig.name})`)
    })

    // Test the connection
    try {
      await connection.ping()
      logger.info(`Redis ping successful for database ${database} (${dbConfig.name})`)
    } catch (error) {
      logger.error(`Redis ping failed for database ${database} (${dbConfig.name})`, error)
      throw error
    }

    this.connections.set(database, connection)
  }

  getConnection(database: RedisDatabase): Redis {
    if (!this.isInitialized) {
      throw new Error('Redis manager not initialized. Call initialize() first.')
    }

    const connection = this.connections.get(database)
    if (!connection) {
      throw new Error(`No Redis connection found for database ${database}`)
    }

    return connection
  }

  // Convenience methods for each database type
  getSessionStore(): Redis {
    return this.getConnection(RedisDatabase.SESSIONS)
  }

  getUserPrefsStore(): Redis {
    return this.getConnection(RedisDatabase.USER_PREFS)
  }

  getCacheStore(): Redis {
    return this.getConnection(RedisDatabase.CACHE)
  }

  getRateLimitStore(): Redis {
    return this.getConnection(RedisDatabase.RATE_LIMITING)
  }

  getJobQueueStore(): Redis {
    return this.getConnection(RedisDatabase.JOB_QUEUE)
  }

  getAnalyticsStore(): Redis {
    return this.getConnection(RedisDatabase.ANALYTICS)
  }

  // Enhanced cache operations with TTL defaults
  async setWithTTL(database: RedisDatabase, key: string, value: string | object, ttl?: number): Promise<void> {
    const connection = this.getConnection(database)
    const dbConfig = DATABASE_CONFIGS[database]
    const finalTTL = ttl || dbConfig.defaultTTL

    const serializedValue = typeof value === 'object' ? JSON.stringify(value) : value

    await connection.setex(key, finalTTL, serializedValue)

    logger.debug(`Set key in Redis database ${database}`, {
      key,
      ttl: finalTTL,
      database: dbConfig.name
    })
  }

  async getWithParsing<T = any>(database: RedisDatabase, key: string): Promise<T | null> {
    const connection = this.getConnection(database)
    const value = await connection.get(key)

    if (value === null) {
      return null
    }

    try {
      return JSON.parse(value) as T
    } catch {
      return value as T
    }
  }

  async deleteKey(database: RedisDatabase, key: string): Promise<number> {
    const connection = this.getConnection(database)
    return await connection.del(key)
  }

  async deletePattern(database: RedisDatabase, pattern: string): Promise<number> {
    const connection = this.getConnection(database)
    const keys = await connection.keys(pattern)

    if (keys.length === 0) {
      return 0
    }

    return await connection.del(...keys)
  }

  async exists(database: RedisDatabase, key: string): Promise<boolean> {
    const connection = this.getConnection(database)
    const result = await connection.exists(key)
    return result === 1
  }

  async expire(database: RedisDatabase, key: string, seconds: number): Promise<boolean> {
    const connection = this.getConnection(database)
    const result = await connection.expire(key, seconds)
    return result === 1
  }

  async getTTL(database: RedisDatabase, key: string): Promise<number> {
    const connection = this.getConnection(database)
    return await connection.ttl(key)
  }

  // Rate limiting operations
  async incrementWithExpiry(key: string, window: number, limit: number): Promise<{ count: number; remaining: number; resetTime: number }> {
    const rateLimitStore = this.getRateLimitStore()

    const pipeline = rateLimitStore.pipeline()
    pipeline.incr(key)
    pipeline.expire(key, window)
    pipeline.ttl(key)

    const results = await pipeline.exec()

    if (!results) {
      throw new Error('Redis pipeline execution failed')
    }

    const count = results[0][1] as number
    const ttl = results[2][1] as number
    const resetTime = Date.now() + (ttl * 1000)
    const remaining = Math.max(0, limit - count)

    return { count, remaining, resetTime }
  }

  // Session management
  async saveSession(sessionId: string, sessionData: any, maxAge: number): Promise<void> {
    await this.setWithTTL(RedisDatabase.SESSIONS, `session:${sessionId}`, sessionData, maxAge)
  }

  async getSession<T = any>(sessionId: string): Promise<T | null> {
    return await this.getWithParsing<T>(RedisDatabase.SESSIONS, `session:${sessionId}`)
  }

  async deleteSession(sessionId: string): Promise<void> {
    await this.deleteKey(RedisDatabase.SESSIONS, `session:${sessionId}`)
  }

  // Cache management with intelligent invalidation
  async cacheApiResponse(endpoint: string, params: any, response: any, ttl?: number): Promise<void> {
    const cacheKey = `api:${endpoint}:${this.hashParams(params)}`
    await this.setWithTTL(RedisDatabase.CACHE, cacheKey, {
      data: response,
      cachedAt: Date.now(),
      endpoint,
      params
    }, ttl)
  }

  async getCachedApiResponse<T = any>(endpoint: string, params: any): Promise<T | null> {
    const cacheKey = `api:${endpoint}:${this.hashParams(params)}`
    const cached = await this.getWithParsing<{ data: T; cachedAt: number }>(RedisDatabase.CACHE, cacheKey)
    return cached ? cached.data : null
  }

  async invalidateApiCache(pattern: string): Promise<number> {
    return await this.deletePattern(RedisDatabase.CACHE, `api:${pattern}*`)
  }

  // Job queue operations
  async enqueueJob(jobType: string, jobData: any, delay = 0): Promise<string> {
    const jobId = `${jobType}:${Date.now()}:${Math.random().toString(36).substr(2, 9)}`
    const job = {
      id: jobId,
      type: jobType,
      data: jobData,
      createdAt: Date.now(),
      scheduledFor: Date.now() + delay,
      status: 'pending'
    }

    const jobStore = this.getJobQueueStore()
    await jobStore.lpush(`queue:${jobType}`, JSON.stringify(job))

    if (delay > 0) {
      await jobStore.zadd('delayed_jobs', Date.now() + delay, jobId)
    }

    return jobId
  }

  async dequeueJob(jobType: string): Promise<any | null> {
    const jobStore = this.getJobQueueStore()
    const jobData = await jobStore.brpop(`queue:${jobType}`, 10)

    if (!jobData) {
      return null
    }

    try {
      return JSON.parse(jobData[1])
    } catch {
      return null
    }
  }

  // Health checking and monitoring
  private startHealthChecking(): void {
    this.healthCheckInterval = setInterval(async () => {
      await this.performHealthCheck()
    }, 30000) // Check every 30 seconds
  }

  async performHealthCheck(): Promise<Record<RedisDatabase, boolean>> {
    const results: Record<RedisDatabase, boolean> = {} as any

    for (const [database, connection] of this.connections) {
      try {
        await connection.ping()
        results[database] = true
      } catch (error) {
        results[database] = false
        logger.error(`Redis health check failed for database ${database}`, error)
      }
    }

    const healthyDatabases = Object.values(results).filter(healthy => healthy).length
    const totalDatabases = Object.keys(results).length

    if (healthyDatabases < totalDatabases) {
      logger.warn(`Redis health check: ${healthyDatabases}/${totalDatabases} databases healthy`, results)
    }

    return results
  }

  async getConnectionInfo(): Promise<Record<RedisDatabase, any>> {
    const info: Record<RedisDatabase, any> = {} as any

    for (const [database, connection] of this.connections) {
      try {
        const serverInfo = await connection.info('server')
        const memoryInfo = await connection.info('memory')
        const statsInfo = await connection.info('stats')

        info[database] = {
          status: connection.status,
          server: this.parseRedisInfo(serverInfo),
          memory: this.parseRedisInfo(memoryInfo),
          stats: this.parseRedisInfo(statsInfo)
        }
      } catch (error) {
        info[database] = { error: error instanceof Error ? error.message : 'Unknown error' }
      }
    }

    return info
  }

  async cleanup(): Promise<void> {
    if (this.healthCheckInterval) {
      clearInterval(this.healthCheckInterval)
    }

    for (const [database, connection] of this.connections) {
      try {
        await connection.quit()
        logger.info(`Redis connection closed for database ${database}`)
      } catch (error) {
        logger.error(`Error closing Redis connection for database ${database}`, error)
      }
    }

    this.connections.clear()
    this.isInitialized = false
    logger.info('Redis manager cleanup completed')
  }

  // Utility methods
  private hashParams(params: any): string {
    return require('crypto')
      .createHash('md5')
      .update(JSON.stringify(params))
      .digest('hex')
  }

  private parseRedisInfo(info: string): Record<string, string> {
    const result: Record<string, string> = {}
    const lines = info.split('\r\n')

    for (const line of lines) {
      if (line && !line.startsWith('#')) {
        const [key, value] = line.split(':')
        if (key && value) {
          result[key] = value
        }
      }
    }

    return result
  }

  // Database configuration getters
  getDatabaseConfig(database: RedisDatabase): DatabaseConfig {
    return DATABASE_CONFIGS[database]
  }

  getAllDatabaseConfigs(): Record<RedisDatabase, DatabaseConfig> {
    return DATABASE_CONFIGS
  }
}

// Singleton instance
export const redisManager = new RedisManager()

// Connection management utility
export class RedisConnectionPool {
  private static instances: Map<string, RedisManager> = new Map()

  static getInstance(instanceName = 'default'): RedisManager {
    if (!this.instances.has(instanceName)) {
      this.instances.set(instanceName, new RedisManager())
    }
    return this.instances.get(instanceName)!
  }

  static async initializeAll(): Promise<void> {
    const promises = Array.from(this.instances.values()).map(instance => instance.initialize())
    await Promise.all(promises)
  }

  static async cleanupAll(): Promise<void> {
    const promises = Array.from(this.instances.values()).map(instance => instance.cleanup())
    await Promise.all(promises)
    this.instances.clear()
  }
}

// Export types for external use
export type { RedisManagerConfig, DatabaseConfig }