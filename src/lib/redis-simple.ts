import Redis from 'ioredis'
import { logger } from './logger'

// Simple Redis manager for development without Sentinel
export class SimpleRedisManager {
  private redis: Redis | null = null
  private isInitialized = false

  constructor() {
    // Simple Redis configuration for development
    const redisUrl = process.env.REDIS_URL || 'redis://localhost:6379'
    const redisHost = process.env.REDIS_HOST || 'localhost'
    const redisPort = parseInt(process.env.REDIS_PORT || '6379')

    this.redis = new Redis({
      host: redisHost,
      port: redisPort,
      password: process.env.REDIS_PASSWORD || undefined,
      retryDelayOnFailover: 100,
      maxRetriesPerRequest: 3,
      lazyConnect: true,
      connectTimeout: 10000,
      commandTimeout: 5000,
      keepAlive: true,
      reconnectOnError: (err) => {
        const targetError = 'READONLY'
        return err.message.includes(targetError)
      }
    })

    this.redis.on('connect', () => {
      logger.info('Redis connected successfully')
    })

    this.redis.on('error', (error) => {
      logger.error('Redis connection error', error)
    })

    this.redis.on('close', () => {
      logger.warn('Redis connection closed')
    })
  }

  async initialize(): Promise<void> {
    if (this.isInitialized || !this.redis) {
      return
    }

    try {
      await this.redis.ping()
      this.isInitialized = true
      logger.info('Simple Redis manager initialized successfully')
    } catch (error) {
      logger.error('Failed to initialize Simple Redis manager', error)
      // Don't throw in development to avoid blocking the app
      logger.warn('Continuing without Redis connection')
    }
  }

  getConnection(): Redis | null {
    return this.redis
  }

  async set(key: string, value: string | object, ttl?: number): Promise<void> {
    if (!this.redis) return

    try {
      const serializedValue = typeof value === 'object' ? JSON.stringify(value) : value
      if (ttl) {
        await this.redis.setex(key, ttl, serializedValue)
      } else {
        await this.redis.set(key, serializedValue)
      }
    } catch (error) {
      logger.error('Redis set error', error)
    }
  }

  async get<T = any>(key: string): Promise<T | null> {
    if (!this.redis) return null

    try {
      const value = await this.redis.get(key)
      if (value === null) return null

      try {
        return JSON.parse(value) as T
      } catch {
        return value as T
      }
    } catch (error) {
      logger.error('Redis get error', error)
      return null
    }
  }

  async del(key: string): Promise<number> {
    if (!this.redis) return 0

    try {
      return await this.redis.del(key)
    } catch (error) {
      logger.error('Redis del error', error)
      return 0
    }
  }

  async exists(key: string): Promise<boolean> {
    if (!this.redis) return false

    try {
      const result = await this.redis.exists(key)
      return result === 1
    } catch (error) {
      logger.error('Redis exists error', error)
      return false
    }
  }

  async incr(key: string): Promise<number> {
    if (!this.redis) return 0

    try {
      return await this.redis.incr(key)
    } catch (error) {
      logger.error('Redis incr error', error)
      return 0
    }
  }

  async expire(key: string, seconds: number): Promise<boolean> {
    if (!this.redis) return false

    try {
      const result = await this.redis.expire(key, seconds)
      return result === 1
    } catch (error) {
      logger.error('Redis expire error', error)
      return false
    }
  }

  async cleanup(): Promise<void> {
    if (this.redis) {
      try {
        await this.redis.quit()
        logger.info('Redis connection closed')
      } catch (error) {
        logger.error('Error closing Redis connection', error)
      }
    }
    this.isInitialized = false
  }
}

// Singleton instance for development
export const simpleRedisManager = new SimpleRedisManager()