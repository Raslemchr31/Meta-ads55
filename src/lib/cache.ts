import Redis from 'ioredis'
import { createHash } from 'crypto'

interface CacheConfig {
  host: string
  port: number
  password?: string
  db: number
  keyPrefix: string
  retryDelayOnFailover: number
  enableReadyCheck: boolean
  maxRetriesPerRequest: number
}

export class CacheManager {
  private redis: Redis | null = null
  private config: CacheConfig
  private fallbackCache: Map<string, { value: any; expires: number }> = new Map()

  constructor() {
    this.config = {
      host: process.env.REDIS_HOST || 'localhost',
      port: parseInt(process.env.REDIS_PORT || '6379'),
      password: process.env.REDIS_PASSWORD || undefined,
      db: parseInt(process.env.REDIS_DB || '0'),
      keyPrefix: 'meta-ads:',
      retryDelayOnFailover: 100,
      enableReadyCheck: true,
      maxRetriesPerRequest: 3,
    }
  }

  async connect(): Promise<void> {
    try {
      this.redis = new Redis({
        ...this.config,
        lazyConnect: true,
      })

      this.redis.on('error', (error) => {
        console.error('Redis connection error:', error)
        // Fallback to in-memory cache on Redis failure
        this.redis = null
      })

      this.redis.on('connect', () => {
        console.log('Redis connected successfully')
      })

      await this.redis.connect()
    } catch (error) {
      console.warn('Failed to connect to Redis, using in-memory fallback:', error)
      this.redis = null
    }
  }

  private generateKey(key: string): string {
    return `${this.config.keyPrefix}${key}`
  }

  private hashKey(key: string): string {
    return createHash('md5').update(key).digest('hex')
  }

  async get<T>(key: string): Promise<T | null> {
    const hashedKey = this.generateKey(this.hashKey(key))

    try {
      if (this.redis) {
        const value = await this.redis.get(hashedKey)
        return value ? JSON.parse(value) : null
      } else {
        // Fallback to in-memory cache
        const cached = this.fallbackCache.get(hashedKey)
        if (cached && cached.expires > Date.now()) {
          return cached.value
        } else if (cached) {
          this.fallbackCache.delete(hashedKey)
        }
        return null
      }
    } catch (error) {
      console.error('Cache get error:', error)
      return null
    }
  }

  async set<T>(key: string, value: T, ttlSeconds: number = 3600): Promise<boolean> {
    const hashedKey = this.generateKey(this.hashKey(key))

    try {
      if (this.redis) {
        await this.redis.setex(hashedKey, ttlSeconds, JSON.stringify(value))
        return true
      } else {
        // Fallback to in-memory cache
        this.fallbackCache.set(hashedKey, {
          value,
          expires: Date.now() + (ttlSeconds * 1000),
        })
        return true
      }
    } catch (error) {
      console.error('Cache set error:', error)
      return false
    }
  }

  async del(key: string): Promise<boolean> {
    const hashedKey = this.generateKey(this.hashKey(key))

    try {
      if (this.redis) {
        await this.redis.del(hashedKey)
        return true
      } else {
        this.fallbackCache.delete(hashedKey)
        return true
      }
    } catch (error) {
      console.error('Cache delete error:', error)
      return false
    }
  }

  async exists(key: string): Promise<boolean> {
    const hashedKey = this.generateKey(this.hashKey(key))

    try {
      if (this.redis) {
        const result = await this.redis.exists(hashedKey)
        return result === 1
      } else {
        const cached = this.fallbackCache.get(hashedKey)
        return cached ? cached.expires > Date.now() : false
      }
    } catch (error) {
      console.error('Cache exists error:', error)
      return false
    }
  }

  async mget<T>(keys: string[]): Promise<(T | null)[]> {
    const hashedKeys = keys.map(key => this.generateKey(this.hashKey(key)))

    try {
      if (this.redis) {
        const values = await this.redis.mget(...hashedKeys)
        return values.map(value => value ? JSON.parse(value) : null)
      } else {
        return hashedKeys.map(key => {
          const cached = this.fallbackCache.get(key)
          if (cached && cached.expires > Date.now()) {
            return cached.value
          } else if (cached) {
            this.fallbackCache.delete(key)
          }
          return null
        })
      }
    } catch (error) {
      console.error('Cache mget error:', error)
      return keys.map(() => null)
    }
  }

  async mset<T>(keyValuePairs: Array<{ key: string; value: T; ttl?: number }>): Promise<boolean> {
    try {
      if (this.redis) {
        const pipeline = this.redis.pipeline()
        
        for (const { key, value, ttl = 3600 } of keyValuePairs) {
          const hashedKey = this.generateKey(this.hashKey(key))
          pipeline.setex(hashedKey, ttl, JSON.stringify(value))
        }
        
        await pipeline.exec()
        return true
      } else {
        for (const { key, value, ttl = 3600 } of keyValuePairs) {
          const hashedKey = this.generateKey(this.hashKey(key))
          this.fallbackCache.set(hashedKey, {
            value,
            expires: Date.now() + (ttl * 1000),
          })
        }
        return true
      }
    } catch (error) {
      console.error('Cache mset error:', error)
      return false
    }
  }

  async incr(key: string, amount: number = 1): Promise<number> {
    const hashedKey = this.generateKey(this.hashKey(key))

    try {
      if (this.redis) {
        return await this.redis.incrby(hashedKey, amount)
      } else {
        const cached = this.fallbackCache.get(hashedKey)
        const currentValue = (cached && cached.expires > Date.now()) ? (cached.value || 0) : 0
        const newValue = currentValue + amount
        
        this.fallbackCache.set(hashedKey, {
          value: newValue,
          expires: Date.now() + 3600000, // 1 hour default
        })
        
        return newValue
      }
    } catch (error) {
      console.error('Cache incr error:', error)
      return amount
    }
  }

  async expire(key: string, ttlSeconds: number): Promise<boolean> {
    const hashedKey = this.generateKey(this.hashKey(key))

    try {
      if (this.redis) {
        await this.redis.expire(hashedKey, ttlSeconds)
        return true
      } else {
        const cached = this.fallbackCache.get(hashedKey)
        if (cached) {
          cached.expires = Date.now() + (ttlSeconds * 1000)
          return true
        }
        return false
      }
    } catch (error) {
      console.error('Cache expire error:', error)
      return false
    }
  }

  // Meta Ads specific cache operations
  async cacheInsights(accountId: string, level: string, data: any, ttlMinutes: number = 15): Promise<void> {
    const key = `insights:${accountId}:${level}:${new Date().toISOString().split('T')[0]}`
    await this.set(key, data, ttlMinutes * 60)
  }

  async getCachedInsights(accountId: string, level: string): Promise<any | null> {
    const key = `insights:${accountId}:${level}:${new Date().toISOString().split('T')[0]}`
    return await this.get(key)
  }

  async cacheAccountData(accountId: string, data: any, ttlMinutes: number = 60): Promise<void> {
    const key = `account:${accountId}`
    await this.set(key, data, ttlMinutes * 60)
  }

  async getCachedAccountData(accountId: string): Promise<any | null> {
    const key = `account:${accountId}`
    return await this.get(key)
  }

  async cacheCampaigns(accountId: string, campaigns: any[], ttlMinutes: number = 30): Promise<void> {
    const key = `campaigns:${accountId}`
    await this.set(key, campaigns, ttlMinutes * 60)
  }

  async getCachedCampaigns(accountId: string): Promise<any[] | null> {
    const key = `campaigns:${accountId}`
    return await this.get(key)
  }

  // Rate limiting helpers
  async incrementRateLimit(identifier: string, windowSeconds: number = 3600): Promise<number> {
    const key = `rate_limit:${identifier}:${Math.floor(Date.now() / (windowSeconds * 1000))}`
    const count = await this.incr(key)
    await this.expire(key, windowSeconds)
    return count
  }

  async getRateLimit(identifier: string, windowSeconds: number = 3600): Promise<number> {
    const key = `rate_limit:${identifier}:${Math.floor(Date.now() / (windowSeconds * 1000))}`
    const count = await this.get<number>(key)
    return count || 0
  }

  // Cache warming and cleanup
  async warmCache(accountIds: string[]): Promise<void> {
    console.log('Starting cache warming for', accountIds.length, 'accounts')
    
    // This would be implemented to pre-populate frequently accessed data
    for (const accountId of accountIds) {
      try {
        // Pre-cache basic account info
        const cacheKey = `account:${accountId}`
        const exists = await this.exists(cacheKey)
        
        if (!exists) {
          // Would fetch and cache account data here
          console.log(`Warming cache for account ${accountId}`)
        }
      } catch (error) {
        console.error(`Failed to warm cache for account ${accountId}:`, error)
      }
    }
  }

  async cleanupExpiredKeys(): Promise<void> {
    if (!this.redis) {
      // Clean up in-memory cache
      const now = Date.now()
      for (const [key, cached] of this.fallbackCache.entries()) {
        if (cached.expires <= now) {
          this.fallbackCache.delete(key)
        }
      }
      return
    }

    try {
      // For Redis, we rely on TTL expiration, but we can do additional cleanup
      const keys = await this.redis.keys(`${this.config.keyPrefix}*`)
      let cleaned = 0
      
      for (const key of keys) {
        const ttl = await this.redis.ttl(key)
        if (ttl === -2) { // Key doesn't exist
          cleaned++
        }
      }
      
      if (cleaned > 0) {
        console.log(`Cleaned up ${cleaned} expired cache keys`)
      }
    } catch (error) {
      console.error('Cache cleanup error:', error)
    }
  }

  async getStats(): Promise<{ keys: number; memory?: string; connected: boolean }> {
    try {
      if (this.redis) {
        const info = await this.redis.info('memory')
        const dbsize = await this.redis.dbsize()
        
        return {
          keys: dbsize,
          memory: info.split('\r\n').find(line => line.startsWith('used_memory_human:'))?.split(':')[1],
          connected: true,
        }
      } else {
        return {
          keys: this.fallbackCache.size,
          connected: false,
        }
      }
    } catch (error) {
      console.error('Failed to get cache stats:', error)
      return { keys: 0, connected: false }
    }
  }

  async close(): Promise<void> {
    if (this.redis) {
      await this.redis.quit()
      this.redis = null
    }
    this.fallbackCache.clear()
  }
}

// Singleton instance
export const cacheManager = new CacheManager()