import { redisManager, RedisDatabase } from '../redis-manager'
import { logger } from '../logger'
import crypto from 'crypto'

interface MetaToken {
  accessToken: string
  refreshToken?: string
  tokenType: 'user' | 'system_user' | 'app'
  userId?: string
  appId: string
  scopes: string[]
  issuedAt: number
  expiresAt: number
  lastRefresh?: number
  refreshCount: number
  metadata: {
    ipAddress?: string
    userAgent?: string
    sessionId?: string
  }
}

interface SystemUserToken extends MetaToken {
  systemUserId: string
  businessId: string
  permissions: string[]
  quotaUsage: {
    daily: number
    hourly: number
    lastReset: number
  }
}

interface TokenRefreshResult {
  success: boolean
  newToken?: MetaToken
  error?: string
  retryAfter?: number
}

interface TokenQuota {
  limit: number
  used: number
  resetTime: number
  window: 'hour' | 'day'
}

export class MetaTokenManager {
  private readonly cacheStore = redisManager.getCacheStore()
  private readonly auditStore = redisManager.getAnalyticsStore()
  private readonly encryptionKey: string

  private readonly metaAPIEndpoints = {
    tokenInfo: 'https://graph.facebook.com/v23.0/me',
    tokenRefresh: 'https://graph.facebook.com/v23.0/oauth/access_token',
    systemUserTokens: 'https://graph.facebook.com/v23.0/{system-user-id}/access_tokens'
  }

  private readonly scopePermissions = {
    'ads_management': ['campaign_create', 'campaign_read', 'campaign_update', 'campaign_delete'],
    'ads_read': ['campaign_read', 'insights_read'],
    'business_management': ['business_read', 'business_write'],
    'instagram_basic': ['instagram_read'],
    'instagram_manage_insights': ['instagram_insights_read'],
    'read_insights': ['insights_read'],
    'pages_read_engagement': ['page_read'],
    'pages_show_list': ['page_list']
  }

  constructor() {
    this.encryptionKey = process.env.META_TOKEN_ENCRYPTION_KEY || this.generateEncryptionKey()
  }

  private generateEncryptionKey(): string {
    return crypto.randomBytes(32).toString('hex')
  }

  private encrypt(data: string): { encrypted: string; iv: string } {
    const iv = crypto.randomBytes(16)
    const cipher = crypto.createCipher('aes-256-gcm', this.encryptionKey)
    let encrypted = cipher.update(data, 'utf8', 'hex')
    encrypted += cipher.final('hex')
    const authTag = cipher.getAuthTag()

    return {
      encrypted: encrypted + ':' + authTag.toString('hex'),
      iv: iv.toString('hex')
    }
  }

  private decrypt(encrypted: string, iv: string): string {
    const [encryptedData, authTag] = encrypted.split(':')
    const decipher = crypto.createDecipher('aes-256-gcm', this.encryptionKey)
    decipher.setAuthTag(Buffer.from(authTag, 'hex'))

    let decrypted = decipher.update(encryptedData, 'hex', 'utf8')
    decrypted += decipher.final('utf8')
    return decrypted
  }

  async storeToken(
    tokenId: string,
    token: MetaToken | SystemUserToken,
    encrypt = true
  ): Promise<void> {
    try {
      const tokenData = {
        ...token,
        storedAt: Date.now()
      }

      let serializedData = JSON.stringify(tokenData)
      let storageData: any = { data: serializedData }

      if (encrypt) {
        const { encrypted, iv } = this.encrypt(serializedData)
        storageData = { encrypted, iv, encrypted: true }
      }

      const ttl = Math.max(0, Math.floor((token.expiresAt - Date.now()) / 1000))
      const tokenKey = `meta_token:${tokenId}`

      await this.cacheStore.setex(tokenKey, ttl, JSON.stringify(storageData))

      // Store token reference for user/system user
      if (token.tokenType === 'user' && token.userId) {
        const userTokensKey = `user:${token.userId}:meta_tokens`
        await this.cacheStore.sadd(userTokensKey, tokenId)
        await this.cacheStore.expire(userTokensKey, ttl)
      } else if (token.tokenType === 'system_user') {
        const systemToken = token as SystemUserToken
        const systemTokensKey = `system_user:${systemToken.systemUserId}:tokens`
        await this.cacheStore.sadd(systemTokensKey, tokenId)
        await this.cacheStore.expire(systemTokensKey, ttl)
      }

      // Log token storage
      await this.logTokenEvent(tokenId, 'stored', {
        tokenType: token.tokenType,
        userId: token.userId,
        scopes: token.scopes,
        expiresAt: token.expiresAt
      })

      logger.info('Meta token stored successfully', {
        tokenId,
        tokenType: token.tokenType,
        userId: token.userId,
        expiresAt: new Date(token.expiresAt).toISOString()
      })
    } catch (error) {
      logger.error('Failed to store Meta token', error, { tokenId })
      throw error
    }
  }

  async getToken(tokenId: string): Promise<MetaToken | SystemUserToken | null> {
    try {
      const tokenKey = `meta_token:${tokenId}`
      const tokenData = await this.cacheStore.get(tokenKey)

      if (!tokenData) {
        return null
      }

      const storageData = JSON.parse(tokenData)
      let serializedData: string

      if (storageData.encrypted) {
        serializedData = this.decrypt(storageData.encrypted, storageData.iv)
      } else {
        serializedData = storageData.data
      }

      const token = JSON.parse(serializedData)

      // Check if token is expired
      if (token.expiresAt <= Date.now()) {
        await this.removeToken(tokenId)
        return null
      }

      return token
    } catch (error) {
      logger.error('Failed to get Meta token', error, { tokenId })
      return null
    }
  }

  async refreshToken(tokenId: string, force = false): Promise<TokenRefreshResult> {
    try {
      const token = await this.getToken(tokenId)
      if (!token) {
        return { success: false, error: 'Token not found' }
      }

      // Check if refresh is needed
      const timeUntilExpiry = token.expiresAt - Date.now()
      const refreshThreshold = 24 * 60 * 60 * 1000 // 24 hours

      if (!force && timeUntilExpiry > refreshThreshold) {
        return { success: true, newToken: token }
      }

      // Check if token has refresh capability
      if (!token.refreshToken && token.tokenType !== 'system_user') {
        return { success: false, error: 'Token cannot be refreshed' }
      }

      // Perform refresh based on token type
      let refreshResult: TokenRefreshResult

      if (token.tokenType === 'system_user') {
        refreshResult = await this.refreshSystemUserToken(token as SystemUserToken)
      } else {
        refreshResult = await this.refreshUserToken(token)
      }

      if (refreshResult.success && refreshResult.newToken) {
        // Store the new token
        await this.storeToken(tokenId, refreshResult.newToken)

        // Log refresh event
        await this.logTokenEvent(tokenId, 'refreshed', {
          oldExpiresAt: token.expiresAt,
          newExpiresAt: refreshResult.newToken.expiresAt,
          refreshCount: refreshResult.newToken.refreshCount
        })
      }

      return refreshResult
    } catch (error) {
      logger.error('Failed to refresh Meta token', error, { tokenId })
      return { success: false, error: error instanceof Error ? error.message : 'Unknown error' }
    }
  }

  private async refreshUserToken(token: MetaToken): Promise<TokenRefreshResult> {
    try {
      if (!token.refreshToken) {
        return { success: false, error: 'No refresh token available' }
      }

      const response = await fetch(this.metaAPIEndpoints.tokenRefresh, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: new URLSearchParams({
          grant_type: 'refresh_token',
          refresh_token: token.refreshToken,
          client_id: process.env.FACEBOOK_CLIENT_ID!,
          client_secret: process.env.FACEBOOK_CLIENT_SECRET!
        })
      })

      if (!response.ok) {
        const error = await response.text()
        return { success: false, error: `Token refresh failed: ${error}` }
      }

      const data = await response.json()

      const newToken: MetaToken = {
        ...token,
        accessToken: data.access_token,
        refreshToken: data.refresh_token || token.refreshToken,
        expiresAt: Date.now() + (data.expires_in * 1000),
        lastRefresh: Date.now(),
        refreshCount: token.refreshCount + 1
      }

      return { success: true, newToken }
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error'
      }
    }
  }

  private async refreshSystemUserToken(token: SystemUserToken): Promise<TokenRefreshResult> {
    try {
      const appId = process.env.FACEBOOK_CLIENT_ID!
      const appSecret = process.env.FACEBOOK_CLIENT_SECRET!

      const response = await fetch(
        this.metaAPIEndpoints.systemUserTokens.replace('{system-user-id}', token.systemUserId),
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
          },
          body: new URLSearchParams({
            access_token: `${appId}|${appSecret}`,
            scope: token.scopes.join(',')
          })
        }
      )

      if (!response.ok) {
        const error = await response.text()
        return { success: false, error: `System user token refresh failed: ${error}` }
      }

      const data = await response.json()

      const newToken: SystemUserToken = {
        ...token,
        accessToken: data.access_token,
        issuedAt: Date.now(),
        expiresAt: Date.now() + (365 * 24 * 60 * 60 * 1000), // System user tokens don't expire, but we refresh annually
        lastRefresh: Date.now(),
        refreshCount: token.refreshCount + 1
      }

      return { success: true, newToken }
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error'
      }
    }
  }

  async validateToken(tokenId: string): Promise<{
    valid: boolean
    token?: MetaToken | SystemUserToken
    scopes?: string[]
    permissions?: string[]
    quotaStatus?: TokenQuota
  }> {
    try {
      const token = await this.getToken(tokenId)
      if (!token) {
        return { valid: false }
      }

      // Check expiration
      if (token.expiresAt <= Date.now()) {
        await this.removeToken(tokenId)
        return { valid: false }
      }

      // Validate with Meta API
      const validation = await this.validateWithMeta(token.accessToken)
      if (!validation.valid) {
        await this.removeToken(tokenId)
        return { valid: false }
      }

      // Get permissions from scopes
      const permissions = this.getPermissionsFromScopes(token.scopes)

      // Get quota status for system user tokens
      let quotaStatus: TokenQuota | undefined
      if (token.tokenType === 'system_user') {
        quotaStatus = await this.getQuotaStatus(tokenId)
      }

      return {
        valid: true,
        token,
        scopes: token.scopes,
        permissions,
        quotaStatus
      }
    } catch (error) {
      logger.error('Failed to validate Meta token', error, { tokenId })
      return { valid: false }
    }
  }

  private async validateWithMeta(accessToken: string): Promise<{ valid: boolean; data?: any }> {
    try {
      const response = await fetch(`${this.metaAPIEndpoints.tokenInfo}?access_token=${accessToken}`)

      if (!response.ok) {
        return { valid: false }
      }

      const data = await response.json()
      return { valid: true, data }
    } catch (error) {
      return { valid: false }
    }
  }

  private getPermissionsFromScopes(scopes: string[]): string[] {
    const permissions: string[] = []

    for (const scope of scopes) {
      const scopePermissions = this.scopePermissions[scope as keyof typeof this.scopePermissions]
      if (scopePermissions) {
        permissions.push(...scopePermissions)
      }
    }

    return [...new Set(permissions)] // Remove duplicates
  }

  async removeToken(tokenId: string): Promise<void> {
    try {
      const token = await this.getToken(tokenId)

      if (token) {
        // Remove from user/system user references
        if (token.tokenType === 'user' && token.userId) {
          const userTokensKey = `user:${token.userId}:meta_tokens`
          await this.cacheStore.srem(userTokensKey, tokenId)
        } else if (token.tokenType === 'system_user') {
          const systemToken = token as SystemUserToken
          const systemTokensKey = `system_user:${systemToken.systemUserId}:tokens`
          await this.cacheStore.srem(systemTokensKey, tokenId)
        }

        // Log token removal
        await this.logTokenEvent(tokenId, 'removed', {
          tokenType: token.tokenType,
          userId: token.userId
        })
      }

      // Remove token
      const tokenKey = `meta_token:${tokenId}`
      await this.cacheStore.del(tokenKey)

      logger.info('Meta token removed', { tokenId })
    } catch (error) {
      logger.error('Failed to remove Meta token', error, { tokenId })
    }
  }

  async getUserTokens(userId: string): Promise<Array<{ tokenId: string; token: MetaToken }>> {
    try {
      const userTokensKey = `user:${userId}:meta_tokens`
      const tokenIds = await this.cacheStore.smembers(userTokensKey)

      const tokens = await Promise.all(
        tokenIds.map(async (tokenId) => {
          const token = await this.getToken(tokenId)
          return token ? { tokenId, token: token as MetaToken } : null
        })
      )

      return tokens.filter(t => t !== null) as Array<{ tokenId: string; token: MetaToken }>
    } catch (error) {
      logger.error('Failed to get user Meta tokens', error, { userId })
      return []
    }
  }

  async getSystemUserTokens(systemUserId: string): Promise<Array<{ tokenId: string; token: SystemUserToken }>> {
    try {
      const systemTokensKey = `system_user:${systemUserId}:tokens`
      const tokenIds = await this.cacheStore.smembers(systemTokensKey)

      const tokens = await Promise.all(
        tokenIds.map(async (tokenId) => {
          const token = await this.getToken(tokenId)
          return token ? { tokenId, token: token as SystemUserToken } : null
        })
      )

      return tokens.filter(t => t !== null) as Array<{ tokenId: string; token: SystemUserToken }>
    } catch (error) {
      logger.error('Failed to get system user Meta tokens', error, { systemUserId })
      return []
    }
  }

  async trackQuotaUsage(tokenId: string, apiEndpoint: string, cost = 1): Promise<{
    allowed: boolean
    quota: TokenQuota
    retryAfter?: number
  }> {
    try {
      const token = await this.getToken(tokenId)
      if (!token || token.tokenType !== 'system_user') {
        return { allowed: true, quota: { limit: 1000, used: 0, resetTime: Date.now() + 3600000, window: 'hour' } }
      }

      const now = Date.now()
      const hourlyKey = `quota:hourly:${tokenId}:${Math.floor(now / 3600000)}`
      const dailyKey = `quota:daily:${tokenId}:${Math.floor(now / 86400000)}`

      // Get current usage
      const hourlyUsed = parseInt(await this.cacheStore.get(hourlyKey) || '0')
      const dailyUsed = parseInt(await this.cacheStore.get(dailyKey) || '0')

      // Define limits (these should be configurable based on app and user tier)
      const hourlyLimit = 200 // Facebook's default hourly limit
      const dailyLimit = 2000 // Facebook's default daily limit

      // Check limits
      if (hourlyUsed + cost > hourlyLimit) {
        const resetTime = (Math.floor(now / 3600000) + 1) * 3600000
        return {
          allowed: false,
          quota: { limit: hourlyLimit, used: hourlyUsed, resetTime, window: 'hour' },
          retryAfter: Math.ceil((resetTime - now) / 1000)
        }
      }

      if (dailyUsed + cost > dailyLimit) {
        const resetTime = (Math.floor(now / 86400000) + 1) * 86400000
        return {
          allowed: false,
          quota: { limit: dailyLimit, used: dailyUsed, resetTime, window: 'day' },
          retryAfter: Math.ceil((resetTime - now) / 1000)
        }
      }

      // Update usage
      await this.cacheStore.incrby(hourlyKey, cost)
      await this.cacheStore.expire(hourlyKey, 3600) // 1 hour
      await this.cacheStore.incrby(dailyKey, cost)
      await this.cacheStore.expire(dailyKey, 86400) // 24 hours

      // Log quota usage
      await this.logTokenEvent(tokenId, 'quota_used', {
        apiEndpoint,
        cost,
        hourlyUsed: hourlyUsed + cost,
        dailyUsed: dailyUsed + cost
      })

      return {
        allowed: true,
        quota: { limit: hourlyLimit, used: hourlyUsed + cost, resetTime: (Math.floor(now / 3600000) + 1) * 3600000, window: 'hour' }
      }
    } catch (error) {
      logger.error('Failed to track quota usage', error, { tokenId })
      // Fail open - allow request if tracking fails
      return { allowed: true, quota: { limit: 1000, used: 0, resetTime: Date.now() + 3600000, window: 'hour' } }
    }
  }

  private async getQuotaStatus(tokenId: string): Promise<TokenQuota> {
    const now = Date.now()
    const hourlyKey = `quota:hourly:${tokenId}:${Math.floor(now / 3600000)}`
    const hourlyUsed = parseInt(await this.cacheStore.get(hourlyKey) || '0')
    const hourlyLimit = 200

    return {
      limit: hourlyLimit,
      used: hourlyUsed,
      resetTime: (Math.floor(now / 3600000) + 1) * 3600000,
      window: 'hour'
    }
  }

  async rotateSystemUserTokens(systemUserId: string): Promise<{
    rotated: number
    failed: number
    errors: string[]
  }> {
    const tokens = await this.getSystemUserTokens(systemUserId)
    let rotated = 0
    let failed = 0
    const errors: string[] = []

    for (const { tokenId, token } of tokens) {
      try {
        const refreshResult = await this.refreshToken(tokenId, true)
        if (refreshResult.success) {
          rotated++
        } else {
          failed++
          errors.push(`${tokenId}: ${refreshResult.error}`)
        }
      } catch (error) {
        failed++
        errors.push(`${tokenId}: ${error instanceof Error ? error.message : 'Unknown error'}`)
      }
    }

    logger.info('System user token rotation completed', {
      systemUserId,
      rotated,
      failed,
      total: tokens.length
    })

    return { rotated, failed, errors }
  }

  private async logTokenEvent(
    tokenId: string,
    event: string,
    metadata: Record<string, any>
  ): Promise<void> {
    const logEntry = {
      tokenId,
      event,
      timestamp: Date.now(),
      metadata
    }

    const logKey = `token_log:${tokenId}:${Date.now()}`
    await this.auditStore.setex(logKey, 90 * 24 * 60 * 60, JSON.stringify(logEntry)) // 90 days
  }

  // Automatic token refresh job
  async refreshExpiringTokens(): Promise<{ refreshed: number; failed: number }> {
    let refreshed = 0
    let failed = 0

    try {
      // Find tokens expiring in the next 24 hours
      const pattern = 'meta_token:*'
      const keys = await this.cacheStore.keys(pattern)

      for (const key of keys) {
        try {
          const tokenId = key.replace('meta_token:', '')
          const token = await this.getToken(tokenId)

          if (token) {
            const timeUntilExpiry = token.expiresAt - Date.now()
            const refreshThreshold = 24 * 60 * 60 * 1000 // 24 hours

            if (timeUntilExpiry <= refreshThreshold && timeUntilExpiry > 0) {
              const result = await this.refreshToken(tokenId)
              if (result.success) {
                refreshed++
              } else {
                failed++
              }
            }
          }
        } catch (error) {
          logger.error('Error refreshing token', error, { key })
          failed++
        }
      }

      logger.info('Token refresh job completed', { refreshed, failed })
    } catch (error) {
      logger.error('Token refresh job failed', error)
      failed++
    }

    return { refreshed, failed }
  }

  // Token cleanup job
  async cleanupExpiredTokens(): Promise<{ cleaned: number; errors: number }> {
    let cleaned = 0
    let errors = 0

    try {
      const pattern = 'meta_token:*'
      const keys = await this.cacheStore.keys(pattern)

      for (const key of keys) {
        try {
          const tokenId = key.replace('meta_token:', '')
          const token = await this.getToken(tokenId)

          if (!token) {
            // Token already cleaned up or expired
            continue
          }

          if (token.expiresAt <= Date.now()) {
            await this.removeToken(tokenId)
            cleaned++
          }
        } catch (error) {
          logger.error('Error cleaning token', error, { key })
          errors++
        }
      }

      logger.info('Token cleanup completed', { cleaned, errors })
    } catch (error) {
      logger.error('Token cleanup failed', error)
      errors++
    }

    return { cleaned, errors }
  }
}

// Singleton instance
export const metaTokenManager = new MetaTokenManager()