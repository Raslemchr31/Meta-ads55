import { redisManager, RedisDatabase } from '../redis-manager'
import { logger } from '../logger'
import crypto from 'crypto'
import { JWT, JWTPayload } from 'jose'

interface SessionData {
  userId: string
  email: string
  name: string
  profileImage?: string
  metaAccessToken?: string
  metaRefreshToken?: string
  metaTokenExpiry?: number
  scopes: string[]
  permissions: string[]
  teamId?: string
  role: string
  lastActivity: number
  createdAt: number
  deviceFingerprint: string
  ipAddress: string
  userAgent: string
  geographic: {
    country?: string
    city?: string
    timezone?: string
  }
  mfa?: {
    enabled: boolean
    lastVerified?: number
  }
}

interface SessionConfig {
  maxAge: number
  slidingWindow: boolean
  slidingWindowDuration: number
  maxConcurrentSessions: number
  deviceTracking: boolean
}

interface DeviceFingerprint {
  userAgent: string
  acceptLanguage: string
  timezone: string
  screenResolution?: string
  plugins?: string[]
  canvasFingerprint?: string
}

interface LoginHistoryEntry {
  timestamp: number
  sessionId: string
  ipAddress: string
  userAgent: string
  deviceFingerprint: string
  geographic: {
    country?: string
    city?: string
    timezone?: string
  }
  success: boolean
  failureReason?: string
  suspicious: boolean
}

export class EnhancedSessionManager {
  private readonly sessionStore = redisManager.getSessionStore()
  private readonly userStore = redisManager.getUserPrefsStore()
  private readonly auditStore = redisManager.getAnalyticsStore()
  private readonly encryptionKey: string
  private readonly jwtSecret: string

  constructor() {
    this.encryptionKey = process.env.SESSION_ENCRYPTION_KEY || this.generateEncryptionKey()
    this.jwtSecret = process.env.NEXTAUTH_SECRET || 'fallback-secret'
  }

  private generateEncryptionKey(): string {
    return crypto.randomBytes(32).toString('hex')
  }

  private encrypt(data: string): { encrypted: string; iv: string } {
    const iv = crypto.randomBytes(16)
    const cipher = crypto.createCipher('aes-256-cbc', this.encryptionKey)
    let encrypted = cipher.update(data, 'utf8', 'hex')
    encrypted += cipher.final('hex')
    return { encrypted, iv: iv.toString('hex') }
  }

  private decrypt(encrypted: string, iv: string): string {
    const decipher = crypto.createDecipher('aes-256-cbc', this.encryptionKey)
    let decrypted = decipher.update(encrypted, 'hex', 'utf8')
    decrypted += decipher.final('utf8')
    return decrypted
  }

  private generateSessionId(): string {
    return crypto.randomBytes(32).toString('hex')
  }

  private generateDeviceFingerprint(request: {
    userAgent: string
    acceptLanguage?: string
    timezone?: string
    ip: string
  }): string {
    const fingerprintData = {
      userAgent: request.userAgent,
      acceptLanguage: request.acceptLanguage || '',
      timezone: request.timezone || '',
      ip: request.ip.split('.').slice(0, 3).join('.') // Partial IP for privacy
    }

    return crypto
      .createHash('sha256')
      .update(JSON.stringify(fingerprintData))
      .digest('hex')
  }

  async createSession(
    userData: Partial<SessionData>,
    request: {
      ip: string
      userAgent: string
      acceptLanguage?: string
      timezone?: string
    },
    config: Partial<SessionConfig> = {}
  ): Promise<{ sessionId: string; token: string }> {
    const sessionId = this.generateSessionId()
    const deviceFingerprint = this.generateDeviceFingerprint(request)

    const sessionConfig: SessionConfig = {
      maxAge: 30 * 24 * 60 * 60, // 30 days
      slidingWindow: true,
      slidingWindowDuration: 7 * 24 * 60 * 60, // 7 days
      maxConcurrentSessions: 5,
      deviceTracking: true,
      ...config
    }

    // Check for concurrent session limits
    if (userData.userId) {
      await this.enforceConcurrentSessionLimits(userData.userId, sessionConfig.maxConcurrentSessions)
    }

    const now = Date.now()
    const sessionData: SessionData = {
      userId: userData.userId || '',
      email: userData.email || '',
      name: userData.name || '',
      profileImage: userData.profileImage,
      metaAccessToken: userData.metaAccessToken,
      metaRefreshToken: userData.metaRefreshToken,
      metaTokenExpiry: userData.metaTokenExpiry,
      scopes: userData.scopes || [],
      permissions: userData.permissions || [],
      teamId: userData.teamId,
      role: userData.role || 'user',
      lastActivity: now,
      createdAt: now,
      deviceFingerprint,
      ipAddress: request.ip,
      userAgent: request.userAgent,
      geographic: {
        timezone: request.timezone
      },
      mfa: userData.mfa || { enabled: false }
    }

    // Encrypt sensitive data
    const { encrypted: encryptedData, iv } = this.encrypt(JSON.stringify(sessionData))

    // Store session in Redis with TTL
    const sessionKey = `session:${sessionId}`
    await this.sessionStore.setex(sessionKey, sessionConfig.maxAge, JSON.stringify({
      data: encryptedData,
      iv,
      config: sessionConfig,
      lastAccess: now
    }))

    // Store session reference for user
    if (userData.userId) {
      const userSessionsKey = `user:${userData.userId}:sessions`
      await this.sessionStore.sadd(userSessionsKey, sessionId)
      await this.sessionStore.expire(userSessionsKey, sessionConfig.maxAge)
    }

    // Store device fingerprint tracking
    if (sessionConfig.deviceTracking && userData.userId) {
      await this.trackDeviceFingerprint(userData.userId, deviceFingerprint, sessionId)
    }

    // Log session creation
    await this.logSessionEvent(sessionId, 'created', {
      userId: userData.userId,
      deviceFingerprint,
      ipAddress: request.ip
    })

    // Generate JWT token for client
    const token = await this.generateJWT(sessionId, userData.userId || '', sessionConfig.maxAge)

    logger.info('Session created successfully', {
      sessionId,
      userId: userData.userId,
      deviceFingerprint,
      ipAddress: request.ip,
      type: 'session_created'
    })

    return { sessionId, token }
  }

  async getSession(sessionId: string, extendSession = true): Promise<SessionData | null> {
    try {
      const sessionKey = `session:${sessionId}`
      const sessionString = await this.sessionStore.get(sessionKey)

      if (!sessionString) {
        return null
      }

      const sessionWrapper = JSON.parse(sessionString)
      const { data: encryptedData, iv, config, lastAccess } = sessionWrapper

      // Decrypt session data
      const decryptedData = this.decrypt(encryptedData, iv)
      const sessionData: SessionData = JSON.parse(decryptedData)

      const now = Date.now()

      // Check if session is expired
      if (config.slidingWindow) {
        const timeSinceLastAccess = now - lastAccess
        if (timeSinceLastAccess > config.slidingWindowDuration * 1000) {
          await this.destroySession(sessionId)
          return null
        }
      }

      // Extend session if configured and requested
      if (extendSession && config.slidingWindow) {
        sessionWrapper.lastAccess = now
        sessionData.lastActivity = now

        // Re-encrypt and store updated session
        const { encrypted: newEncryptedData, iv: newIv } = this.encrypt(JSON.stringify(sessionData))
        sessionWrapper.data = newEncryptedData
        sessionWrapper.iv = newIv

        await this.sessionStore.setex(sessionKey, config.maxAge, JSON.stringify(sessionWrapper))

        // Log session extension
        await this.logSessionEvent(sessionId, 'extended', {
          userId: sessionData.userId,
          lastActivity: now
        })
      }

      return sessionData
    } catch (error) {
      logger.error('Failed to get session', error, { sessionId })
      return null
    }
  }

  async updateSession(sessionId: string, updates: Partial<SessionData>): Promise<boolean> {
    try {
      const sessionData = await this.getSession(sessionId, false)
      if (!sessionData) {
        return false
      }

      // Merge updates
      const updatedData = { ...sessionData, ...updates, lastActivity: Date.now() }

      // Get current session wrapper
      const sessionKey = `session:${sessionId}`
      const sessionString = await this.sessionStore.get(sessionKey)
      if (!sessionString) {
        return false
      }

      const sessionWrapper = JSON.parse(sessionString)

      // Re-encrypt updated data
      const { encrypted: encryptedData, iv } = this.encrypt(JSON.stringify(updatedData))
      sessionWrapper.data = encryptedData
      sessionWrapper.iv = iv

      await this.sessionStore.setex(sessionKey, sessionWrapper.config.maxAge, JSON.stringify(sessionWrapper))

      // Log session update
      await this.logSessionEvent(sessionId, 'updated', {
        userId: updatedData.userId,
        updates: Object.keys(updates)
      })

      return true
    } catch (error) {
      logger.error('Failed to update session', error, { sessionId })
      return false
    }
  }

  async destroySession(sessionId: string): Promise<void> {
    try {
      const sessionData = await this.getSession(sessionId, false)

      if (sessionData) {
        // Remove from user sessions
        if (sessionData.userId) {
          const userSessionsKey = `user:${sessionData.userId}:sessions`
          await this.sessionStore.srem(userSessionsKey, sessionId)
        }

        // Log session destruction
        await this.logSessionEvent(sessionId, 'destroyed', {
          userId: sessionData.userId
        })
      }

      // Remove session
      const sessionKey = `session:${sessionId}`
      await this.sessionStore.del(sessionKey)

      logger.info('Session destroyed', { sessionId })
    } catch (error) {
      logger.error('Failed to destroy session', error, { sessionId })
    }
  }

  async destroyAllUserSessions(userId: string, excludeSessionId?: string): Promise<void> {
    try {
      const userSessionsKey = `user:${userId}:sessions`
      const sessionIds = await this.sessionStore.smembers(userSessionsKey)

      const destroyPromises = sessionIds
        .filter(id => id !== excludeSessionId)
        .map(id => this.destroySession(id))

      await Promise.all(destroyPromises)

      // Publish session invalidation event
      await this.publishSessionInvalidation(userId, excludeSessionId)

      logger.info('All user sessions destroyed', {
        userId,
        excludeSessionId,
        destroyedCount: sessionIds.length - (excludeSessionId ? 1 : 0)
      })
    } catch (error) {
      logger.error('Failed to destroy all user sessions', error, { userId })
    }
  }

  async getUserSessions(userId: string): Promise<Array<{ sessionId: string; data: SessionData }>> {
    try {
      const userSessionsKey = `user:${userId}:sessions`
      const sessionIds = await this.sessionStore.smembers(userSessionsKey)

      const sessions = await Promise.all(
        sessionIds.map(async (sessionId) => {
          const data = await this.getSession(sessionId, false)
          return data ? { sessionId, data } : null
        })
      )

      return sessions.filter(session => session !== null) as Array<{ sessionId: string; data: SessionData }>
    } catch (error) {
      logger.error('Failed to get user sessions', error, { userId })
      return []
    }
  }

  private async enforceConcurrentSessionLimits(userId: string, maxSessions: number): Promise<void> {
    const sessions = await this.getUserSessions(userId)

    if (sessions.length >= maxSessions) {
      // Sort by last activity and remove oldest sessions
      sessions.sort((a, b) => a.data.lastActivity - b.data.lastActivity)

      const sessionsToRemove = sessions.slice(0, sessions.length - maxSessions + 1)

      for (const session of sessionsToRemove) {
        await this.destroySession(session.sessionId)
      }

      logger.info('Enforced concurrent session limits', {
        userId,
        maxSessions,
        removedSessions: sessionsToRemove.length
      })
    }
  }

  private async trackDeviceFingerprint(userId: string, fingerprint: string, sessionId: string): Promise<void> {
    const deviceKey = `user:${userId}:devices:${fingerprint}`
    const deviceData = {
      fingerprint,
      firstSeen: Date.now(),
      lastSeen: Date.now(),
      sessionCount: 1,
      currentSessionId: sessionId
    }

    const existingDevice = await this.userStore.get(deviceKey)
    if (existingDevice) {
      const existing = JSON.parse(existingDevice)
      deviceData.firstSeen = existing.firstSeen
      deviceData.sessionCount = existing.sessionCount + 1
    }

    await this.userStore.setex(deviceKey, 365 * 24 * 60 * 60, JSON.stringify(deviceData)) // 1 year
  }

  private async generateJWT(sessionId: string, userId: string, maxAge: number): Promise<string> {
    const payload: JWTPayload = {
      sessionId,
      userId,
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor((Date.now() + maxAge * 1000) / 1000)
    }

    // This is a simplified JWT generation - in production, use a proper JWT library
    const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url')
    const payloadEncoded = Buffer.from(JSON.stringify(payload)).toString('base64url')
    const signature = crypto
      .createHmac('sha256', this.jwtSecret)
      .update(`${header}.${payloadEncoded}`)
      .digest('base64url')

    return `${header}.${payloadEncoded}.${signature}`
  }

  async validateJWT(token: string): Promise<{ sessionId: string; userId: string } | null> {
    try {
      const [header, payload, signature] = token.split('.')

      // Verify signature
      const expectedSignature = crypto
        .createHmac('sha256', this.jwtSecret)
        .update(`${header}.${payload}`)
        .digest('base64url')

      if (signature !== expectedSignature) {
        return null
      }

      const decodedPayload = JSON.parse(Buffer.from(payload, 'base64url').toString())

      // Check expiration
      if (decodedPayload.exp < Math.floor(Date.now() / 1000)) {
        return null
      }

      return {
        sessionId: decodedPayload.sessionId,
        userId: decodedPayload.userId
      }
    } catch (error) {
      logger.error('JWT validation failed', error)
      return null
    }
  }

  private async publishSessionInvalidation(userId: string, excludeSessionId?: string): Promise<void> {
    const message = JSON.stringify({
      type: 'session_invalidation',
      userId,
      excludeSessionId,
      timestamp: Date.now()
    })

    await this.sessionStore.publish('auth:session_invalidation', message)
  }

  private async logSessionEvent(
    sessionId: string,
    event: string,
    metadata: Record<string, any>
  ): Promise<void> {
    const logEntry = {
      sessionId,
      event,
      timestamp: Date.now(),
      metadata
    }

    const logKey = `session_log:${sessionId}:${Date.now()}`
    await this.auditStore.setex(logKey, 90 * 24 * 60 * 60, JSON.stringify(logEntry)) // 90 days
  }

  async addLoginHistory(
    userId: string,
    entry: Omit<LoginHistoryEntry, 'timestamp'>
  ): Promise<void> {
    const historyEntry: LoginHistoryEntry = {
      ...entry,
      timestamp: Date.now()
    }

    const historyKey = `user:${userId}:login_history`
    await this.userStore.lpush(historyKey, JSON.stringify(historyEntry))
    await this.userStore.ltrim(historyKey, 0, 99) // Keep last 100 entries
    await this.userStore.expire(historyKey, 365 * 24 * 60 * 60) // 1 year
  }

  async getLoginHistory(userId: string, limit = 20): Promise<LoginHistoryEntry[]> {
    try {
      const historyKey = `user:${userId}:login_history`
      const entries = await this.userStore.lrange(historyKey, 0, limit - 1)

      return entries.map(entry => JSON.parse(entry))
    } catch (error) {
      logger.error('Failed to get login history', error, { userId })
      return []
    }
  }

  async detectSuspiciousActivity(userId: string, newEntry: Partial<LoginHistoryEntry>): Promise<{
    suspicious: boolean
    reasons: string[]
    riskScore: number
  }> {
    const history = await this.getLoginHistory(userId, 10)
    const reasons: string[] = []
    let riskScore = 0

    // Geographic anomaly detection
    if (history.length > 0) {
      const lastEntry = history[0]
      if (lastEntry.geographic.country && newEntry.geographic?.country) {
        if (lastEntry.geographic.country !== newEntry.geographic.country) {
          const timeDiff = Date.now() - lastEntry.timestamp
          if (timeDiff < 60 * 60 * 1000) { // Less than 1 hour
            reasons.push('Geographic anomaly: country change within 1 hour')
            riskScore += 30
          }
        }
      }
    }

    // Device fingerprint changes
    const recentFingerprints = history.slice(0, 5).map(h => h.deviceFingerprint)
    if (newEntry.deviceFingerprint && !recentFingerprints.includes(newEntry.deviceFingerprint)) {
      reasons.push('New device fingerprint')
      riskScore += 20
    }

    // IP address anomalies
    const recentIPs = history.slice(0, 3).map(h => h.ipAddress)
    if (newEntry.ipAddress && !recentIPs.includes(newEntry.ipAddress)) {
      reasons.push('New IP address')
      riskScore += 15
    }

    // Time-based anomalies (unusual login hours)
    const currentHour = new Date().getHours()
    const userHours = history.map(h => new Date(h.timestamp).getHours())
    const avgHour = userHours.reduce((a, b) => a + b, 0) / userHours.length

    if (Math.abs(currentHour - avgHour) > 6 && userHours.length > 5) {
      reasons.push('Unusual login time')
      riskScore += 10
    }

    // Recent failed attempts
    const recentFailures = history.filter(h =>
      !h.success && (Date.now() - h.timestamp) < 60 * 60 * 1000
    ).length

    if (recentFailures > 2) {
      reasons.push('Multiple recent failed attempts')
      riskScore += 25
    }

    return {
      suspicious: riskScore > 30,
      reasons,
      riskScore
    }
  }

  // Session cleanup job
  async cleanupExpiredSessions(): Promise<{ cleaned: number; errors: number }> {
    let cleaned = 0
    let errors = 0

    try {
      const pattern = 'session:*'
      const keys = await this.sessionStore.keys(pattern)

      for (const key of keys) {
        try {
          const sessionString = await this.sessionStore.get(key)
          if (!sessionString) {
            continue
          }

          const sessionWrapper = JSON.parse(sessionString)
          const { lastAccess, config } = sessionWrapper

          const now = Date.now()
          const isExpired = config.slidingWindow
            ? (now - lastAccess) > (config.slidingWindowDuration * 1000)
            : (now - lastAccess) > (config.maxAge * 1000)

          if (isExpired) {
            const sessionId = key.replace('session:', '')
            await this.destroySession(sessionId)
            cleaned++
          }
        } catch (error) {
          logger.error('Error cleaning session', error, { key })
          errors++
        }
      }

      logger.info('Session cleanup completed', { cleaned, errors })
    } catch (error) {
      logger.error('Session cleanup failed', error)
      errors++
    }

    return { cleaned, errors }
  }
}

// Singleton instance
export const sessionManager = new EnhancedSessionManager()