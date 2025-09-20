import { redisManager, RedisDatabase } from '../redis-manager'
import { logger } from '../logger'
import crypto from 'crypto'

interface RateLimitConfig {
  windowMs: number
  maxAttempts: number
  blockDuration: number
  progressiveDelays: number[]
}

interface SecurityThreat {
  id: string
  type: 'brute_force' | 'suspicious_activity' | 'geographic_anomaly' | 'rapid_requests' | 'credential_stuffing'
  severity: 'low' | 'medium' | 'high' | 'critical'
  userId?: string
  ipAddress: string
  userAgent: string
  timestamp: number
  metadata: Record<string, any>
  automated: boolean
}

interface LoginAttempt {
  timestamp: number
  success: boolean
  ipAddress: string
  userAgent: string
  failureReason?: string
  geographic?: {
    country?: string
    city?: string
  }
}

interface BlockedEntity {
  id: string
  type: 'ip' | 'user' | 'device'
  reason: string
  blockedAt: number
  expiresAt: number
  attempts: number
  severity: string
}

export class SecurityManager {
  private readonly rateLimitStore = redisManager.getRateLimitStore()
  private readonly auditStore = redisManager.getAnalyticsStore()
  private readonly userStore = redisManager.getUserPrefsStore()

  private readonly defaultRateLimits: Record<string, RateLimitConfig> = {
    login: {
      windowMs: 15 * 60 * 1000, // 15 minutes
      maxAttempts: 5,
      blockDuration: 60 * 60 * 1000, // 1 hour
      progressiveDelays: [60, 300, 900, 3600] // 1min, 5min, 15min, 1hr (in seconds)
    },
    api: {
      windowMs: 60 * 1000, // 1 minute
      maxAttempts: 100,
      blockDuration: 5 * 60 * 1000, // 5 minutes
      progressiveDelays: [60, 120, 300] // 1min, 2min, 5min
    },
    password_reset: {
      windowMs: 60 * 60 * 1000, // 1 hour
      maxAttempts: 3,
      blockDuration: 24 * 60 * 60 * 1000, // 24 hours
      progressiveDelays: [3600, 7200, 86400] // 1hr, 2hr, 24hr
    },
    registration: {
      windowMs: 60 * 60 * 1000, // 1 hour
      maxAttempts: 3,
      blockDuration: 24 * 60 * 60 * 1000, // 24 hours
      progressiveDelays: [3600] // 1hr
    }
  }

  async checkRateLimit(
    identifier: string,
    type: keyof typeof this.defaultRateLimits,
    customConfig?: Partial<RateLimitConfig>
  ): Promise<{
    allowed: boolean
    remaining: number
    resetTime: number
    retryAfter?: number
    blocked: boolean
  }> {
    const config = { ...this.defaultRateLimits[type], ...customConfig }
    const key = `rate_limit:${type}:${identifier}`
    const blockKey = `blocked:${type}:${identifier}`

    try {
      // Check if entity is currently blocked
      const blockData = await this.rateLimitStore.get(blockKey)
      if (blockData) {
        const block: BlockedEntity = JSON.parse(blockData)
        if (block.expiresAt > Date.now()) {
          return {
            allowed: false,
            remaining: 0,
            resetTime: block.expiresAt,
            retryAfter: Math.ceil((block.expiresAt - Date.now()) / 1000),
            blocked: true
          }
        } else {
          // Block expired, remove it
          await this.rateLimitStore.del(blockKey)
        }
      }

      // Get current attempt count
      const currentCount = await this.rateLimitStore.get(key)
      const count = currentCount ? parseInt(currentCount) : 0

      if (count >= config.maxAttempts) {
        // Create progressive block
        await this.createProgressiveBlock(identifier, type, count)

        return {
          allowed: false,
          remaining: 0,
          resetTime: Date.now() + config.blockDuration,
          retryAfter: Math.ceil(config.blockDuration / 1000),
          blocked: true
        }
      }

      // Increment counter
      const newCount = await this.rateLimitStore.incr(key)
      if (newCount === 1) {
        // Set expiration on first increment
        await this.rateLimitStore.expire(key, Math.ceil(config.windowMs / 1000))
      }

      const ttl = await this.rateLimitStore.ttl(key)
      const resetTime = Date.now() + (ttl * 1000)

      return {
        allowed: true,
        remaining: Math.max(0, config.maxAttempts - newCount),
        resetTime,
        blocked: false
      }
    } catch (error) {
      logger.error('Rate limit check failed', error, { identifier, type })
      // Fail open - allow request if Redis is down
      return {
        allowed: true,
        remaining: config.maxAttempts,
        resetTime: Date.now() + config.windowMs,
        blocked: false
      }
    }
  }

  private async createProgressiveBlock(
    identifier: string,
    type: keyof typeof this.defaultRateLimits,
    attemptCount: number
  ): Promise<void> {
    const config = this.defaultRateLimits[type]
    const blockKey = `blocked:${type}:${identifier}`
    const attemptsKey = `attempts:${type}:${identifier}`

    // Get previous attempt count for progressive delays
    const previousAttempts = await this.rateLimitStore.get(attemptsKey)
    const totalAttempts = previousAttempts ? parseInt(previousAttempts) + attemptCount : attemptCount

    // Calculate progressive delay
    const delayIndex = Math.min(
      Math.floor(totalAttempts / config.maxAttempts) - 1,
      config.progressiveDelays.length - 1
    )
    const delaySeconds = config.progressiveDelays[Math.max(0, delayIndex)]
    const blockDuration = delaySeconds * 1000

    const block: BlockedEntity = {
      id: crypto.randomUUID(),
      type: identifier.includes('.') ? 'ip' : 'user',
      reason: `Rate limit exceeded: ${attemptCount} attempts in ${config.windowMs}ms`,
      blockedAt: Date.now(),
      expiresAt: Date.now() + blockDuration,
      attempts: totalAttempts,
      severity: this.calculateSeverity(totalAttempts, delayIndex)
    }

    // Store block
    await this.rateLimitStore.setex(
      blockKey,
      Math.ceil(blockDuration / 1000),
      JSON.stringify(block)
    )

    // Update total attempts counter
    await this.rateLimitStore.setex(
      attemptsKey,
      7 * 24 * 60 * 60, // 7 days
      totalAttempts.toString()
    )

    // Log security event
    await this.logSecurityThreat({
      type: 'brute_force',
      severity: block.severity as any,
      ipAddress: identifier,
      userAgent: '',
      metadata: {
        attempts: totalAttempts,
        blockDuration: blockDuration / 1000,
        rateLimitType: type
      },
      automated: true
    })

    logger.warn('Progressive block created', {
      identifier,
      type,
      attempts: totalAttempts,
      blockDuration: blockDuration / 1000,
      severity: block.severity
    })
  }

  private calculateSeverity(attempts: number, delayIndex: number): string {
    if (attempts >= 50) return 'critical'
    if (attempts >= 20) return 'high'
    if (attempts >= 10) return 'medium'
    return 'low'
  }

  async recordLoginAttempt(
    identifier: string,
    attempt: LoginAttempt,
    userId?: string
  ): Promise<void> {
    const key = `login_attempts:${identifier}`

    // Store attempt
    await this.rateLimitStore.lpush(key, JSON.stringify(attempt))
    await this.rateLimitStore.ltrim(key, 0, 99) // Keep last 100 attempts
    await this.rateLimitStore.expire(key, 7 * 24 * 60 * 60) // 7 days

    // If user is known, also store in user-specific key
    if (userId) {
      const userKey = `user_login_attempts:${userId}`
      await this.rateLimitStore.lpush(userKey, JSON.stringify(attempt))
      await this.rateLimitStore.ltrim(userKey, 0, 99)
      await this.rateLimitStore.expire(userKey, 30 * 24 * 60 * 60) // 30 days
    }

    // Analyze for suspicious patterns
    if (!attempt.success) {
      await this.analyzeFailedAttempts(identifier, userId)
    }
  }

  private async analyzeFailedAttempts(identifier: string, userId?: string): Promise<void> {
    const key = `login_attempts:${identifier}`
    const attempts = await this.rateLimitStore.lrange(key, 0, 19) // Last 20 attempts

    if (attempts.length < 3) return

    const parsedAttempts: LoginAttempt[] = attempts.map(a => JSON.parse(a))
    const recentAttempts = parsedAttempts.filter(
      a => Date.now() - a.timestamp < 60 * 60 * 1000 // Last hour
    )

    // Check for rapid failed attempts
    const failedAttempts = recentAttempts.filter(a => !a.success)
    if (failedAttempts.length >= 3) {
      const timeSpan = failedAttempts[0].timestamp - failedAttempts[failedAttempts.length - 1].timestamp
      if (timeSpan < 5 * 60 * 1000) { // Within 5 minutes
        await this.logSecurityThreat({
          type: 'brute_force',
          severity: 'medium',
          userId,
          ipAddress: identifier,
          userAgent: failedAttempts[0].userAgent,
          metadata: {
            failedAttempts: failedAttempts.length,
            timeSpan: timeSpan / 1000,
            reasons: failedAttempts.map(a => a.failureReason)
          },
          automated: true
        })
      }
    }

    // Check for credential stuffing patterns
    const uniqueUserAgents = new Set(recentAttempts.map(a => a.userAgent))
    if (uniqueUserAgents.size === 1 && recentAttempts.length >= 5) {
      await this.logSecurityThreat({
        type: 'credential_stuffing',
        severity: 'high',
        userId,
        ipAddress: identifier,
        userAgent: recentAttempts[0].userAgent,
        metadata: {
          attempts: recentAttempts.length,
          sameUserAgent: true
        },
        automated: true
      })
    }
  }

  async checkGeographicAnomaly(
    userId: string,
    newLocation: { country?: string; city?: string; ip: string }
  ): Promise<{
    anomaly: boolean
    riskScore: number
    reason?: string
  }> {
    const historyKey = `user:${userId}:geo_history`
    const history = await this.userStore.lrange(historyKey, 0, 9) // Last 10 locations

    if (history.length === 0) {
      // First login, store location
      await this.storeGeographicData(userId, newLocation)
      return { anomaly: false, riskScore: 0 }
    }

    const recentLocations = history.map(h => JSON.parse(h))
    const lastLocation = recentLocations[0]

    // Check for country change within short time
    if (lastLocation.country && newLocation.country) {
      if (lastLocation.country !== newLocation.country) {
        const timeDiff = Date.now() - lastLocation.timestamp
        const hoursDiff = timeDiff / (60 * 60 * 1000)

        // Impossible travel detection
        if (hoursDiff < 1) {
          await this.logSecurityThreat({
            type: 'geographic_anomaly',
            severity: 'high',
            userId,
            ipAddress: newLocation.ip,
            userAgent: '',
            metadata: {
              previousCountry: lastLocation.country,
              newCountry: newLocation.country,
              timeDiff: hoursDiff,
              impossibleTravel: true
            },
            automated: true
          })

          return {
            anomaly: true,
            riskScore: 90,
            reason: 'Impossible travel detected: country change within 1 hour'
          }
        }

        // Suspicious travel (intercontinental within 6 hours)
        if (hoursDiff < 6 && this.isIntercontinental(lastLocation.country, newLocation.country)) {
          return {
            anomaly: true,
            riskScore: 70,
            reason: 'Suspicious travel: intercontinental movement within 6 hours'
          }
        }
      }
    }

    // Store current location
    await this.storeGeographicData(userId, newLocation)

    return { anomaly: false, riskScore: 0 }
  }

  private async storeGeographicData(
    userId: string,
    location: { country?: string; city?: string; ip: string }
  ): Promise<void> {
    const geoData = {
      ...location,
      timestamp: Date.now()
    }

    const historyKey = `user:${userId}:geo_history`
    await this.userStore.lpush(historyKey, JSON.stringify(geoData))
    await this.userStore.ltrim(historyKey, 0, 49) // Keep last 50 locations
    await this.userStore.expire(historyKey, 90 * 24 * 60 * 60) // 90 days
  }

  private isIntercontinental(country1: string, country2: string): boolean {
    // Simplified continent mapping - in production, use a proper GeoIP service
    const continents: Record<string, string> = {
      'US': 'NA', 'CA': 'NA', 'MX': 'NA',
      'BR': 'SA', 'AR': 'SA', 'CL': 'SA',
      'GB': 'EU', 'FR': 'EU', 'DE': 'EU', 'IT': 'EU', 'ES': 'EU',
      'CN': 'AS', 'JP': 'AS', 'IN': 'AS', 'KR': 'AS',
      'AU': 'OC', 'NZ': 'OC',
      'EG': 'AF', 'ZA': 'AF', 'NG': 'AF'
    }

    const continent1 = continents[country1]
    const continent2 = continents[country2]

    return continent1 && continent2 && continent1 !== continent2
  }

  async detectSuspiciousActivity(
    userId: string,
    ipAddress: string,
    userAgent: string,
    metadata: Record<string, any> = {}
  ): Promise<{
    suspicious: boolean
    threats: SecurityThreat[]
    actions: string[]
  }> {
    const threats: SecurityThreat[] = []
    const actions: string[] = []

    // Check for rapid requests from same IP
    const rapidRequests = await this.checkRapidRequests(ipAddress)
    if (rapidRequests.suspicious) {
      threats.push({
        id: crypto.randomUUID(),
        type: 'rapid_requests',
        severity: 'medium',
        userId,
        ipAddress,
        userAgent,
        timestamp: Date.now(),
        metadata: rapidRequests.data,
        automated: true
      })
      actions.push('rate_limit_ip')
    }

    // Check user agent anomalies
    const uaAnomaly = await this.checkUserAgentAnomaly(userId, userAgent)
    if (uaAnomaly.suspicious) {
      threats.push({
        id: crypto.randomUUID(),
        type: 'suspicious_activity',
        severity: 'low',
        userId,
        ipAddress,
        userAgent,
        timestamp: Date.now(),
        metadata: uaAnomaly.data,
        automated: true
      })
      actions.push('require_mfa')
    }

    // Check for bot-like behavior
    const botBehavior = await this.checkBotBehavior(ipAddress, userAgent)
    if (botBehavior.suspicious) {
      threats.push({
        id: crypto.randomUUID(),
        type: 'suspicious_activity',
        severity: 'high',
        userId,
        ipAddress,
        userAgent,
        timestamp: Date.now(),
        metadata: botBehavior.data,
        automated: true
      })
      actions.push('block_ip', 'require_captcha')
    }

    // Log all threats
    for (const threat of threats) {
      await this.logSecurityThreat(threat)
    }

    return {
      suspicious: threats.length > 0,
      threats,
      actions
    }
  }

  private async checkRapidRequests(ipAddress: string): Promise<{
    suspicious: boolean
    data: Record<string, any>
  }> {
    const key = `rapid_requests:${ipAddress}`
    const window = 60 * 1000 // 1 minute
    const threshold = 100 // requests per minute

    const count = await this.rateLimitStore.incr(key)
    if (count === 1) {
      await this.rateLimitStore.expire(key, 60)
    }

    return {
      suspicious: count > threshold,
      data: {
        requestCount: count,
        window: window / 1000,
        threshold
      }
    }
  }

  private async checkUserAgentAnomaly(userId: string, userAgent: string): Promise<{
    suspicious: boolean
    data: Record<string, any>
  }> {
    const historyKey = `user:${userId}:user_agents`
    const knownAgents = await this.userStore.smembers(historyKey)

    // Store current user agent
    await this.userStore.sadd(historyKey, userAgent)
    await this.userStore.expire(historyKey, 30 * 24 * 60 * 60) // 30 days

    // Check for suspicious user agent patterns
    const suspiciousPatterns = [
      /bot|crawler|spider|scraper/i,
      /python|curl|wget|powershell/i,
      /automated|script|tool/i
    ]

    const isSuspiciousUA = suspiciousPatterns.some(pattern => pattern.test(userAgent))
    const isNewUA = !knownAgents.includes(userAgent)

    return {
      suspicious: isSuspiciousUA || (isNewUA && knownAgents.length > 0),
      data: {
        userAgent,
        knownAgents: knownAgents.length,
        isNewUA,
        isSuspiciousUA
      }
    }
  }

  private async checkBotBehavior(ipAddress: string, userAgent: string): Promise<{
    suspicious: boolean
    data: Record<string, any>
  }> {
    // Check for known bot patterns
    const botPatterns = [
      /bot|crawler|spider|scraper|slurp/i,
      /python-requests|curl|wget|httpclient/i,
      /headless|phantom|selenium|puppeteer/i
    ]

    const isBotUA = botPatterns.some(pattern => pattern.test(userAgent))

    // Check for IP reputation
    const ipReputationKey = `ip_reputation:${ipAddress}`
    const reputation = await this.rateLimitStore.get(ipReputationKey)
    const badReputation = reputation && parseInt(reputation) < -10

    return {
      suspicious: isBotUA || badReputation,
      data: {
        userAgent,
        ipAddress,
        isBotUA,
        reputation: reputation ? parseInt(reputation) : 0
      }
    }
  }

  async blockEntity(
    identifier: string,
    type: 'ip' | 'user' | 'device',
    reason: string,
    duration: number,
    severity: 'low' | 'medium' | 'high' | 'critical' = 'medium'
  ): Promise<void> {
    const blockKey = `blocked:${type}:${identifier}`
    const block: BlockedEntity = {
      id: crypto.randomUUID(),
      type,
      reason,
      blockedAt: Date.now(),
      expiresAt: Date.now() + duration,
      attempts: 1,
      severity
    }

    await this.rateLimitStore.setex(
      blockKey,
      Math.ceil(duration / 1000),
      JSON.stringify(block)
    )

    logger.warn('Entity blocked', {
      identifier,
      type,
      reason,
      duration: duration / 1000,
      severity
    })
  }

  async isBlocked(identifier: string, type: 'ip' | 'user' | 'device'): Promise<{
    blocked: boolean
    reason?: string
    expiresAt?: number
  }> {
    const blockKey = `blocked:${type}:${identifier}`
    const blockData = await this.rateLimitStore.get(blockKey)

    if (!blockData) {
      return { blocked: false }
    }

    const block: BlockedEntity = JSON.parse(blockData)
    if (block.expiresAt <= Date.now()) {
      // Block expired, remove it
      await this.rateLimitStore.del(blockKey)
      return { blocked: false }
    }

    return {
      blocked: true,
      reason: block.reason,
      expiresAt: block.expiresAt
    }
  }

  async logSecurityThreat(threat: Omit<SecurityThreat, 'id' | 'timestamp'>): Promise<void> {
    const fullThreat: SecurityThreat = {
      id: crypto.randomUUID(),
      timestamp: Date.now(),
      ...threat
    }

    // Store in audit log
    const threatKey = `security_threat:${fullThreat.id}`
    await this.auditStore.setex(
      threatKey,
      90 * 24 * 60 * 60, // 90 days
      JSON.stringify(fullThreat)
    )

    // Add to threat timeline
    const timelineKey = `threat_timeline:${new Date().toISOString().slice(0, 10)}`
    await this.auditStore.lpush(timelineKey, fullThreat.id)
    await this.auditStore.expire(timelineKey, 90 * 24 * 60 * 60)

    // Update IP reputation if applicable
    if (threat.severity === 'high' || threat.severity === 'critical') {
      await this.updateIPReputation(threat.ipAddress, -5)
    }

    logger.logSecurityEvent(
      `Security threat detected: ${threat.type}`,
      threat.severity,
      {
        threatId: fullThreat.id,
        type: threat.type,
        userId: threat.userId,
        ipAddress: threat.ipAddress,
        automated: threat.automated
      }
    )
  }

  private async updateIPReputation(ipAddress: string, delta: number): Promise<void> {
    const reputationKey = `ip_reputation:${ipAddress}`
    const current = await this.rateLimitStore.get(reputationKey)
    const reputation = current ? parseInt(current) + delta : delta

    await this.rateLimitStore.setex(
      reputationKey,
      30 * 24 * 60 * 60, // 30 days
      reputation.toString()
    )
  }

  async getSecurityThreats(
    filters: {
      type?: SecurityThreat['type']
      severity?: SecurityThreat['severity']
      userId?: string
      ipAddress?: string
      timeRange?: { start: number; end: number }
    } = {},
    limit = 50
  ): Promise<SecurityThreat[]> {
    // This is a simplified implementation
    // In production, you might want to use a time-series database
    const threats: SecurityThreat[] = []

    // Get recent threat IDs
    const today = new Date().toISOString().slice(0, 10)
    const timelineKey = `threat_timeline:${today}`
    const threatIds = await this.auditStore.lrange(timelineKey, 0, limit - 1)

    for (const threatId of threatIds) {
      try {
        const threatKey = `security_threat:${threatId}`
        const threatData = await this.auditStore.get(threatKey)
        if (threatData) {
          const threat: SecurityThreat = JSON.parse(threatData)

          // Apply filters
          if (filters.type && threat.type !== filters.type) continue
          if (filters.severity && threat.severity !== filters.severity) continue
          if (filters.userId && threat.userId !== filters.userId) continue
          if (filters.ipAddress && threat.ipAddress !== filters.ipAddress) continue
          if (filters.timeRange) {
            if (threat.timestamp < filters.timeRange.start || threat.timestamp > filters.timeRange.end) continue
          }

          threats.push(threat)
        }
      } catch (error) {
        logger.error('Failed to parse security threat', error, { threatId })
      }
    }

    return threats.sort((a, b) => b.timestamp - a.timestamp)
  }

  // Cleanup expired blocks and threats
  async cleanupSecurityData(): Promise<{ cleaned: number; errors: number }> {
    let cleaned = 0
    let errors = 0

    try {
      // Clean expired blocks
      const blockPatterns = ['blocked:*', 'rate_limit:*', 'attempts:*']
      for (const pattern of blockPatterns) {
        const keys = await this.rateLimitStore.keys(pattern)
        for (const key of keys) {
          try {
            const ttl = await this.rateLimitStore.ttl(key)
            if (ttl === -1) {
              // Key without expiration, check if it should be cleaned
              await this.rateLimitStore.expire(key, 7 * 24 * 60 * 60) // 7 days default
            }
          } catch (error) {
            errors++
          }
        }
      }

      logger.info('Security data cleanup completed', { cleaned, errors })
    } catch (error) {
      logger.error('Security data cleanup failed', error)
      errors++
    }

    return { cleaned, errors }
  }
}

// Singleton instance
export const securityManager = new SecurityManager()