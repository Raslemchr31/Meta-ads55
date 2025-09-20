import { redisManager, RedisDatabase } from '@/lib/redis-manager'
import { logger } from '@/lib/logger'
import { webSocketManager } from '@/lib/realtime/websocket-manager'
import { timeSeriesManager } from '@/lib/data/time-series-manager'

export interface ThreatPattern {
  id: string
  name: string
  type: 'api_abuse' | 'login_anomaly' | 'data_access' | 'ddos' | 'suspicious_behavior'
  severity: 'low' | 'medium' | 'high' | 'critical'
  description: string
  conditions: {
    timeWindow: number // milliseconds
    threshold: number
    metric: string
    operator: '>' | '<' | '=' | '!=' | '>=' | '<='
  }[]
  actions: ('log' | 'alert' | 'block' | 'throttle' | 'escalate')[]
  enabled: boolean
}

export interface ThreatEvent {
  id: string
  timestamp: number
  type: string
  severity: 'low' | 'medium' | 'high' | 'critical'
  sourceIp: string
  userId?: string
  tenantId?: string
  pattern: string
  details: Record<string, any>
  resolved: boolean
  actions: string[]
}

export interface IpReputation {
  ip: string
  score: number // 0-100, lower is more suspicious
  categories: string[]
  lastSeen: number
  threatCount: number
  blockedUntil?: number
  whitelisted: boolean
  geolocation?: {
    country: string
    region: string
    city: string
  }
}

export interface AnomalyDetectionConfig {
  enabled: boolean
  sensitivity: 'low' | 'medium' | 'high'
  learningPeriod: number // days
  minDataPoints: number
  alertThreshold: number // standard deviations
}

export class ThreatDetectionSystem {
  private patterns: Map<string, ThreatPattern> = new Map()
  private ipReputations: Map<string, IpReputation> = new Map()
  private anomalyConfig: AnomalyDetectionConfig = {
    enabled: true,
    sensitivity: 'medium',
    learningPeriod: 30,
    minDataPoints: 100,
    alertThreshold: 2.5
  }

  async initialize(): Promise<void> {
    try {
      await this.loadThreatPatterns()
      await this.loadIpReputations()
      await this.startBackgroundMonitoring()

      logger.info('Threat detection system initialized', {
        patterns: this.patterns.size,
        ipReputations: this.ipReputations.size
      })
    } catch (error) {
      logger.error('Failed to initialize threat detection system', error)
      throw error
    }
  }

  // Real-time anomaly detection for API usage
  async detectApiAnomalies(
    userId: string,
    endpoint: string,
    method: string,
    ip: string,
    tenantId?: string
  ): Promise<ThreatEvent[]> {
    const events: ThreatEvent[] = []
    const client = redisManager.getConnection(RedisDatabase.ANALYTICS)

    try {
      // Check rate limiting anomalies
      const rateLimitKey = `api:rate:${userId}:${endpoint}`
      const currentCount = await client.incr(rateLimitKey)
      await client.expire(rateLimitKey, 60) // 1 minute window

      // Get baseline for this user/endpoint combination
      const baselineKey = `api:baseline:${userId}:${endpoint}`
      const baseline = await this.getApiBaseline(userId, endpoint)

      // Detect unusual request patterns
      if (currentCount > baseline.normal + (baseline.stdDev * this.anomalyConfig.alertThreshold)) {
        const threat = await this.createThreatEvent({
          type: 'api_abuse',
          severity: currentCount > baseline.normal + (baseline.stdDev * 3) ? 'critical' : 'high',
          sourceIp: ip,
          userId,
          tenantId,
          pattern: 'excessive_api_requests',
          details: {
            endpoint,
            method,
            currentCount,
            baseline: baseline.normal,
            threshold: baseline.normal + (baseline.stdDev * this.anomalyConfig.alertThreshold)
          }
        })
        events.push(threat)
      }

      // Check for unusual timing patterns
      const timingAnomaly = await this.detectTimingAnomalies(userId, endpoint)
      if (timingAnomaly) {
        events.push(timingAnomaly)
      }

      // Store API usage for baseline learning
      await timeSeriesManager.addDataPoint(`api:usage:${userId}:${endpoint}`, {
        timestamp: Date.now(),
        value: 1,
        metadata: { method, ip, tenantId }
      })

    } catch (error) {
      logger.error('Failed to detect API anomalies', error, { userId, endpoint })
    }

    return events
  }

  // IP reputation scoring and blocking
  async evaluateIpReputation(ip: string, userId?: string): Promise<IpReputation> {
    let reputation = this.ipReputations.get(ip)

    if (!reputation) {
      reputation = {
        ip,
        score: 80, // Start with neutral score
        categories: [],
        lastSeen: Date.now(),
        threatCount: 0,
        whitelisted: false
      }
    }

    // Update last seen
    reputation.lastSeen = Date.now()

    // Check against known threat databases
    await this.checkExternalThreatFeeds(reputation)

    // Analyze behavior patterns
    await this.analyzeBehaviorPatterns(reputation, userId)

    // Update geolocation if needed
    if (!reputation.geolocation) {
      reputation.geolocation = await this.getGeolocation(ip)
    }

    // Store updated reputation
    this.ipReputations.set(ip, reputation)
    await this.persistIpReputation(reputation)

    return reputation
  }

  // Suspicious behavior analysis
  async analyzeSuspiciousBehavior(
    userId: string,
    action: string,
    metadata: Record<string, any>
  ): Promise<ThreatEvent[]> {
    const events: ThreatEvent[] = []
    const client = redisManager.getConnection(RedisDatabase.ANALYTICS)

    try {
      // Check for unusual login times
      if (action === 'login') {
        const loginTime = new Date().getHours()
        const userLoginPattern = await this.getUserLoginPattern(userId)

        if (this.isUnusualTime(loginTime, userLoginPattern)) {
          events.push(await this.createThreatEvent({
            type: 'login_anomaly',
            severity: 'medium',
            sourceIp: metadata.ip,
            userId,
            tenantId: metadata.tenantId,
            pattern: 'unusual_login_time',
            details: { loginTime, userPattern: userLoginPattern }
          }))
        }
      }

      // Check for unusual data access patterns
      if (action === 'data_access') {
        const accessPattern = await this.analyzeDataAccessPattern(userId, metadata)
        if (accessPattern.suspicious) {
          events.push(await this.createThreatEvent({
            type: 'data_access',
            severity: accessPattern.severity,
            sourceIp: metadata.ip,
            userId,
            tenantId: metadata.tenantId,
            pattern: 'unusual_data_access',
            details: accessPattern
          }))
        }
      }

      // Check for impossible travel
      if (metadata.ip && metadata.location) {
        const travelAnomaly = await this.detectImpossibleTravel(userId, metadata.ip, metadata.location)
        if (travelAnomaly) {
          events.push(travelAnomaly)
        }
      }

    } catch (error) {
      logger.error('Failed to analyze suspicious behavior', error, { userId, action })
    }

    return events
  }

  // DDoS protection with rate limiting escalation
  async detectDDoSAttack(ip: string, endpoint: string): Promise<{
    isDDoS: boolean
    severity: 'low' | 'medium' | 'high' | 'critical'
    action: 'monitor' | 'throttle' | 'block' | 'blacklist'
    duration: number
  }> {
    const client = redisManager.getConnection(RedisDatabase.RATE_LIMITING)

    try {
      // Multi-tier rate limiting
      const windows = [
        { period: 60, limit: 100, tier: 'basic' },
        { period: 300, limit: 300, tier: 'moderate' },
        { period: 3600, limit: 1000, tier: 'aggressive' }
      ]

      for (const window of windows) {
        const key = `ddos:${ip}:${endpoint}:${window.period}`
        const count = await client.incr(key)
        await client.expire(key, window.period)

        if (count > window.limit) {
          const severity = this.calculateDDoSSeverity(count, window.limit)
          const action = this.determineDDoSAction(severity, window.tier)
          const duration = this.calculateBlockDuration(severity)

          // Execute blocking action if needed
          if (action === 'block' || action === 'blacklist') {
            await this.blockIp(ip, duration, action === 'blacklist')
          }

          // Create threat event
          await this.createThreatEvent({
            type: 'ddos',
            severity,
            sourceIp: ip,
            pattern: 'ddos_attack',
            details: {
              endpoint,
              requestCount: count,
              limit: window.limit,
              window: window.period,
              tier: window.tier
            }
          })

          return { isDDoS: true, severity, action, duration }
        }
      }

    } catch (error) {
      logger.error('Failed to detect DDoS attack', error, { ip, endpoint })
    }

    return { isDDoS: false, severity: 'low', action: 'monitor', duration: 0 }
  }

  // Pattern recognition for API abuse
  async detectAPIAbusePatterns(userId: string, requests: any[]): Promise<ThreatEvent[]> {
    const events: ThreatEvent[] = []

    try {
      // Sequential pattern detection
      const sequentialPattern = this.detectSequentialPatterns(requests)
      if (sequentialPattern.suspicious) {
        events.push(await this.createThreatEvent({
          type: 'api_abuse',
          severity: 'high',
          sourceIp: requests[0]?.ip,
          userId,
          pattern: 'sequential_api_abuse',
          details: sequentialPattern
        }))
      }

      // Burst pattern detection
      const burstPattern = this.detectBurstPatterns(requests)
      if (burstPattern.suspicious) {
        events.push(await this.createThreatEvent({
          type: 'api_abuse',
          severity: 'medium',
          sourceIp: requests[0]?.ip,
          userId,
          pattern: 'burst_api_abuse',
          details: burstPattern
        }))
      }

      // Scraping pattern detection
      const scrapingPattern = this.detectScrapingPatterns(requests)
      if (scrapingPattern.suspicious) {
        events.push(await this.createThreatEvent({
          type: 'api_abuse',
          severity: 'high',
          sourceIp: requests[0]?.ip,
          userId,
          pattern: 'data_scraping',
          details: scrapingPattern
        }))
      }

    } catch (error) {
      logger.error('Failed to detect API abuse patterns', error, { userId })
    }

    return events
  }

  // Automated threat response
  async respondToThreat(event: ThreatEvent): Promise<void> {
    try {
      const pattern = this.patterns.get(event.pattern)
      if (!pattern) return

      for (const action of pattern.actions) {
        switch (action) {
          case 'log':
            logger.warn('Security threat detected', { event })
            break

          case 'alert':
            await this.sendSecurityAlert(event)
            break

          case 'block':
            if (event.sourceIp) {
              await this.blockIp(event.sourceIp, this.calculateBlockDuration(event.severity))
            }
            if (event.userId) {
              await this.blockUser(event.userId, this.calculateBlockDuration(event.severity))
            }
            break

          case 'throttle':
            if (event.sourceIp) {
              await this.throttleIp(event.sourceIp, event.severity)
            }
            break

          case 'escalate':
            await this.escalateThreat(event)
            break
        }
      }

      // Send real-time notification
      await webSocketManager.sendToRoom('security', 'threat_detected', {
        event,
        timestamp: new Date().toISOString()
      })

    } catch (error) {
      logger.error('Failed to respond to threat', error, { eventId: event.id })
    }
  }

  // Helper methods
  private async loadThreatPatterns(): Promise<void> {
    const client = redisManager.getConnection(RedisDatabase.CACHE)

    try {
      const patterns = await client.hgetall('security:patterns')
      for (const [id, data] of Object.entries(patterns)) {
        this.patterns.set(id, JSON.parse(data))
      }
    } catch (error) {
      // Load default patterns if none exist
      await this.loadDefaultPatterns()
    }
  }

  private async loadDefaultPatterns(): Promise<void> {
    const defaultPatterns: ThreatPattern[] = [
      {
        id: 'api_rate_limit_exceeded',
        name: 'API Rate Limit Exceeded',
        type: 'api_abuse',
        severity: 'high',
        description: 'User exceeded normal API usage patterns',
        conditions: [
          { timeWindow: 60000, threshold: 100, metric: 'requests_per_minute', operator: '>' }
        ],
        actions: ['log', 'alert', 'throttle'],
        enabled: true
      },
      {
        id: 'unusual_login_time',
        name: 'Unusual Login Time',
        type: 'login_anomaly',
        severity: 'medium',
        description: 'Login outside normal hours for user',
        conditions: [
          { timeWindow: 3600000, threshold: 2, metric: 'login_time_deviation', operator: '>' }
        ],
        actions: ['log', 'alert'],
        enabled: true
      },
      {
        id: 'ddos_attack',
        name: 'DDoS Attack Pattern',
        type: 'ddos',
        severity: 'critical',
        description: 'Distributed denial of service attack detected',
        conditions: [
          { timeWindow: 60000, threshold: 1000, metric: 'requests_per_minute_per_ip', operator: '>' }
        ],
        actions: ['log', 'alert', 'block', 'escalate'],
        enabled: true
      }
    ]

    for (const pattern of defaultPatterns) {
      this.patterns.set(pattern.id, pattern)
      await this.persistThreatPattern(pattern)
    }
  }

  private async getApiBaseline(userId: string, endpoint: string): Promise<{
    normal: number
    stdDev: number
    confidence: number
  }> {
    try {
      const data = await timeSeriesManager.getTimeSeries(`api:usage:${userId}:${endpoint}`, {
        start: Date.now() - (this.anomalyConfig.learningPeriod * 24 * 60 * 60 * 1000),
        end: Date.now(),
        aggregation: 'hourly'
      })

      if (data.length < this.anomalyConfig.minDataPoints) {
        return { normal: 10, stdDev: 5, confidence: 0.1 }
      }

      const values = data.map(point => point.value)
      const mean = values.reduce((sum, val) => sum + val, 0) / values.length
      const variance = values.reduce((sum, val) => sum + Math.pow(val - mean, 2), 0) / values.length
      const stdDev = Math.sqrt(variance)
      const confidence = Math.min(data.length / this.anomalyConfig.minDataPoints, 1)

      return { normal: mean, stdDev, confidence }
    } catch (error) {
      logger.error('Failed to get API baseline', error, { userId, endpoint })
      return { normal: 10, stdDev: 5, confidence: 0.1 }
    }
  }

  private async createThreatEvent(eventData: {
    type: string
    severity: 'low' | 'medium' | 'high' | 'critical'
    sourceIp: string
    userId?: string
    tenantId?: string
    pattern: string
    details: Record<string, any>
  }): Promise<ThreatEvent> {
    const event: ThreatEvent = {
      id: `threat_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      timestamp: Date.now(),
      ...eventData,
      resolved: false,
      actions: []
    }

    // Store threat event
    const client = redisManager.getConnection(RedisDatabase.ANALYTICS)
    await client.zadd('security:threats', event.timestamp, JSON.stringify(event))

    // Keep only last 10000 events
    await client.zremrangebyrank('security:threats', 0, -10001)

    // Respond to threat
    await this.respondToThreat(event)

    return event
  }

  private calculateDDoSSeverity(count: number, limit: number): 'low' | 'medium' | 'high' | 'critical' {
    const ratio = count / limit
    if (ratio > 10) return 'critical'
    if (ratio > 5) return 'high'
    if (ratio > 2) return 'medium'
    return 'low'
  }

  private determineDDoSAction(severity: string, tier: string): 'monitor' | 'throttle' | 'block' | 'blacklist' {
    if (severity === 'critical') return 'blacklist'
    if (severity === 'high') return 'block'
    if (severity === 'medium') return 'throttle'
    return 'monitor'
  }

  private calculateBlockDuration(severity: 'low' | 'medium' | 'high' | 'critical'): number {
    switch (severity) {
      case 'low': return 5 * 60 * 1000 // 5 minutes
      case 'medium': return 30 * 60 * 1000 // 30 minutes
      case 'high': return 2 * 60 * 60 * 1000 // 2 hours
      case 'critical': return 24 * 60 * 60 * 1000 // 24 hours
    }
  }

  private async blockIp(ip: string, duration: number, permanent = false): Promise<void> {
    const client = redisManager.getConnection(RedisDatabase.RATE_LIMITING)
    const key = `blocked:ip:${ip}`

    if (permanent) {
      await client.set(key, 'permanent')
    } else {
      await client.setex(key, Math.floor(duration / 1000), Date.now() + duration)
    }

    logger.warn('IP blocked', { ip, duration, permanent })
  }

  private async blockUser(userId: string, duration: number): Promise<void> {
    const client = redisManager.getConnection(RedisDatabase.RATE_LIMITING)
    const key = `blocked:user:${userId}`

    await client.setex(key, Math.floor(duration / 1000), Date.now() + duration)
    logger.warn('User blocked', { userId, duration })
  }

  private async throttleIp(ip: string, severity: 'low' | 'medium' | 'high' | 'critical'): Promise<void> {
    const client = redisManager.getConnection(RedisDatabase.RATE_LIMITING)
    const limits = {
      low: 50,
      medium: 25,
      high: 10,
      critical: 5
    }

    const key = `throttle:ip:${ip}`
    await client.setex(key, 3600, limits[severity]) // 1 hour throttling

    logger.info('IP throttled', { ip, severity, limit: limits[severity] })
  }

  private async sendSecurityAlert(event: ThreatEvent): Promise<void> {
    // Implementation would integrate with alerting system
    logger.warn('Security alert triggered', { event })
  }

  private async escalateThreat(event: ThreatEvent): Promise<void> {
    // Implementation would integrate with incident response system
    logger.error('Threat escalated', { event })
  }

  private async persistThreatPattern(pattern: ThreatPattern): Promise<void> {
    const client = redisManager.getConnection(RedisDatabase.CACHE)
    await client.hset('security:patterns', pattern.id, JSON.stringify(pattern))
  }

  private async persistIpReputation(reputation: IpReputation): Promise<void> {
    const client = redisManager.getConnection(RedisDatabase.CACHE)
    await client.hset('security:ip_reputation', reputation.ip, JSON.stringify(reputation))
  }

  private async startBackgroundMonitoring(): Promise<void> {
    // Start periodic cleanup and analysis tasks
    setInterval(async () => {
      await this.cleanupExpiredThreats()
      await this.updateIpReputationScores()
    }, 5 * 60 * 1000) // Every 5 minutes
  }

  private async cleanupExpiredThreats(): Promise<void> {
    const client = redisManager.getConnection(RedisDatabase.ANALYTICS)
    const cutoff = Date.now() - (7 * 24 * 60 * 60 * 1000) // 7 days
    await client.zremrangebyscore('security:threats', 0, cutoff)
  }

  private async updateIpReputationScores(): Promise<void> {
    // Periodic reputation score updates based on behavior
    for (const [ip, reputation] of this.ipReputations) {
      // Decay scores over time for inactive IPs
      if (Date.now() - reputation.lastSeen > 24 * 60 * 60 * 1000) {
        reputation.score = Math.min(100, reputation.score + 1)
      }
    }
  }

  // Placeholder methods for external integrations
  private async checkExternalThreatFeeds(reputation: IpReputation): Promise<void> {
    // Integration with threat intelligence feeds
  }

  private async getGeolocation(ip: string): Promise<any> {
    // Integration with geolocation service
    return { country: 'Unknown', region: 'Unknown', city: 'Unknown' }
  }

  private async analyzeBehaviorPatterns(reputation: IpReputation, userId?: string): Promise<void> {
    // Analyze historical behavior patterns
  }

  private async detectTimingAnomalies(userId: string, endpoint: string): Promise<ThreatEvent | null> {
    // Detect unusual timing patterns
    return null
  }

  private async getUserLoginPattern(userId: string): Promise<any> {
    // Get user's historical login patterns
    return { normalHours: [9, 10, 11, 12, 13, 14, 15, 16, 17] }
  }

  private isUnusualTime(hour: number, pattern: any): boolean {
    return !pattern.normalHours.includes(hour)
  }

  private async analyzeDataAccessPattern(userId: string, metadata: any): Promise<any> {
    // Analyze data access patterns for anomalies
    return { suspicious: false, severity: 'low' }
  }

  private async detectImpossibleTravel(userId: string, ip: string, location: any): Promise<ThreatEvent | null> {
    // Detect impossible travel scenarios
    return null
  }

  private detectSequentialPatterns(requests: any[]): any {
    // Detect sequential API abuse patterns
    return { suspicious: false }
  }

  private detectBurstPatterns(requests: any[]): any {
    // Detect burst patterns in API requests
    return { suspicious: false }
  }

  private detectScrapingPatterns(requests: any[]): any {
    // Detect data scraping patterns
    return { suspicious: false }
  }

  private async loadIpReputations(): Promise<void> {
    const client = redisManager.getConnection(RedisDatabase.CACHE)
    try {
      const reputations = await client.hgetall('security:ip_reputation')
      for (const [ip, data] of Object.entries(reputations)) {
        this.ipReputations.set(ip, JSON.parse(data))
      }
    } catch (error) {
      logger.warn('No existing IP reputations found')
    }
  }
}

export const threatDetectionSystem = new ThreatDetectionSystem()