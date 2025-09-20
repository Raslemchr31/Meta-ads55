import { redisManager, RedisDatabase } from '@/lib/redis-manager'
import { logger } from '@/lib/logger'

export type AuditEventType =
  | 'login_success'
  | 'login_failed'
  | 'logout'
  | 'session_created'
  | 'session_terminated'
  | 'session_expired'
  | 'password_changed'
  | 'account_locked'
  | 'account_unlocked'
  | 'rate_limit_exceeded'
  | 'suspicious_activity'
  | 'security_violation'
  | 'meta_token_created'
  | 'meta_token_refreshed'
  | 'meta_token_expired'
  | 'api_access'
  | 'privilege_escalation'
  | 'data_access'
  | 'configuration_changed'

export type RiskLevel = 'low' | 'medium' | 'high' | 'critical'

export interface AuditEvent {
  eventId: string
  eventType: AuditEventType
  userId?: string
  sessionId?: string
  timestamp: string
  ipAddress: string
  userAgent: string
  riskLevel: RiskLevel
  details: Record<string, any>
  outcome: 'success' | 'failure' | 'blocked'
  source: string
  geolocation?: {
    country?: string
    region?: string
    city?: string
    timezone?: string
  }
}

export interface SecurityAlert {
  alertId: string
  eventIds: string[]
  alertType: string
  severity: 'low' | 'medium' | 'high' | 'critical'
  title: string
  description: string
  userId?: string
  triggeredAt: string
  status: 'open' | 'investigating' | 'resolved' | 'false_positive'
  assignedTo?: string
  metadata: Record<string, any>
}

export interface AuditQuery {
  userId?: string
  eventType?: AuditEventType | AuditEventType[]
  riskLevel?: RiskLevel | RiskLevel[]
  outcome?: 'success' | 'failure' | 'blocked'
  startTime?: string
  endTime?: string
  ipAddress?: string
  limit?: number
  offset?: number
}

export class AuditLogger {
  private readonly MAX_EVENTS_PER_USER = 10000
  private readonly RETENTION_DAYS = 90
  private readonly ALERT_THRESHOLD_MAP: Record<string, number> = {
    failed_login_attempts: 5,
    rate_limit_violations: 10,
    suspicious_locations: 3,
    concurrent_sessions: 5,
    privilege_escalations: 1
  }

  async logEvent(event: Omit<AuditEvent, 'eventId' | 'timestamp'>): Promise<string> {
    const eventId = this.generateEventId()
    const timestamp = new Date().toISOString()

    const auditEvent: AuditEvent = {
      eventId,
      timestamp,
      ...event
    }

    try {
      const client = redisManager.getConnection(RedisDatabase.ANALYTICS)

      // Store the audit event
      await client.hset(
        `audit:event:${eventId}`,
        {
          data: JSON.stringify(auditEvent),
          indexed: timestamp,
          userId: event.userId || 'anonymous',
          eventType: event.eventType,
          riskLevel: event.riskLevel,
          outcome: event.outcome
        }
      )

      // Set expiration based on retention policy
      await client.expire(`audit:event:${eventId}`, this.RETENTION_DAYS * 24 * 60 * 60)

      // Index by user
      if (event.userId) {
        await client.zadd(
          `audit:user:${event.userId}`,
          Date.now(),
          eventId
        )

        // Maintain user event count limit
        const userEventCount = await client.zcard(`audit:user:${event.userId}`)
        if (userEventCount > this.MAX_EVENTS_PER_USER) {
          const eventsToRemove = userEventCount - this.MAX_EVENTS_PER_USER
          const oldestEvents = await client.zrange(
            `audit:user:${event.userId}`,
            0,
            eventsToRemove - 1
          )

          // Remove oldest events
          for (const oldEventId of oldestEvents) {
            await client.del(`audit:event:${oldEventId}`)
          }

          await client.zremrangebyrank(
            `audit:user:${event.userId}`,
            0,
            eventsToRemove - 1
          )
        }

        await client.expire(
          `audit:user:${event.userId}`,
          this.RETENTION_DAYS * 24 * 60 * 60
        )
      }

      // Index by event type
      await client.zadd(
        `audit:type:${event.eventType}`,
        Date.now(),
        eventId
      )

      // Index by risk level
      await client.zadd(
        `audit:risk:${event.riskLevel}`,
        Date.now(),
        eventId
      )

      // Index by outcome
      await client.zadd(
        `audit:outcome:${event.outcome}`,
        Date.now(),
        eventId
      )

      // Index by IP address for security analysis
      await client.zadd(
        `audit:ip:${event.ipAddress}`,
        Date.now(),
        eventId
      )

      // Real-time security monitoring
      await this.checkSecurityAlerts(auditEvent)

      logger.info('Audit event logged', {
        eventId,
        eventType: event.eventType,
        userId: event.userId,
        riskLevel: event.riskLevel
      })

      return eventId

    } catch (error) {
      logger.error('Failed to log audit event', {
        error: error instanceof Error ? error.message : 'Unknown error',
        eventType: event.eventType,
        userId: event.userId
      })
      throw error
    }
  }

  async queryEvents(query: AuditQuery): Promise<{ events: AuditEvent[]; total: number }> {
    try {
      const client = redisManager.getConnection(RedisDatabase.ANALYTICS)
      const { limit = 50, offset = 0 } = query

      let eventIds: string[] = []

      if (query.userId) {
        // Query by user
        eventIds = await client.zrevrange(
          `audit:user:${query.userId}`,
          offset,
          offset + limit - 1
        )
      } else if (query.eventType) {
        // Query by event type
        const eventTypes = Array.isArray(query.eventType) ? query.eventType : [query.eventType]

        for (const eventType of eventTypes) {
          const typeEventIds = await client.zrevrange(
            `audit:type:${eventType}`,
            offset,
            offset + limit - 1
          )
          eventIds.push(...typeEventIds)
        }
      } else {
        // General query - get recent events
        const allKeys = await client.keys('audit:event:*')
        eventIds = allKeys
          .map(key => key.replace('audit:event:', ''))
          .sort((a, b) => b.localeCompare(a))
          .slice(offset, offset + limit)
      }

      // Apply additional filters
      const events: AuditEvent[] = []

      for (const eventId of eventIds) {
        const eventData = await client.hget(`audit:event:${eventId}`, 'data')
        if (!eventData) continue

        const event: AuditEvent = JSON.parse(eventData)

        // Apply filters
        if (query.riskLevel && !this.matchesRiskLevel(event.riskLevel, query.riskLevel)) {
          continue
        }

        if (query.outcome && event.outcome !== query.outcome) {
          continue
        }

        if (query.startTime && event.timestamp < query.startTime) {
          continue
        }

        if (query.endTime && event.timestamp > query.endTime) {
          continue
        }

        if (query.ipAddress && event.ipAddress !== query.ipAddress) {
          continue
        }

        events.push(event)

        if (events.length >= limit) {
          break
        }
      }

      return {
        events,
        total: eventIds.length
      }

    } catch (error) {
      logger.error('Failed to query audit events', {
        error: error instanceof Error ? error.message : 'Unknown error',
        query
      })
      throw error
    }
  }

  async createAlert(alert: Omit<SecurityAlert, 'alertId' | 'triggeredAt' | 'status'>): Promise<string> {
    const alertId = this.generateAlertId()
    const triggeredAt = new Date().toISOString()

    const securityAlert: SecurityAlert = {
      alertId,
      triggeredAt,
      status: 'open',
      ...alert
    }

    try {
      const client = redisManager.getConnection(RedisDatabase.ANALYTICS)

      // Store the alert
      await client.hset(
        `security:alert:${alertId}`,
        {
          data: JSON.stringify(securityAlert),
          severity: alert.severity,
          userId: alert.userId || 'system',
          triggeredAt,
          status: 'open'
        }
      )

      // Index by severity
      await client.zadd(
        `security:alerts:${alert.severity}`,
        Date.now(),
        alertId
      )

      // Index by user
      if (alert.userId) {
        await client.zadd(
          `security:user:alerts:${alert.userId}`,
          Date.now(),
          alertId
        )
      }

      // Add to active alerts
      await client.zadd(
        'security:alerts:active',
        Date.now(),
        alertId
      )

      logger.warn('Security alert created', {
        alertId,
        alertType: alert.alertType,
        severity: alert.severity,
        userId: alert.userId
      })

      // Send notifications for high/critical alerts
      if (alert.severity === 'high' || alert.severity === 'critical') {
        await this.sendSecurityNotification(securityAlert)
      }

      return alertId

    } catch (error) {
      logger.error('Failed to create security alert', {
        error: error instanceof Error ? error.message : 'Unknown error',
        alertType: alert.alertType
      })
      throw error
    }
  }

  async getSecurityDashboard(userId?: string): Promise<{
    recentEvents: AuditEvent[]
    activeAlerts: SecurityAlert[]
    riskSummary: Record<RiskLevel, number>
    eventTypeSummary: Record<AuditEventType, number>
    timelineData: Array<{ timestamp: string; eventCount: number; riskScore: number }>
  }> {
    try {
      // Get recent events
      const recentEventsQuery: AuditQuery = {
        userId,
        limit: 50,
        startTime: new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString()
      }
      const { events: recentEvents } = await this.queryEvents(recentEventsQuery)

      // Get active alerts
      const activeAlerts = await this.getActiveAlerts(userId)

      // Calculate risk summary
      const riskSummary: Record<RiskLevel, number> = {
        low: 0,
        medium: 0,
        high: 0,
        critical: 0
      }

      // Calculate event type summary
      const eventTypeSummary: Record<AuditEventType, number> = {} as any

      recentEvents.forEach(event => {
        riskSummary[event.riskLevel]++
        eventTypeSummary[event.eventType] = (eventTypeSummary[event.eventType] || 0) + 1
      })

      // Generate timeline data (last 24 hours, hourly buckets)
      const timelineData = await this.generateTimelineData(userId)

      return {
        recentEvents,
        activeAlerts,
        riskSummary,
        eventTypeSummary,
        timelineData
      }

    } catch (error) {
      logger.error('Failed to get security dashboard', {
        error: error instanceof Error ? error.message : 'Unknown error',
        userId
      })
      throw error
    }
  }

  private async checkSecurityAlerts(event: AuditEvent): Promise<void> {
    // Check for failed login patterns
    if (event.eventType === 'login_failed' && event.userId) {
      await this.checkFailedLoginPattern(event.userId, event.ipAddress)
    }

    // Check for suspicious activity patterns
    if (event.riskLevel === 'high' || event.riskLevel === 'critical') {
      await this.checkSuspiciousActivityPattern(event)
    }

    // Check for rate limit violations
    if (event.eventType === 'rate_limit_exceeded') {
      await this.checkRateLimitPattern(event.ipAddress)
    }

    // Check for geographic anomalies
    if (event.geolocation && event.userId) {
      await this.checkGeographicAnomaly(event.userId, event.geolocation)
    }
  }

  private async checkFailedLoginPattern(userId: string, ipAddress: string): Promise<void> {
    const client = redisManager.getConnection(RedisDatabase.ANALYTICS)
    const key = `security:failed_logins:${userId}`

    const failedCount = await client.incr(key)
    await client.expire(key, 3600) // 1 hour window

    if (failedCount >= this.ALERT_THRESHOLD_MAP.failed_login_attempts) {
      await this.createAlert({
        eventIds: [],
        alertType: 'brute_force_attack',
        severity: 'high',
        title: 'Multiple Failed Login Attempts',
        description: `User ${userId} has ${failedCount} failed login attempts from IP ${ipAddress}`,
        userId,
        metadata: { failedCount, ipAddress, timeWindow: '1 hour' }
      })
    }
  }

  private async checkSuspiciousActivityPattern(event: AuditEvent): Promise<void> {
    if (!event.userId) return

    await this.createAlert({
      eventIds: [event.eventId],
      alertType: 'suspicious_activity',
      severity: event.riskLevel === 'critical' ? 'critical' : 'high',
      title: 'Suspicious Activity Detected',
      description: `High-risk event detected: ${event.eventType}`,
      userId: event.userId,
      metadata: {
        eventType: event.eventType,
        riskLevel: event.riskLevel,
        ipAddress: event.ipAddress,
        details: event.details
      }
    })
  }

  private async checkRateLimitPattern(ipAddress: string): Promise<void> {
    const client = redisManager.getConnection(RedisDatabase.ANALYTICS)
    const key = `security:rate_violations:${ipAddress}`

    const violationCount = await client.incr(key)
    await client.expire(key, 3600) // 1 hour window

    if (violationCount >= this.ALERT_THRESHOLD_MAP.rate_limit_violations) {
      await this.createAlert({
        eventIds: [],
        alertType: 'rate_limit_abuse',
        severity: 'medium',
        title: 'Excessive Rate Limit Violations',
        description: `IP ${ipAddress} has exceeded rate limits ${violationCount} times`,
        metadata: { violationCount, ipAddress, timeWindow: '1 hour' }
      })
    }
  }

  private async checkGeographicAnomaly(userId: string, geolocation: any): Promise<void> {
    // Implementation for geographic anomaly detection
    // This would check against user's typical locations
  }

  private async getActiveAlerts(userId?: string): Promise<SecurityAlert[]> {
    const client = redisManager.getConnection(RedisDatabase.ANALYTICS)
    const alertIds = await client.zrevrange('security:alerts:active', 0, 20)

    const alerts: SecurityAlert[] = []

    for (const alertId of alertIds) {
      const alertData = await client.hget(`security:alert:${alertId}`, 'data')
      if (!alertData) continue

      const alert: SecurityAlert = JSON.parse(alertData)

      if (userId && alert.userId !== userId) {
        continue
      }

      if (alert.status === 'open' || alert.status === 'investigating') {
        alerts.push(alert)
      }
    }

    return alerts
  }

  private async generateTimelineData(userId?: string): Promise<Array<{ timestamp: string; eventCount: number; riskScore: number }>> {
    const now = new Date()
    const timelineData = []

    for (let i = 23; i >= 0; i--) {
      const timestamp = new Date(now.getTime() - i * 60 * 60 * 1000)
      const hourStart = new Date(timestamp)
      hourStart.setMinutes(0, 0, 0)
      const hourEnd = new Date(hourStart.getTime() + 60 * 60 * 1000)

      const query: AuditQuery = {
        userId,
        startTime: hourStart.toISOString(),
        endTime: hourEnd.toISOString(),
        limit: 1000
      }

      const { events } = await this.queryEvents(query)

      const eventCount = events.length
      const riskScore = this.calculateRiskScore(events)

      timelineData.push({
        timestamp: hourStart.toISOString(),
        eventCount,
        riskScore
      })
    }

    return timelineData
  }

  private calculateRiskScore(events: AuditEvent[]): number {
    if (events.length === 0) return 0

    const riskWeights = {
      low: 1,
      medium: 3,
      high: 7,
      critical: 10
    }

    const totalRisk = events.reduce((sum, event) =>
      sum + riskWeights[event.riskLevel], 0
    )

    return Math.min(100, (totalRisk / events.length) * 10)
  }

  private matchesRiskLevel(eventRisk: RiskLevel, queryRisk: RiskLevel | RiskLevel[]): boolean {
    if (Array.isArray(queryRisk)) {
      return queryRisk.includes(eventRisk)
    }
    return eventRisk === queryRisk
  }

  private async sendSecurityNotification(alert: SecurityAlert): Promise<void> {
    // Implementation for sending notifications (email, Slack, etc.)
    logger.warn('High-severity security alert', {
      alertId: alert.alertId,
      alertType: alert.alertType,
      severity: alert.severity,
      title: alert.title
    })
  }

  private generateEventId(): string {
    return `evt_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`
  }

  private generateAlertId(): string {
    return `alt_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`
  }
}

export const auditLogger = new AuditLogger()