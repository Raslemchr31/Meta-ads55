import { webSocketManager, NotificationPayload } from './websocket-manager'
import { redisManager, RedisDatabase } from '@/lib/redis-manager'
import { logger } from '@/lib/logger'

export type NotificationType =
  | 'campaign_performance_alert'
  | 'budget_threshold_warning'
  | 'optimization_suggestion'
  | 'account_limit_reached'
  | 'system_maintenance'
  | 'collaboration_invite'
  | 'report_ready'
  | 'bid_adjustment_success'
  | 'campaign_approval_needed'
  | 'audience_insights_available'

export interface NotificationTemplate {
  type: NotificationType
  title: string
  messageTemplate: string
  defaultPriority: 'low' | 'medium' | 'high' | 'critical'
  channels: ('websocket' | 'email' | 'sms' | 'push')[]
  persistDuration: number // in seconds
}

export interface NotificationRule {
  id: string
  name: string
  description: string
  conditions: {
    field: string
    operator: 'gt' | 'lt' | 'eq' | 'gte' | 'lte' | 'contains' | 'not_contains'
    value: any
    logicalOperator?: 'AND' | 'OR'
  }[]
  notificationType: NotificationType
  targetUsers: string[]
  customMessage?: string
  enabled: boolean
  cooldownPeriod: number // prevent spam, in seconds
  escalationRules?: {
    timeThreshold: number
    escalateTo: string[]
    escalationMessage: string
  }
}

export interface NotificationPreferences {
  userId: string
  emailEnabled: boolean
  pushEnabled: boolean
  smsEnabled: boolean
  websocketEnabled: boolean
  quietHours: {
    start: string // HH:MM format
    end: string
    timezone: string
  }
  typePreferences: Record<NotificationType, {
    enabled: boolean
    priority: 'low' | 'medium' | 'high' | 'critical'
    channels: ('websocket' | 'email' | 'sms' | 'push')[]
  }>
}

export class NotificationSystem {
  private templates: Map<NotificationType, NotificationTemplate> = new Map()
  private activeRules: Map<string, NotificationRule> = new Map()
  private recentNotifications: Map<string, number> = new Map() // For cooldown tracking

  constructor() {
    this.initializeTemplates()
  }

  private initializeTemplates(): void {
    const templates: NotificationTemplate[] = [
      {
        type: 'campaign_performance_alert',
        title: 'Campaign Performance Alert',
        messageTemplate: 'Campaign "{campaignName}" has {metric} of {value}, which is {threshold}% {direction} than expected.',
        defaultPriority: 'high',
        channels: ['websocket', 'email'],
        persistDuration: 86400 // 24 hours
      },
      {
        type: 'budget_threshold_warning',
        title: 'Budget Threshold Warning',
        messageTemplate: 'Campaign "{campaignName}" has spent {spentAmount} of {budgetAmount} ({percentage}% of budget).',
        defaultPriority: 'medium',
        channels: ['websocket', 'email'],
        persistDuration: 43200 // 12 hours
      },
      {
        type: 'optimization_suggestion',
        title: 'Optimization Suggestion Available',
        messageTemplate: 'New optimization suggestion available for "{entityName}": {suggestion}',
        defaultPriority: 'medium',
        channels: ['websocket'],
        persistDuration: 86400 // 24 hours
      },
      {
        type: 'account_limit_reached',
        title: 'Account Limit Reached',
        messageTemplate: 'Account limit reached for {limitType}. Current usage: {currentUsage}/{limit}.',
        defaultPriority: 'critical',
        channels: ['websocket', 'email', 'sms'],
        persistDuration: 172800 // 48 hours
      },
      {
        type: 'system_maintenance',
        title: 'System Maintenance Notification',
        messageTemplate: 'Scheduled maintenance: {maintenanceDetails}. Expected duration: {duration}.',
        defaultPriority: 'medium',
        channels: ['websocket', 'email'],
        persistDuration: 259200 // 72 hours
      },
      {
        type: 'collaboration_invite',
        title: 'Collaboration Invitation',
        messageTemplate: '{inviterName} has invited you to collaborate on "{entityName}".',
        defaultPriority: 'medium',
        channels: ['websocket', 'email'],
        persistDuration: 604800 // 7 days
      },
      {
        type: 'report_ready',
        title: 'Report Ready for Download',
        messageTemplate: 'Your requested report "{reportName}" is ready for download.',
        defaultPriority: 'low',
        channels: ['websocket', 'email'],
        persistDuration: 86400 // 24 hours
      },
      {
        type: 'bid_adjustment_success',
        title: 'Bid Adjustment Applied',
        messageTemplate: 'Automatic bid adjustment applied to "{adSetName}". New bid: {newBid} (was {oldBid}).',
        defaultPriority: 'low',
        channels: ['websocket'],
        persistDuration: 43200 // 12 hours
      },
      {
        type: 'campaign_approval_needed',
        title: 'Campaign Approval Required',
        messageTemplate: 'Campaign "{campaignName}" requires approval before it can go live.',
        defaultPriority: 'high',
        channels: ['websocket', 'email'],
        persistDuration: 172800 // 48 hours
      },
      {
        type: 'audience_insights_available',
        title: 'New Audience Insights Available',
        messageTemplate: 'New audience insights are available for "{audienceName}". {insightSummary}',
        defaultPriority: 'medium',
        channels: ['websocket'],
        persistDuration: 86400 // 24 hours
      }
    ]

    templates.forEach(template => {
      this.templates.set(template.type, template)
    })
  }

  async sendNotification(
    type: NotificationType,
    targetUsers: string[],
    data: Record<string, any>,
    options?: {
      priority?: 'low' | 'medium' | 'high' | 'critical'
      customMessage?: string
      customTitle?: string
      channels?: ('websocket' | 'email' | 'sms' | 'push')[]
      expiresAt?: string
      metadata?: any
    }
  ): Promise<boolean> {
    try {
      const template = this.templates.get(type)
      if (!template) {
        logger.error('Unknown notification type', { type })
        return false
      }

      // Check cooldown
      const cooldownKey = `${type}:${JSON.stringify(data)}`
      if (this.isInCooldown(cooldownKey)) {
        logger.debug('Notification skipped due to cooldown', { type, data })
        return false
      }

      // Process each target user
      const processedUsers = await this.processTargetUsers(targetUsers, type)

      if (processedUsers.length === 0) {
        logger.debug('No eligible users for notification', { type, targetUsers })
        return false
      }

      // Build notification payload
      const title = options?.customTitle || template.title
      const message = options?.customMessage || this.interpolateTemplate(template.messageTemplate, data)
      const priority = options?.priority || template.defaultPriority

      const notification: NotificationPayload = {
        type,
        title,
        message,
        priority,
        data,
        targetUsers: processedUsers,
        expiresAt: options?.expiresAt || new Date(Date.now() + template.persistDuration * 1000).toISOString()
      }

      // Send via WebSocket
      await webSocketManager.sendNotification(notification)

      // Send via other channels if specified
      const channels = options?.channels || template.channels
      await this.sendToOtherChannels(notification, channels, processedUsers)

      // Store notification for persistence and tracking
      await this.storeNotification(notification)

      // Set cooldown
      this.setCooldown(cooldownKey, 60) // 1 minute default cooldown

      logger.info('Notification sent successfully', {
        type,
        targetUsers: processedUsers,
        priority,
        channels
      })

      return true

    } catch (error) {
      logger.error('Failed to send notification', {
        type,
        targetUsers,
        error: error instanceof Error ? error.message : 'Unknown error'
      })
      return false
    }
  }

  async createNotificationRule(rule: NotificationRule): Promise<boolean> {
    try {
      // Validate rule conditions
      if (!this.validateRuleConditions(rule.conditions)) {
        logger.error('Invalid rule conditions', { ruleId: rule.id })
        return false
      }

      // Store rule
      this.activeRules.set(rule.id, rule)

      // Persist to Redis
      const client = redisManager.getConnection(RedisDatabase.CACHE)
      await client.hset(
        'notification:rules',
        rule.id,
        JSON.stringify(rule)
      )

      logger.info('Notification rule created', { ruleId: rule.id, name: rule.name })
      return true

    } catch (error) {
      logger.error('Failed to create notification rule', {
        ruleId: rule.id,
        error: error instanceof Error ? error.message : 'Unknown error'
      })
      return false
    }
  }

  async evaluateRules(eventData: any): Promise<void> {
    try {
      for (const [ruleId, rule] of this.activeRules) {
        if (!rule.enabled) continue

        // Check cooldown for this rule
        const ruleCooldownKey = `rule:${ruleId}`
        if (this.isInCooldown(ruleCooldownKey)) {
          continue
        }

        // Evaluate conditions
        if (this.evaluateConditions(rule.conditions, eventData)) {
          // Send notification
          await this.sendNotification(
            rule.notificationType,
            rule.targetUsers,
            eventData,
            {
              customMessage: rule.customMessage
            }
          )

          // Set rule cooldown
          this.setCooldown(ruleCooldownKey, rule.cooldownPeriod)

          // Handle escalation if configured
          if (rule.escalationRules) {
            await this.scheduleEscalation(rule, eventData)
          }

          logger.info('Notification rule triggered', {
            ruleId,
            ruleName: rule.name,
            eventData
          })
        }
      }

    } catch (error) {
      logger.error('Failed to evaluate notification rules', {
        error: error instanceof Error ? error.message : 'Unknown error'
      })
    }
  }

  async getUserNotificationPreferences(userId: string): Promise<NotificationPreferences | null> {
    try {
      const client = redisManager.getConnection(RedisDatabase.CACHE)
      const prefsData = await client.hget('notification:preferences', userId)

      return prefsData ? JSON.parse(prefsData) : null

    } catch (error) {
      logger.error('Failed to get user notification preferences', {
        userId,
        error: error instanceof Error ? error.message : 'Unknown error'
      })
      return null
    }
  }

  async updateUserNotificationPreferences(
    userId: string,
    preferences: Partial<NotificationPreferences>
  ): Promise<boolean> {
    try {
      const client = redisManager.getConnection(RedisDatabase.CACHE)

      // Get existing preferences
      const existingPrefs = await this.getUserNotificationPreferences(userId)

      // Merge with new preferences
      const updatedPrefs: NotificationPreferences = {
        userId,
        emailEnabled: true,
        pushEnabled: true,
        smsEnabled: false,
        websocketEnabled: true,
        quietHours: {
          start: '22:00',
          end: '08:00',
          timezone: 'UTC'
        },
        typePreferences: {} as any,
        ...existingPrefs,
        ...preferences
      }

      // Store updated preferences
      await client.hset(
        'notification:preferences',
        userId,
        JSON.stringify(updatedPrefs)
      )

      logger.info('User notification preferences updated', { userId })
      return true

    } catch (error) {
      logger.error('Failed to update user notification preferences', {
        userId,
        error: error instanceof Error ? error.message : 'Unknown error'
      })
      return false
    }
  }

  async getNotificationHistory(
    userId: string,
    limit: number = 50,
    offset: number = 0
  ): Promise<NotificationPayload[]> {
    try {
      const client = redisManager.getConnection(RedisDatabase.CACHE)

      const notifications = await client.lrange(
        `notification:history:${userId}`,
        offset,
        offset + limit - 1
      )

      return notifications.map(notification => JSON.parse(notification))

    } catch (error) {
      logger.error('Failed to get notification history', {
        userId,
        error: error instanceof Error ? error.message : 'Unknown error'
      })
      return []
    }
  }

  async markNotificationAsRead(userId: string, notificationId: string): Promise<boolean> {
    try {
      const client = redisManager.getConnection(RedisDatabase.CACHE)

      await client.sadd(`notification:read:${userId}`, notificationId)
      await client.expire(`notification:read:${userId}`, 30 * 24 * 60 * 60) // 30 days

      return true

    } catch (error) {
      logger.error('Failed to mark notification as read', {
        userId,
        notificationId,
        error: error instanceof Error ? error.message : 'Unknown error'
      })
      return false
    }
  }

  private async processTargetUsers(targetUsers: string[], type: NotificationType): Promise<string[]> {
    const eligibleUsers = []

    for (const userId of targetUsers) {
      const preferences = await this.getUserNotificationPreferences(userId)

      // Check if user has notifications enabled for this type
      if (preferences?.typePreferences[type]?.enabled === false) {
        continue
      }

      // Check quiet hours
      if (preferences && this.isInQuietHours(preferences.quietHours)) {
        continue
      }

      eligibleUsers.push(userId)
    }

    return eligibleUsers
  }

  private interpolateTemplate(template: string, data: Record<string, any>): string {
    let message = template

    for (const [key, value] of Object.entries(data)) {
      const placeholder = `{${key}}`
      message = message.replace(new RegExp(placeholder, 'g'), String(value))
    }

    return message
  }

  private async sendToOtherChannels(
    notification: NotificationPayload,
    channels: string[],
    targetUsers: string[]
  ): Promise<void> {
    // Email notifications
    if (channels.includes('email')) {
      await this.sendEmailNotifications(notification, targetUsers)
    }

    // SMS notifications
    if (channels.includes('sms')) {
      await this.sendSmsNotifications(notification, targetUsers)
    }

    // Push notifications
    if (channels.includes('push')) {
      await this.sendPushNotifications(notification, targetUsers)
    }
  }

  private async sendEmailNotifications(notification: NotificationPayload, targetUsers: string[]): Promise<void> {
    // Email sending logic would go here
    logger.debug('Email notifications would be sent', {
      notification: notification.title,
      targetUsers
    })
  }

  private async sendSmsNotifications(notification: NotificationPayload, targetUsers: string[]): Promise<void> {
    // SMS sending logic would go here
    logger.debug('SMS notifications would be sent', {
      notification: notification.title,
      targetUsers
    })
  }

  private async sendPushNotifications(notification: NotificationPayload, targetUsers: string[]): Promise<void> {
    // Push notification logic would go here
    logger.debug('Push notifications would be sent', {
      notification: notification.title,
      targetUsers
    })
  }

  private async storeNotification(notification: NotificationPayload): Promise<void> {
    try {
      const client = redisManager.getConnection(RedisDatabase.CACHE)

      // Store in user's notification history
      if (notification.targetUsers) {
        for (const userId of notification.targetUsers) {
          await client.lpush(
            `notification:history:${userId}`,
            JSON.stringify(notification)
          )
          await client.ltrim(`notification:history:${userId}`, 0, 199) // Keep last 200
          await client.expire(`notification:history:${userId}`, 30 * 24 * 60 * 60) // 30 days
        }
      }

      // Store in global notification log
      await client.lpush('notification:global:log', JSON.stringify({
        ...notification,
        sentAt: new Date().toISOString()
      }))
      await client.ltrim('notification:global:log', 0, 9999) // Keep last 10k
      await client.expire('notification:global:log', 90 * 24 * 60 * 60) // 90 days

    } catch (error) {
      logger.error('Failed to store notification', {
        error: error instanceof Error ? error.message : 'Unknown error'
      })
    }
  }

  private validateRuleConditions(conditions: any[]): boolean {
    // Basic validation - enhance as needed
    return conditions.every(condition =>
      condition.field &&
      condition.operator &&
      condition.value !== undefined
    )
  }

  private evaluateConditions(conditions: any[], eventData: any): boolean {
    // Simple condition evaluation - enhance for complex logic
    return conditions.every(condition => {
      const fieldValue = this.getNestedValue(eventData, condition.field)
      return this.evaluateCondition(fieldValue, condition.operator, condition.value)
    })
  }

  private evaluateCondition(fieldValue: any, operator: string, conditionValue: any): boolean {
    switch (operator) {
      case 'gt':
        return Number(fieldValue) > Number(conditionValue)
      case 'lt':
        return Number(fieldValue) < Number(conditionValue)
      case 'gte':
        return Number(fieldValue) >= Number(conditionValue)
      case 'lte':
        return Number(fieldValue) <= Number(conditionValue)
      case 'eq':
        return fieldValue === conditionValue
      case 'contains':
        return String(fieldValue).includes(String(conditionValue))
      case 'not_contains':
        return !String(fieldValue).includes(String(conditionValue))
      default:
        return false
    }
  }

  private getNestedValue(obj: any, path: string): any {
    return path.split('.').reduce((current, key) => current?.[key], obj)
  }

  private async scheduleEscalation(rule: NotificationRule, eventData: any): Promise<void> {
    if (!rule.escalationRules) return

    try {
      const client = redisManager.getConnection(RedisDatabase.JOBS)

      // Schedule escalation job
      const escalationJob = {
        type: 'escalation',
        ruleId: rule.id,
        eventData,
        escalationRules: rule.escalationRules,
        scheduledFor: Date.now() + rule.escalationRules.timeThreshold * 1000
      }

      await client.zadd(
        'escalation:schedule',
        escalationJob.scheduledFor,
        JSON.stringify(escalationJob)
      )

    } catch (error) {
      logger.error('Failed to schedule escalation', {
        ruleId: rule.id,
        error: error instanceof Error ? error.message : 'Unknown error'
      })
    }
  }

  private isInCooldown(key: string): boolean {
    const lastSent = this.recentNotifications.get(key)
    return lastSent ? (Date.now() - lastSent) < 60000 : false // Default 1 minute
  }

  private setCooldown(key: string, seconds: number): void {
    this.recentNotifications.set(key, Date.now())
    // Clean up old entries periodically
    setTimeout(() => {
      this.recentNotifications.delete(key)
    }, seconds * 1000)
  }

  private isInQuietHours(quietHours: { start: string; end: string; timezone: string }): boolean {
    try {
      const now = new Date()
      const userTime = new Date(now.toLocaleString("en-US", { timeZone: quietHours.timezone }))

      const [startHour, startMinute] = quietHours.start.split(':').map(Number)
      const [endHour, endMinute] = quietHours.end.split(':').map(Number)

      const currentMinutes = userTime.getHours() * 60 + userTime.getMinutes()
      const startMinutes = startHour * 60 + startMinute
      const endMinutes = endHour * 60 + endMinute

      if (startMinutes <= endMinutes) {
        // Same day quiet hours
        return currentMinutes >= startMinutes && currentMinutes <= endMinutes
      } else {
        // Quiet hours cross midnight
        return currentMinutes >= startMinutes || currentMinutes <= endMinutes
      }

    } catch (error) {
      // If timezone parsing fails, don't block notifications
      return false
    }
  }
}

export const notificationSystem = new NotificationSystem()