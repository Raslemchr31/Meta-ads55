import winston from 'winston'
import { databaseManager } from './database'

interface LogContext {
  userId?: string
  accountId?: string
  requestId?: string
  endpoint?: string
  method?: string
  userAgent?: string
  ipAddress?: string
  [key: string]: any
}

class Logger {
  private winston: winston.Logger
  private isDevelopment: boolean

  constructor() {
    this.isDevelopment = process.env.NODE_ENV === 'development'
    
    const logFormat = winston.format.combine(
      winston.format.timestamp(),
      winston.format.errors({ stack: true }),
      winston.format.json(),
      winston.format.printf(({ timestamp, level, message, ...meta }) => {
        return JSON.stringify({
          timestamp,
          level,
          message,
          ...meta,
        })
      })
    )

    this.winston = winston.createLogger({
      level: process.env.LOG_LEVEL || 'info',
      format: logFormat,
      defaultMeta: {
        service: 'meta-ads-platform',
        version: process.env.APP_VERSION || '1.0.0',
      },
      transports: [
        // Console transport for development
        new winston.transports.Console({
          format: this.isDevelopment
            ? winston.format.combine(
                winston.format.colorize(),
                winston.format.simple()
              )
            : logFormat,
        }),

        // File transports
        new winston.transports.File({
          filename: 'logs/error.log',
          level: 'error',
          maxsize: 5242880, // 5MB
          maxFiles: 5,
        }),
        new winston.transports.File({
          filename: 'logs/combined.log',
          maxsize: 5242880, // 5MB
          maxFiles: 5,
        }),
      ],
      exceptionHandlers: [
        new winston.transports.File({
          filename: 'logs/exceptions.log',
          maxsize: 5242880, // 5MB
          maxFiles: 3,
        }),
      ],
      rejectionHandlers: [
        new winston.transports.File({
          filename: 'logs/rejections.log',
          maxsize: 5242880, // 5MB
          maxFiles: 3,
        }),
      ],
    })
  }

  private async logToDatabase(level: string, message: string, context: LogContext = {}): Promise<void> {
    if (context.endpoint && context.method) {
      try {
        await databaseManager.logApiCall({
          endpoint: context.endpoint,
          method: context.method,
          status_code: context.statusCode,
          response_time_ms: context.responseTime,
          request_size_bytes: context.requestSize,
          response_size_bytes: context.responseSize,
          error_message: level === 'error' ? message : undefined,
          user_id: context.userId,
          ip_address: context.ipAddress,
          user_agent: context.userAgent,
        })
      } catch (error) {
        // Don't throw database logging errors to avoid infinite loops
        this.winston.error('Failed to log to database:', error)
      }
    }
  }

  info(message: string, context: LogContext = {}): void {
    this.winston.info(message, context)
    this.logToDatabase('info', message, context)
  }

  warn(message: string, context: LogContext = {}): void {
    this.winston.warn(message, context)
    this.logToDatabase('warn', message, context)
  }

  error(message: string, error?: Error | any, context: LogContext = {}): void {
    const errorContext = {
      ...context,
      error: error instanceof Error ? {
        name: error.name,
        message: error.message,
        stack: error.stack,
      } : error,
    }
    
    this.winston.error(message, errorContext)
    this.logToDatabase('error', message, errorContext)
  }

  debug(message: string, context: LogContext = {}): void {
    this.winston.debug(message, context)
  }

  // Meta Ads specific logging methods
  logApiRequest(endpoint: string, method: string, context: LogContext = {}): string {
    const requestId = `req_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`
    
    this.info(`API Request: ${method} ${endpoint}`, {
      ...context,
      requestId,
      endpoint,
      method,
      type: 'api_request',
    })
    
    return requestId
  }

  logApiResponse(
    requestId: string,
    endpoint: string,
    method: string,
    statusCode: number,
    responseTime: number,
    context: LogContext = {}
  ): void {
    const level = statusCode >= 400 ? 'error' : statusCode >= 300 ? 'warn' : 'info'
    const message = `API Response: ${method} ${endpoint} - ${statusCode} (${responseTime}ms)`
    
    const responseContext = {
      ...context,
      requestId,
      endpoint,
      method,
      statusCode,
      responseTime,
      type: 'api_response',
    }

    if (level === 'error') {
      this.error(message, undefined, responseContext)
    } else if (level === 'warn') {
      this.warn(message, responseContext)
    } else {
      this.info(message, responseContext)
    }
  }

  logMetaApiCall(
    endpoint: string,
    method: string,
    accountId?: string,
    rateLimitRemaining?: number,
    context: LogContext = {}
  ): void {
    this.info(`Meta API Call: ${method} ${endpoint}`, {
      ...context,
      endpoint,
      method,
      accountId,
      rateLimitRemaining,
      type: 'meta_api_call',
    })
  }

  logRateLimitHit(endpoint: string, limit: number, context: LogContext = {}): void {
    this.warn(`Rate limit hit for ${endpoint} (limit: ${limit})`, {
      ...context,
      endpoint,
      limit,
      type: 'rate_limit_hit',
    })
  }

  logCacheHit(key: string, context: LogContext = {}): void {
    this.debug(`Cache hit: ${key}`, {
      ...context,
      cacheKey: key,
      type: 'cache_hit',
    })
  }

  logCacheMiss(key: string, context: LogContext = {}): void {
    this.debug(`Cache miss: ${key}`, {
      ...context,
      cacheKey: key,
      type: 'cache_miss',
    })
  }

  logDataSync(
    entityType: string,
    entityId: string,
    accountId: string,
    recordsProcessed: number,
    context: LogContext = {}
  ): void {
    this.info(`Data sync completed: ${entityType}/${entityId} (${recordsProcessed} records)`, {
      ...context,
      entityType,
      entityId,
      accountId,
      recordsProcessed,
      type: 'data_sync',
    })
  }

  logSystemUserTokenRefresh(success: boolean, error?: Error, context: LogContext = {}): void {
    if (success) {
      this.info('System User token refreshed successfully', {
        ...context,
        type: 'token_refresh',
        success: true,
      })
    } else {
      this.error('System User token refresh failed', error, {
        ...context,
        type: 'token_refresh',
        success: false,
      })
    }
  }

  logWebhookReceived(type: string, objectId: string, changes: any[], context: LogContext = {}): void {
    this.info(`Webhook received: ${type} for ${objectId}`, {
      ...context,
      webhookType: type,
      objectId,
      changes: changes.length,
      type: 'webhook_received',
    })
  }

  logPerformanceMetric(
    operation: string,
    duration: number,
    metadata: Record<string, any> = {},
    context: LogContext = {}
  ): void {
    this.info(`Performance: ${operation} completed in ${duration}ms`, {
      ...context,
      operation,
      duration,
      ...metadata,
      type: 'performance_metric',
    })
  }

  // Security logging
  logSecurityEvent(
    event: string,
    severity: 'low' | 'medium' | 'high' | 'critical',
    details: Record<string, any> = {},
    context: LogContext = {}
  ): void {
    const message = `Security Event: ${event} (${severity})`
    const securityContext = {
      ...context,
      securityEvent: event,
      severity,
      details,
      type: 'security_event',
    }

    if (severity === 'critical' || severity === 'high') {
      this.error(message, undefined, securityContext)
    } else if (severity === 'medium') {
      this.warn(message, securityContext)
    } else {
      this.info(message, securityContext)
    }
  }

  logAuthEvent(
    event: 'login' | 'logout' | 'token_refresh' | 'unauthorized_access',
    userId?: string,
    context: LogContext = {}
  ): void {
    this.info(`Auth Event: ${event}`, {
      ...context,
      authEvent: event,
      userId,
      type: 'auth_event',
    })
  }

  // Business logic logging
  logCampaignAction(
    action: string,
    campaignId: string,
    accountId: string,
    result: 'success' | 'failure',
    error?: Error,
    context: LogContext = {}
  ): void {
    const message = `Campaign ${action}: ${campaignId} - ${result}`
    const campaignContext = {
      ...context,
      action,
      campaignId,
      accountId,
      result,
      type: 'campaign_action',
    }

    if (result === 'failure') {
      this.error(message, error, campaignContext)
    } else {
      this.info(message, campaignContext)
    }
  }

  // Structured query for logs
  async queryLogs(filters: {
    level?: string
    type?: string
    startDate?: Date
    endDate?: Date
    userId?: string
    accountId?: string
    endpoint?: string
    limit?: number
  }): Promise<any[]> {
    // This would implement querying from the database log table
    // For now, return empty array as this would require complex query building
    return []
  }

  // Health check logging
  logHealthCheck(service: string, status: 'healthy' | 'unhealthy' | 'degraded', details?: any): void {
    const message = `Health Check: ${service} is ${status}`
    const healthContext = {
      service,
      status,
      details,
      type: 'health_check',
    }

    if (status === 'unhealthy') {
      this.error(message, undefined, healthContext)
    } else {
      this.info(message, healthContext)
    }
  }

  // Create child logger with persistent context
  child(context: LogContext): Logger {
    const childLogger = Object.create(this)
    const originalMethods = ['info', 'warn', 'error', 'debug']
    
    originalMethods.forEach(method => {
      childLogger[method] = (message: string, additionalContext: LogContext = {}) => {
        this[method](message, { ...context, ...additionalContext })
      }
    })
    
    return childLogger
  }
}

// Singleton instance
export const logger = new Logger()

// Export the Logger class for creating child loggers
export { Logger }

// Utility function to create request-specific logger
export function createRequestLogger(requestId: string, context: LogContext = {}): Logger {
  return logger.child({ requestId, ...context })
}