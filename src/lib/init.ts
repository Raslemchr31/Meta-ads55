import { databaseManager } from './database'
import { cacheManager } from './cache'
import { dataSyncService } from './sync-service'
import { logger } from './logger'

interface InitializationResult {
  success: boolean
  services: {
    database: boolean
    cache: boolean
    syncService: boolean
  }
  errors: string[]
  startupTime: number
}

class ApplicationInitializer {
  private startTime = Date.now()

  async initialize(): Promise<InitializationResult> {
    const errors: string[] = []
    const services = {
      database: false,
      cache: false,
      syncService: false,
    }

    logger.info('Starting Meta Ads Platform v23.0 initialization')

    // Validate environment variables
    const envValidation = this.validateEnvironment()
    if (!envValidation.valid) {
      errors.push(...envValidation.errors)
      logger.error('Environment validation failed', undefined, { errors: envValidation.errors })
    }

    try {
      // Initialize database
      logger.info('Initializing database connection and schema')
      await databaseManager.initializeSchema()
      services.database = true
      logger.info('Database initialized successfully')
    } catch (error) {
      const errorMsg = `Database initialization failed: ${error instanceof Error ? error.message : 'Unknown error'}`
      errors.push(errorMsg)
      logger.error(errorMsg, error)
    }

    try {
      // Initialize cache
      logger.info('Initializing cache connection')
      await cacheManager.connect()
      services.cache = true
      logger.info('Cache initialized successfully')
    } catch (error) {
      const errorMsg = `Cache initialization failed: ${error instanceof Error ? error.message : 'Unknown error'}`
      errors.push(errorMsg)
      logger.error(errorMsg, error)
    }

    try {
      // Initialize sync service
      logger.info('Initializing data sync service')
      await dataSyncService.initialize()
      services.syncService = true
      logger.info('Data sync service initialized successfully')
    } catch (error) {
      const errorMsg = `Sync service initialization failed: ${error instanceof Error ? error.message : 'Unknown error'}`
      errors.push(errorMsg)
      logger.error(errorMsg, error)
    }

    const startupTime = Date.now() - this.startTime
    const success = errors.length === 0

    const result: InitializationResult = {
      success,
      services,
      errors,
      startupTime,
    }

    if (success) {
      logger.info(`Meta Ads Platform v23.0 initialized successfully in ${startupTime}ms`)
      
      // Log system information
      logger.info('System Information', {
        nodeVersion: process.version,
        platform: process.platform,
        arch: process.arch,
        environment: process.env.NODE_ENV,
        uptime: process.uptime(),
      })

      // Perform initial health checks
      this.performInitialHealthChecks()
    } else {
      logger.error(`Meta Ads Platform v23.0 initialization failed after ${startupTime}ms`, undefined, {
        errors,
        servicesInitialized: Object.entries(services).filter(([_, status]) => status).map(([name]) => name),
      })
    }

    return result
  }

  private validateEnvironment(): { valid: boolean; errors: string[] } {
    const required = [
      'NEXTAUTH_SECRET',
      'NEXTAUTH_URL',
      'FACEBOOK_CLIENT_ID',
      'FACEBOOK_CLIENT_SECRET',
    ]

    const optional = [
      'META_SYSTEM_USER_ID',
      'META_WEBHOOK_VERIFY_TOKEN',
      'DB_HOST',
      'DB_USER',
      'DB_PASSWORD',
      'DB_NAME',
      'REDIS_HOST',
      'REDIS_PORT',
      'LOG_LEVEL',
    ]

    const errors: string[] = []

    // Check required environment variables
    for (const varName of required) {
      if (!process.env[varName]) {
        errors.push(`Missing required environment variable: ${varName}`)
      }
    }

    // Validate Facebook credentials format
    const clientId = process.env.FACEBOOK_CLIENT_ID
    const clientSecret = process.env.FACEBOOK_CLIENT_SECRET

    if (clientId && !/^\d+$/.test(clientId)) {
      errors.push('FACEBOOK_CLIENT_ID should be numeric')
    }

    if (clientSecret && clientSecret.length < 32) {
      errors.push('FACEBOOK_CLIENT_SECRET appears to be too short')
    }

    // Validate NEXTAUTH_URL format
    const nextAuthUrl = process.env.NEXTAUTH_URL
    if (nextAuthUrl) {
      try {
        new URL(nextAuthUrl)
      } catch {
        errors.push('NEXTAUTH_URL is not a valid URL')
      }
    }

    // Validate database configuration
    if (process.env.DB_HOST && !process.env.DB_NAME) {
      errors.push('DB_NAME is required when DB_HOST is specified')
    }

    // Log optional missing variables for awareness
    for (const varName of optional) {
      if (!process.env[varName]) {
        logger.warn(`Optional environment variable not set: ${varName}`)
      }
    }

    return {
      valid: errors.length === 0,
      errors,
    }
  }

  private async performInitialHealthChecks(): Promise<void> {
    logger.info('Performing initial health checks')

    try {
      // Check database connectivity
      const pool = await databaseManager.getConnection()
      const [result] = await pool.execute('SELECT COUNT(*) as count FROM ad_accounts')
      logger.info(`Database health check passed - ${(result as any)[0].count} ad accounts found`)
    } catch (error) {
      logger.warn('Database health check failed', error)
    }

    try {
      // Check cache connectivity
      const stats = await cacheManager.getStats()
      logger.info('Cache health check passed', stats)
    } catch (error) {
      logger.warn('Cache health check failed', error)
    }

    try {
      // Check Meta API connectivity (if credentials are available)
      if (process.env.META_SYSTEM_USER_ID || process.env.FACEBOOK_CLIENT_ID) {
        // This would be a simple API call to check connectivity
        logger.info('Meta API credentials detected - ready for API calls')
      } else {
        logger.warn('Meta API credentials not fully configured')
      }
    } catch (error) {
      logger.warn('Meta API health check failed', error)
    }
  }

  async gracefulShutdown(): Promise<void> {
    logger.info('Starting graceful shutdown')

    try {
      // Stop sync service
      await dataSyncService.stopAllJobs()
      logger.info('Sync service stopped')
    } catch (error) {
      logger.error('Error stopping sync service', error)
    }

    try {
      // Close cache connections
      await cacheManager.close()
      logger.info('Cache connections closed')
    } catch (error) {
      logger.error('Error closing cache connections', error)
    }

    try {
      // Close database connections
      await databaseManager.close()
      logger.info('Database connections closed')
    } catch (error) {
      logger.error('Error closing database connections', error)
    }

    logger.info('Graceful shutdown completed')
  }
}

// Create singleton instance
const appInitializer = new ApplicationInitializer()

// Export initialization functions
export const initializeApplication = () => appInitializer.initialize()
export const shutdownApplication = () => appInitializer.gracefulShutdown()

// Handle process signals for graceful shutdown
if (typeof process !== 'undefined') {
  process.on('SIGINT', async () => {
    logger.info('Received SIGINT signal, starting graceful shutdown')
    await shutdownApplication()
    process.exit(0)
  })

  process.on('SIGTERM', async () => {
    logger.info('Received SIGTERM signal, starting graceful shutdown')
    await shutdownApplication()
    process.exit(0)
  })

  process.on('uncaughtException', (error) => {
    logger.error('Uncaught Exception', error)
    // Give some time for logs to flush
    setTimeout(() => process.exit(1), 1000)
  })

  process.on('unhandledRejection', (reason, promise) => {
    logger.error('Unhandled Rejection', reason instanceof Error ? reason : new Error(String(reason)), {
      promise: promise.toString(),
    })
    // Give some time for logs to flush
    setTimeout(() => process.exit(1), 1000)
  })
}

export { ApplicationInitializer }