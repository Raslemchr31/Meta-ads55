import { NextRequest, NextResponse } from 'next/server'
import { metaGraphApiClient } from '@/lib/api-client'
import { databaseManager } from '@/lib/database'
import { cacheManager } from '@/lib/cache'
import { dataSyncService } from '@/lib/sync-service'
import { logger } from '@/lib/logger'

interface HealthCheckResult {
  service: string
  status: 'healthy' | 'unhealthy' | 'degraded'
  responseTime?: number
  details?: any
  error?: string
}

interface SystemHealth {
  status: 'healthy' | 'unhealthy' | 'degraded'
  timestamp: string
  services: HealthCheckResult[]
  overall: {
    uptime: number
    version: string
    environment: string
    nodeVersion: string
  }
}

export async function GET(request: NextRequest) {
  const startTime = Date.now()
  const { searchParams } = new URL(request.url)
  const detailed = searchParams.get('detailed') === 'true'
  
  try {
    const healthChecks: HealthCheckResult[] = []
    
    // Database health check
    const dbHealth = await checkDatabaseHealth()
    healthChecks.push(dbHealth)
    
    // Cache health check
    const cacheHealth = await checkCacheHealth()
    healthChecks.push(cacheHealth)
    
    // Meta API health check
    const metaApiHealth = await checkMetaApiHealth()
    healthChecks.push(metaApiHealth)
    
    if (detailed) {
      // Data sync service health check
      const syncHealth = await checkSyncServiceHealth()
      healthChecks.push(syncHealth)
      
      // System resources check
      const systemHealth = await checkSystemResources()
      healthChecks.push(systemHealth)
    }
    
    // Determine overall status
    const hasUnhealthy = healthChecks.some(check => check.status === 'unhealthy')
    const hasDegraded = healthChecks.some(check => check.status === 'degraded')
    
    let overallStatus: 'healthy' | 'unhealthy' | 'degraded'
    if (hasUnhealthy) {
      overallStatus = 'unhealthy'
    } else if (hasDegraded) {
      overallStatus = 'degraded'
    } else {
      overallStatus = 'healthy'
    }
    
    const systemHealth: SystemHealth = {
      status: overallStatus,
      timestamp: new Date().toISOString(),
      services: healthChecks,
      overall: {
        uptime: process.uptime(),
        version: process.env.APP_VERSION || '1.0.0',
        environment: process.env.NODE_ENV || 'development',
        nodeVersion: process.version,
      },
    }
    
    // Log health check results
    for (const check of healthChecks) {
      logger.logHealthCheck(check.service, check.status, check.details)
    }
    
    const statusCode = overallStatus === 'healthy' ? 200 : 
                      overallStatus === 'degraded' ? 200 : 503
    
    logger.info(`Health check completed in ${Date.now() - startTime}ms`, {
      status: overallStatus,
      servicesChecked: healthChecks.length,
      responseTime: Date.now() - startTime,
    })
    
    return NextResponse.json(systemHealth, { status: statusCode })
    
  } catch (error) {
    logger.error('Health check failed', error)
    
    const errorHealth: SystemHealth = {
      status: 'unhealthy',
      timestamp: new Date().toISOString(),
      services: [{
        service: 'health-check',
        status: 'unhealthy',
        error: error instanceof Error ? error.message : 'Unknown error',
      }],
      overall: {
        uptime: process.uptime(),
        version: process.env.APP_VERSION || '1.0.0',
        environment: process.env.NODE_ENV || 'development',
        nodeVersion: process.version,
      },
    }
    
    return NextResponse.json(errorHealth, { status: 503 })
  }
}

async function checkDatabaseHealth(): Promise<HealthCheckResult> {
  const startTime = Date.now()
  
  try {
    const pool = await databaseManager.getConnection()
    
    // Test connection with a simple query
    const [rows] = await pool.execute('SELECT 1 as health_check')
    
    // Check if we can access our main tables
    const [accountCount] = await pool.execute('SELECT COUNT(*) as count FROM ad_accounts')
    const [insightsCount] = await pool.execute('SELECT COUNT(*) as count FROM daily_insights WHERE date_start >= DATE_SUB(NOW(), INTERVAL 7 DAY)')
    
    const responseTime = Date.now() - startTime
    
    return {
      service: 'database',
      status: 'healthy',
      responseTime,
      details: {
        connection: 'active',
        accounts: (accountCount as any)[0].count,
        recent_insights: (insightsCount as any)[0].count,
      },
    }
  } catch (error) {
    return {
      service: 'database',
      status: 'unhealthy',
      responseTime: Date.now() - startTime,
      error: error instanceof Error ? error.message : 'Database connection failed',
    }
  }
}

async function checkCacheHealth(): Promise<HealthCheckResult> {
  const startTime = Date.now()
  
  try {
    await cacheManager.connect()
    
    // Test cache operations
    const testKey = 'health-check-test'
    const testValue = { timestamp: Date.now() }
    
    await cacheManager.set(testKey, testValue, 60)
    const retrieved = await cacheManager.get(testKey)
    await cacheManager.del(testKey)
    
    const stats = await cacheManager.getStats()
    const responseTime = Date.now() - startTime
    
    if (JSON.stringify(retrieved) === JSON.stringify(testValue)) {
      return {
        service: 'cache',
        status: 'healthy',
        responseTime,
        details: {
          connected: stats.connected,
          keys: stats.keys,
          memory: stats.memory,
        },
      }
    } else {
      return {
        service: 'cache',
        status: 'degraded',
        responseTime,
        details: {
          connected: stats.connected,
          issue: 'Cache read/write test failed',
        },
      }
    }
  } catch (error) {
    return {
      service: 'cache',
      status: 'unhealthy',
      responseTime: Date.now() - startTime,
      error: error instanceof Error ? error.message : 'Cache connection failed',
    }
  }
}

async function checkMetaApiHealth(): Promise<HealthCheckResult> {
  const startTime = Date.now()
  
  try {
    const rateLimitCheck = await metaGraphApiClient.checkRateLimit()
    const responseTime = Date.now() - startTime
    
    if (rateLimitCheck.status === 'healthy') {
      return {
        service: 'meta-api',
        status: 'healthy',
        responseTime,
        details: {
          api_version: 'v23.0',
          rate_limit_status: rateLimitCheck.status,
        },
      }
    } else if (rateLimitCheck.status === 'rate_limited') {
      return {
        service: 'meta-api',
        status: 'degraded',
        responseTime,
        details: {
          api_version: 'v23.0',
          rate_limit_status: rateLimitCheck.status,
          issue: 'Rate limit exceeded',
        },
      }
    } else {
      return {
        service: 'meta-api',
        status: 'unhealthy',
        responseTime,
        error: rateLimitCheck.error,
      }
    }
  } catch (error) {
    return {
      service: 'meta-api',
      status: 'unhealthy',
      responseTime: Date.now() - startTime,
      error: error instanceof Error ? error.message : 'Meta API connection failed',
    }
  }
}

async function checkSyncServiceHealth(): Promise<HealthCheckResult> {
  const startTime = Date.now()
  
  try {
    const syncStatus = await dataSyncService.getStatus()
    const responseTime = Date.now() - startTime
    
    return {
      service: 'sync-service',
      status: 'healthy',
      responseTime,
      details: {
        running: syncStatus.isRunning,
        scheduled_jobs: syncStatus.scheduledJobs,
        last_run: syncStatus.lastRun,
      },
    }
  } catch (error) {
    return {
      service: 'sync-service',
      status: 'unhealthy',
      responseTime: Date.now() - startTime,
      error: error instanceof Error ? error.message : 'Sync service check failed',
    }
  }
}

async function checkSystemResources(): Promise<HealthCheckResult> {
  const startTime = Date.now()
  
  try {
    const memoryUsage = process.memoryUsage()
    const cpuUsage = process.cpuUsage()
    
    // Convert bytes to MB for easier reading
    const memoryDetails = {
      rss: Math.round(memoryUsage.rss / 1024 / 1024),
      heapTotal: Math.round(memoryUsage.heapTotal / 1024 / 1024),
      heapUsed: Math.round(memoryUsage.heapUsed / 1024 / 1024),
      external: Math.round(memoryUsage.external / 1024 / 1024),
    }
    
    // Check if memory usage is too high (over 1GB)
    const memoryStatus = memoryDetails.rss > 1024 ? 'degraded' : 'healthy'
    
    const responseTime = Date.now() - startTime
    
    return {
      service: 'system-resources',
      status: memoryStatus,
      responseTime,
      details: {
        memory_mb: memoryDetails,
        cpu_usage: cpuUsage,
        uptime_seconds: Math.round(process.uptime()),
        platform: process.platform,
        arch: process.arch,
      },
    }
  } catch (error) {
    return {
      service: 'system-resources',
      status: 'unhealthy',
      responseTime: Date.now() - startTime,
      error: error instanceof Error ? error.message : 'System resources check failed',
    }
  }
}

// Liveness probe endpoint
export async function HEAD(request: NextRequest) {
  try {
    // Quick database connectivity check
    const pool = await databaseManager.getConnection()
    await pool.execute('SELECT 1')
    
    return new NextResponse(null, { status: 200 })
  } catch (error) {
    logger.error('Liveness probe failed', error)
    return new NextResponse(null, { status: 503 })
  }
}