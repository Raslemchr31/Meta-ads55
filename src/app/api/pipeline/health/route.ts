import { NextRequest, NextResponse } from 'next/server'
import { getServerSession } from 'next-auth'
import { authOptions } from '@/lib/auth'
import { dataPipelineManager } from '@/lib/pipeline-init'
import { logger } from '@/lib/logger'

// Get comprehensive pipeline health status
export async function GET(request: NextRequest) {
  const startTime = Date.now()
  const requestId = logger.logApiRequest('/api/pipeline/health', 'GET')

  try {
    const session = await getServerSession(authOptions)
    if (!session) {
      logger.logApiResponse(requestId, '/api/pipeline/health', 'GET', 401, Date.now() - startTime)
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
    }

    // Get comprehensive health check
    const healthCheck = await dataPipelineManager.healthCheck()

    // Get additional statistics
    const [cacheStats, jobStats, wsStats] = await Promise.allSettled([
      dataPipelineManager.getCacheStats(),
      dataPipelineManager.getJobStats(),
      dataPipelineManager.getWebSocketStats()
    ])

    const responseData = {
      ...healthCheck,
      statistics: {
        caches: cacheStats.status === 'fulfilled' ? cacheStats.value : { error: 'Failed to fetch' },
        jobs: jobStats.status === 'fulfilled' ? jobStats.value : { error: 'Failed to fetch' },
        websockets: wsStats.status === 'fulfilled' ? wsStats.value : { error: 'Failed to fetch' }
      },
      components: dataPipelineManager.getComponents(),
      uptime: process.uptime(),
      memory: process.memoryUsage(),
      version: process.env.npm_package_version || 'unknown'
    }

    // Determine HTTP status based on pipeline health
    let httpStatus = 200
    if (healthCheck.status.overall === 'critical') {
      httpStatus = 503 // Service Unavailable
    } else if (healthCheck.status.overall === 'degraded') {
      httpStatus = 206 // Partial Content
    }

    logger.logApiResponse(requestId, '/api/pipeline/health', 'GET', httpStatus, Date.now() - startTime, {
      overallStatus: healthCheck.status.overall,
      components: dataPipelineManager.getComponents().length
    })

    return NextResponse.json(responseData, { status: httpStatus })

  } catch (error) {
    logger.error('Failed to get pipeline health', error, { requestId })
    logger.logApiResponse(requestId, '/api/pipeline/health', 'GET', 500, Date.now() - startTime)

    return NextResponse.json({
      error: 'Failed to get pipeline health',
      message: error instanceof Error ? error.message : 'Unknown error',
      status: {
        redis: 'error',
        caches: 'error',
        websockets: 'error',
        jobs: 'error',
        timeSeries: 'error',
        dataSync: 'error',
        overall: 'critical'
      },
      timestamp: new Date().toISOString()
    }, { status: 500 })
  }
}

// Initialize or restart pipeline components
export async function POST(request: NextRequest) {
  const startTime = Date.now()
  const requestId = logger.logApiRequest('/api/pipeline/health', 'POST')

  try {
    const session = await getServerSession(authOptions)
    if (!session) {
      logger.logApiResponse(requestId, '/api/pipeline/health', 'POST', 401, Date.now() - startTime)
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
    }

    const body = await request.json()
    const { action = 'initialize', component } = body

    let result: any = { action, timestamp: new Date().toISOString() }

    switch (action) {
      case 'initialize':
        await dataPipelineManager.initialize()
        result.message = 'Pipeline initialized successfully'
        result.status = dataPipelineManager.getStatus()
        break

      case 'health-check':
        result = await dataPipelineManager.healthCheck()
        break

      case 'restart':
        if (component) {
          result.message = `Component restart not implemented for ${component}`
          result.error = 'Not implemented'
        } else {
          await dataPipelineManager.shutdown()
          await dataPipelineManager.initialize()
          result.message = 'Pipeline restarted successfully'
          result.status = dataPipelineManager.getStatus()
        }
        break

      default:
        logger.logApiResponse(requestId, '/api/pipeline/health', 'POST', 400, Date.now() - startTime)
        return NextResponse.json({
          error: 'Invalid action',
          validActions: ['initialize', 'health-check', 'restart']
        }, { status: 400 })
    }

    logger.logApiResponse(requestId, '/api/pipeline/health', 'POST', 200, Date.now() - startTime, {
      action,
      component: component || 'all'
    })

    return NextResponse.json(result)

  } catch (error) {
    logger.error('Failed to execute pipeline action', error, { requestId })
    logger.logApiResponse(requestId, '/api/pipeline/health', 'POST', 500, Date.now() - startTime)

    return NextResponse.json({
      error: 'Failed to execute pipeline action',
      message: error instanceof Error ? error.message : 'Unknown error'
    }, { status: 500 })
  }
}