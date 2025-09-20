import { NextRequest, NextResponse } from 'next/server'
import { getServerSession } from 'next-auth'
import { authOptions } from '@/lib/auth'
import { dataSyncService } from '@/lib/sync-service'
import { requireAuth } from '@/lib/middleware'
import { logger } from '@/lib/logger'

export async function POST(request: NextRequest) {
  const startTime = Date.now()
  const requestId = logger.logApiRequest('/api/sync', 'POST')
  
  try {
    // Check authentication
    const authResult = await requireAuth(request)
    if (authResult) {
      return authResult
    }

    const session = await getServerSession(authOptions)
    const { searchParams } = new URL(request.url)
    const body = await request.json().catch(() => ({}))
    
    const syncType = searchParams.get('type') || body.type
    const accountId = searchParams.get('account_id') || body.account_id
    const days = parseInt(searchParams.get('days') || body.days || '7')
    
    logger.info('Manual sync requested', {
      syncType,
      accountId,
      days,
      userId: session?.user?.email,
    })

    let result
    
    switch (syncType) {
      case 'accounts':
        result = await dataSyncService.syncAllAccounts()
        break
        
      case 'campaigns':
        result = await dataSyncService.syncAllCampaigns()
        break
        
      case 'insights':
        result = await dataSyncService.syncAllAccountsInsights(days)
        break
        
      case 'account':
        if (!accountId) {
          logger.logApiResponse(requestId, '/api/sync', 'POST', 400, Date.now() - startTime)
          return NextResponse.json(
            { error: 'account_id is required for account sync' },
            { status: 400 }
          )
        }
        result = await dataSyncService.syncSpecificAccount(accountId)
        break
        
      default:
        logger.logApiResponse(requestId, '/api/sync', 'POST', 400, Date.now() - startTime)
        return NextResponse.json(
          { 
            error: 'Invalid sync type',
            validTypes: ['accounts', 'campaigns', 'insights', 'account'],
          },
          { status: 400 }
        )
    }

    logger.logPerformanceMetric('manual_sync', Date.now() - startTime, {
      syncType,
      accountId,
      success: result.success,
      processed: result.processed,
      errors: result.errors,
    })

    logger.logApiResponse(requestId, '/api/sync', 'POST', 200, Date.now() - startTime, {
      syncType,
      processed: result.processed,
      errors: result.errors,
    })

    return NextResponse.json({
      ...result,
      sync_type: syncType,
      account_id: accountId,
      requested_by: session?.user?.email,
      timestamp: new Date().toISOString(),
    })

  } catch (error) {
    logger.error('Manual sync failed', error, {
      requestId,
      endpoint: '/api/sync',
    })

    logger.logApiResponse(requestId, '/api/sync', 'POST', 500, Date.now() - startTime)

    return NextResponse.json(
      { 
        error: 'Sync operation failed',
        message: error instanceof Error ? error.message : 'Unknown error',
      },
      { status: 500 }
    )
  }
}

export async function GET(request: NextRequest) {
  const startTime = Date.now()
  const requestId = logger.logApiRequest('/api/sync', 'GET')
  
  try {
    // Check authentication
    const authResult = await requireAuth(request)
    if (authResult) {
      return authResult
    }

    // Get sync status
    const status = await dataSyncService.getStatus()

    logger.logApiResponse(requestId, '/api/sync', 'GET', 200, Date.now() - startTime)

    return NextResponse.json({
      status: status.isRunning ? 'running' : 'idle',
      is_running: status.isRunning,
      scheduled_jobs: status.scheduledJobs,
      last_run: status.lastRun,
      available_sync_types: ['accounts', 'campaigns', 'insights', 'account'],
      timestamp: new Date().toISOString(),
    })

  } catch (error) {
    logger.error('Failed to get sync status', error, {
      requestId,
      endpoint: '/api/sync',
    })

    logger.logApiResponse(requestId, '/api/sync', 'GET', 500, Date.now() - startTime)

    return NextResponse.json(
      { 
        error: 'Failed to get sync status',
        message: error instanceof Error ? error.message : 'Unknown error',
      },
      { status: 500 }
    )
  }
}