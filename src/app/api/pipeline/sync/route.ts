import { NextRequest, NextResponse } from 'next/server'
import { getServerSession } from 'next-auth'
import { authOptions } from '@/lib/auth'
import { campaignSyncScheduler } from '@/lib/jobs/campaign-sync-scheduler'
import { jobQueueManager } from '@/lib/jobs/job-queue-manager'
import { dataSyncService } from '@/lib/data/data-sync-service'
import { timeSeriesManager } from '@/lib/data/time-series-manager'
import { webSocketManager } from '@/lib/realtime/websocket-manager'
import { logger } from '@/lib/logger'

// Manual sync trigger endpoint
export async function POST(request: NextRequest) {
  const startTime = Date.now()
  const requestId = logger.logApiRequest('/api/pipeline/sync', 'POST')

  try {
    const session = await getServerSession(authOptions)
    if (!session) {
      logger.logApiResponse(requestId, '/api/pipeline/sync', 'POST', 401, Date.now() - startTime)
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
    }

    const body = await request.json()
    const {
      adAccountId,
      syncType = 'incremental',
      campaignIds,
      priority = 'normal',
      realTimeUpdates = true
    } = body

    if (!adAccountId) {
      logger.logApiResponse(requestId, '/api/pipeline/sync', 'POST', 400, Date.now() - startTime)
      return NextResponse.json({ error: 'adAccountId is required' }, { status: 400 })
    }

    // Trigger manual sync
    const jobId = await campaignSyncScheduler.triggerManualSync(adAccountId, {
      campaignIds,
      syncType,
      priority,
      userId: session.user.id
    })

    if (!jobId) {
      logger.logApiResponse(requestId, '/api/pipeline/sync', 'POST', 500, Date.now() - startTime)
      return NextResponse.json({ error: 'Failed to trigger sync job' }, { status: 500 })
    }

    // Send real-time notification if enabled
    if (realTimeUpdates) {
      await webSocketManager.sendToUser(session.user.id, 'sync_started', {
        jobId,
        adAccountId,
        syncType,
        campaignIds,
        timestamp: new Date().toISOString()
      })

      // Broadcast to account room
      await webSocketManager.sendToRoom(`account:${adAccountId}`, 'sync_triggered', {
        jobId,
        syncType,
        triggeredBy: session.user.id,
        timestamp: new Date().toISOString()
      })
    }

    logger.logApiResponse(requestId, '/api/pipeline/sync', 'POST', 200, Date.now() - startTime, {
      jobId,
      adAccountId,
      syncType
    })

    return NextResponse.json({
      success: true,
      jobId,
      adAccountId,
      syncType,
      campaignIds,
      priority,
      message: 'Sync job triggered successfully',
      timestamp: new Date().toISOString()
    })

  } catch (error) {
    logger.error('Failed to trigger sync', error, { requestId })
    logger.logApiResponse(requestId, '/api/pipeline/sync', 'POST', 500, Date.now() - startTime)

    return NextResponse.json({
      error: 'Failed to trigger sync',
      message: error instanceof Error ? error.message : 'Unknown error'
    }, { status: 500 })
  }
}

// Get sync status and history
export async function GET(request: NextRequest) {
  const startTime = Date.now()
  const requestId = logger.logApiRequest('/api/pipeline/sync', 'GET')

  try {
    const session = await getServerSession(authOptions)
    if (!session) {
      logger.logApiResponse(requestId, '/api/pipeline/sync', 'GET', 401, Date.now() - startTime)
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
    }

    const { searchParams } = new URL(request.url)
    const scheduleId = searchParams.get('schedule_id')
    const adAccountId = searchParams.get('account_id')
    const limit = parseInt(searchParams.get('limit') || '50')

    // Get sync history
    let syncHistory = []
    if (scheduleId) {
      syncHistory = await campaignSyncScheduler.getSyncHistory(scheduleId, limit)
    } else {
      syncHistory = await campaignSyncScheduler.getSyncHistory(undefined, limit)
    }

    // Get active jobs
    const activeJobs = await jobQueueManager.getActiveJobs('campaign_sync')

    // Get schedules if account ID provided
    let schedules = []
    if (adAccountId) {
      schedules = await campaignSyncScheduler.getSchedulesByAccount(adAccountId)
    }

    // Get sync statistics from time-series data
    let syncStats = null
    if (adAccountId) {
      const syncData = await timeSeriesManager.getTimeSeries(
        `sync:stats:${adAccountId}`,
        {
          start: Date.now() - (7 * 24 * 60 * 60 * 1000), // Last 7 days
          end: Date.now(),
          aggregation: 'daily'
        }
      )
      syncStats = syncData
    }

    logger.logApiResponse(requestId, '/api/pipeline/sync', 'GET', 200, Date.now() - startTime, {
      adAccountId,
      historyCount: syncHistory.length,
      activeJobsCount: activeJobs.length,
      schedulesCount: schedules.length
    })

    return NextResponse.json({
      syncHistory,
      activeJobs: activeJobs.map(job => ({
        id: job.id,
        data: job.data,
        opts: job.opts,
        progress: job.progress(),
        timestamp: new Date(job.timestamp).toISOString()
      })),
      schedules,
      syncStats,
      timestamp: new Date().toISOString()
    })

  } catch (error) {
    logger.error('Failed to get sync status', error, { requestId })
    logger.logApiResponse(requestId, '/api/pipeline/sync', 'GET', 500, Date.now() - startTime)

    return NextResponse.json({
      error: 'Failed to get sync status',
      message: error instanceof Error ? error.message : 'Unknown error'
    }, { status: 500 })
  }
}

// Update sync schedule
export async function PUT(request: NextRequest) {
  const startTime = Date.now()
  const requestId = logger.logApiRequest('/api/pipeline/sync', 'PUT')

  try {
    const session = await getServerSession(authOptions)
    if (!session) {
      logger.logApiResponse(requestId, '/api/pipeline/sync', 'PUT', 401, Date.now() - startTime)
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
    }

    const body = await request.json()
    const { scheduleId, ...updates } = body

    if (!scheduleId) {
      logger.logApiResponse(requestId, '/api/pipeline/sync', 'PUT', 400, Date.now() - startTime)
      return NextResponse.json({ error: 'scheduleId is required' }, { status: 400 })
    }

    const success = await campaignSyncScheduler.updateSchedule(scheduleId, updates)

    if (!success) {
      logger.logApiResponse(requestId, '/api/pipeline/sync', 'PUT', 404, Date.now() - startTime)
      return NextResponse.json({ error: 'Schedule not found' }, { status: 404 })
    }

    // Send real-time notification
    await webSocketManager.sendToUser(session.user.id, 'schedule_updated', {
      scheduleId,
      updates,
      timestamp: new Date().toISOString()
    })

    logger.logApiResponse(requestId, '/api/pipeline/sync', 'PUT', 200, Date.now() - startTime, {
      scheduleId,
      updateKeys: Object.keys(updates)
    })

    return NextResponse.json({
      success: true,
      scheduleId,
      updates,
      message: 'Schedule updated successfully',
      timestamp: new Date().toISOString()
    })

  } catch (error) {
    logger.error('Failed to update schedule', error, { requestId })
    logger.logApiResponse(requestId, '/api/pipeline/sync', 'PUT', 500, Date.now() - startTime)

    return NextResponse.json({
      error: 'Failed to update schedule',
      message: error instanceof Error ? error.message : 'Unknown error'
    }, { status: 500 })
  }
}

// Delete sync schedule
export async function DELETE(request: NextRequest) {
  const startTime = Date.now()
  const requestId = logger.logApiRequest('/api/pipeline/sync', 'DELETE')

  try {
    const session = await getServerSession(authOptions)
    if (!session) {
      logger.logApiResponse(requestId, '/api/pipeline/sync', 'DELETE', 401, Date.now() - startTime)
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
    }

    const { searchParams } = new URL(request.url)
    const scheduleId = searchParams.get('schedule_id')

    if (!scheduleId) {
      logger.logApiResponse(requestId, '/api/pipeline/sync', 'DELETE', 400, Date.now() - startTime)
      return NextResponse.json({ error: 'schedule_id parameter is required' }, { status: 400 })
    }

    const success = await campaignSyncScheduler.deleteSchedule(scheduleId)

    if (!success) {
      logger.logApiResponse(requestId, '/api/pipeline/sync', 'DELETE', 404, Date.now() - startTime)
      return NextResponse.json({ error: 'Schedule not found' }, { status: 404 })
    }

    // Send real-time notification
    await webSocketManager.sendToUser(session.user.id, 'schedule_deleted', {
      scheduleId,
      timestamp: new Date().toISOString()
    })

    logger.logApiResponse(requestId, '/api/pipeline/sync', 'DELETE', 200, Date.now() - startTime, {
      scheduleId
    })

    return NextResponse.json({
      success: true,
      scheduleId,
      message: 'Schedule deleted successfully',
      timestamp: new Date().toISOString()
    })

  } catch (error) {
    logger.error('Failed to delete schedule', error, { requestId })
    logger.logApiResponse(requestId, '/api/pipeline/sync', 'DELETE', 500, Date.now() - startTime)

    return NextResponse.json({
      error: 'Failed to delete schedule',
      message: error instanceof Error ? error.message : 'Unknown error'
    }, { status: 500 })
  }
}