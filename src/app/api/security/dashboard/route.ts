import { NextRequest, NextResponse } from 'next/server'
import { getServerSession } from 'next-auth'
import { authOptions } from '@/lib/auth'
import { auditLogger } from '@/lib/auth/audit-logger'
import { securityManager } from '@/lib/auth/security-manager'
import { redisManager, RedisDatabase } from '@/lib/redis-manager'
import { logger } from '@/lib/logger'
import { z } from 'zod'

const dashboardQuerySchema = z.object({
  timeRange: z.enum(['1h', '24h', '7d', '30d']).optional().default('24h'),
  userId: z.string().optional(),
  includeDetails: z.boolean().optional().default(false)
})

export async function GET(request: NextRequest) {
  try {
    const session = await getServerSession(authOptions)

    if (!session?.user?.id) {
      return NextResponse.json(
        { error: 'Authentication required' },
        { status: 401 }
      )
    }

    const url = new URL(request.url)
    const query = dashboardQuerySchema.parse({
      timeRange: url.searchParams.get('timeRange') || '24h',
      userId: url.searchParams.get('userId') || undefined,
      includeDetails: url.searchParams.get('includeDetails') === 'true'
    })

    // Check if user has admin privileges or is requesting their own data
    const requestedUserId = query.userId || session.user.id
    const isAdmin = session.user.role === 'admin' || session.user.role === 'security'

    if (!isAdmin && requestedUserId !== session.user.id) {
      return NextResponse.json(
        { error: 'Insufficient permissions' },
        { status: 403 }
      )
    }

    // Get security dashboard data
    const dashboardData = await auditLogger.getSecurityDashboard(
      isAdmin ? query.userId : session.user.id
    )

    // Get current security status
    const securityStatus = await securityManager.getSecurityStatus(requestedUserId)

    // Calculate time range for queries
    const timeRangeMs = {
      '1h': 60 * 60 * 1000,
      '24h': 24 * 60 * 60 * 1000,
      '7d': 7 * 24 * 60 * 60 * 1000,
      '30d': 30 * 24 * 60 * 60 * 1000
    }

    const startTime = new Date(Date.now() - timeRangeMs[query.timeRange])

    // Filter events by time range
    const filteredEvents = dashboardData.recentEvents.filter(
      event => new Date(event.timestamp) >= startTime
    )

    // Calculate security metrics
    const securityMetrics = {
      totalEvents: filteredEvents.length,
      criticalEvents: filteredEvents.filter(e => e.riskLevel === 'critical').length,
      highRiskEvents: filteredEvents.filter(e => e.riskLevel === 'high').length,
      failedAttempts: filteredEvents.filter(e => e.outcome === 'failure').length,
      activeAlerts: dashboardData.activeAlerts.length,
      criticalAlerts: dashboardData.activeAlerts.filter(a => a.severity === 'critical').length,
      averageRiskScore: dashboardData.timelineData.reduce((sum, point) =>
        sum + point.riskScore, 0) / dashboardData.timelineData.length || 0
    }

    // Prepare response
    const response = {
      timeRange: query.timeRange,
      userId: requestedUserId,
      metrics: securityMetrics,
      securityStatus: {
        riskLevel: securityStatus.riskLevel,
        overallScore: securityStatus.overallScore,
        lastSecurityEvent: securityStatus.lastSecurityEvent,
        activeSecurityMeasures: securityStatus.activeSecurityMeasures
      },
      riskSummary: dashboardData.riskSummary,
      eventTypeSummary: dashboardData.eventTypeSummary,
      timeline: dashboardData.timelineData,
      alerts: dashboardData.activeAlerts.map(alert => ({
        alertId: alert.alertId,
        alertType: alert.alertType,
        severity: alert.severity,
        title: alert.title,
        triggeredAt: alert.triggeredAt,
        status: alert.status,
        ...(query.includeDetails && {
          description: alert.description,
          metadata: alert.metadata
        })
      }))
    }

    // Include detailed events if requested and user has permissions
    if (query.includeDetails && isAdmin) {
      response.recentEvents = filteredEvents.slice(0, 100) // Limit to 100 most recent
    }

    // Log dashboard access
    await auditLogger.logEvent({
      eventType: 'data_access',
      userId: session.user.id,
      ipAddress: request.headers.get('x-forwarded-for') ||
                 request.headers.get('x-real-ip') ||
                 request.ip || '127.0.0.1',
      userAgent: request.headers.get('user-agent') || '',
      riskLevel: 'low',
      outcome: 'success',
      source: 'security_dashboard',
      details: {
        requestedUserId,
        timeRange: query.timeRange,
        includeDetails: query.includeDetails
      }
    })

    return NextResponse.json(response)

  } catch (error) {
    logger.error('Security dashboard API error', {
      error: error instanceof Error ? error.message : 'Unknown error',
      stack: error instanceof Error ? error.stack : undefined
    })

    if (error instanceof z.ZodError) {
      return NextResponse.json(
        { error: 'Invalid query parameters', details: error.errors },
        { status: 400 }
      )
    }

    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    )
  }
}

export async function POST(request: NextRequest) {
  try {
    const session = await getServerSession(authOptions)

    if (!session?.user?.id) {
      return NextResponse.json(
        { error: 'Authentication required' },
        { status: 401 }
      )
    }

    // Check admin privileges for alert actions
    const isAdmin = session.user.role === 'admin' || session.user.role === 'security'

    if (!isAdmin) {
      return NextResponse.json(
        { error: 'Admin privileges required' },
        { status: 403 }
      )
    }

    const body = await request.json()
    const { action, alertId, status, assignedTo, notes } = body

    if (action === 'update_alert' && alertId) {
      // Update alert status
      const client = redisManager.getConnection(RedisDatabase.ANALYTICS)

      const alertData = await client.hget(`security:alert:${alertId}`, 'data')
      if (!alertData) {
        return NextResponse.json(
          { error: 'Alert not found' },
          { status: 404 }
        )
      }

      const alert = JSON.parse(alertData)
      alert.status = status || alert.status
      alert.assignedTo = assignedTo || alert.assignedTo
      alert.updatedAt = new Date().toISOString()
      alert.updatedBy = session.user.id

      if (notes) {
        alert.notes = alert.notes || []
        alert.notes.push({
          note: notes,
          addedBy: session.user.id,
          addedAt: new Date().toISOString()
        })
      }

      await client.hset(`security:alert:${alertId}`, {
        data: JSON.stringify(alert),
        status: alert.status
      })

      // Remove from active alerts if resolved
      if (status === 'resolved' || status === 'false_positive') {
        await client.zrem('security:alerts:active', alertId)
      }

      // Log the alert update
      await auditLogger.logEvent({
        eventType: 'configuration_changed',
        userId: session.user.id,
        ipAddress: request.headers.get('x-forwarded-for') ||
                   request.headers.get('x-real-ip') ||
                   request.ip || '127.0.0.1',
        userAgent: request.headers.get('user-agent') || '',
        riskLevel: 'medium',
        outcome: 'success',
        source: 'security_dashboard',
        details: {
          action: 'alert_updated',
          alertId,
          oldStatus: alertData.status,
          newStatus: status,
          assignedTo,
          notes: notes ? 'added' : 'none'
        }
      })

      return NextResponse.json({
        success: true,
        message: 'Alert updated successfully',
        alertId
      })
    }

    return NextResponse.json(
      { error: 'Invalid action' },
      { status: 400 }
    )

  } catch (error) {
    logger.error('Security dashboard POST API error', {
      error: error instanceof Error ? error.message : 'Unknown error',
      stack: error instanceof Error ? error.stack : undefined
    })

    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    )
  }
}