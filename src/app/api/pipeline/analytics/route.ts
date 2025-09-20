import { NextRequest, NextResponse } from 'next/server'
import { getServerSession } from 'next-auth'
import { authOptions } from '@/lib/auth'
import { timeSeriesManager } from '@/lib/data/time-series-manager'
import { campaignInsightsCache } from '@/lib/cache/campaign-insights-cache'
import { webSocketManager } from '@/lib/realtime/websocket-manager'
import { logger } from '@/lib/logger'

// Get real-time analytics data
export async function GET(request: NextRequest) {
  const startTime = Date.now()
  const requestId = logger.logApiRequest('/api/pipeline/analytics', 'GET')

  try {
    const session = await getServerSession(authOptions)
    if (!session) {
      logger.logApiResponse(requestId, '/api/pipeline/analytics', 'GET', 401, Date.now() - startTime)
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
    }

    const { searchParams } = new URL(request.url)
    const type = searchParams.get('type') || 'performance' // performance, spend, impressions, clicks
    const entityType = searchParams.get('entity_type') || 'campaign' // campaign, adset, ad, account
    const entityId = searchParams.get('entity_id')
    const accountId = searchParams.get('account_id')
    const timeframe = searchParams.get('timeframe') || '7d' // 1h, 24h, 7d, 30d
    const aggregation = searchParams.get('aggregation') || 'hourly' // minutely, hourly, daily
    const realTime = searchParams.get('real_time') === 'true'

    if (!accountId && !entityId) {
      logger.logApiResponse(requestId, '/api/pipeline/analytics', 'GET', 400, Date.now() - startTime)
      return NextResponse.json({ error: 'account_id or entity_id is required' }, { status: 400 })
    }

    // Calculate time range based on timeframe
    const now = Date.now()
    let startTime_ts: number

    switch (timeframe) {
      case '1h':
        startTime_ts = now - (60 * 60 * 1000)
        break
      case '24h':
        startTime_ts = now - (24 * 60 * 60 * 1000)
        break
      case '7d':
        startTime_ts = now - (7 * 24 * 60 * 60 * 1000)
        break
      case '30d':
        startTime_ts = now - (30 * 24 * 60 * 60 * 1000)
        break
      default:
        startTime_ts = now - (7 * 24 * 60 * 60 * 1000)
    }

    const analyticsData: any = {
      type,
      entityType,
      entityId: entityId || accountId,
      timeframe,
      aggregation,
      realTime,
      timestamp: new Date().toISOString()
    }

    // Get time-series data based on type
    const tsKey = entityId
      ? `insights:${entityType}:${entityId}`
      : `insights:account:${accountId}`

    try {
      const timeSeriesData = await timeSeriesManager.getTimeSeries(tsKey, {
        start: startTime_ts,
        end: now,
        aggregation: aggregation as any
      })

      analyticsData.timeSeries = timeSeriesData
    } catch (tsError) {
      logger.warn('Failed to get time-series data', { tsKey, error: tsError })
      analyticsData.timeSeries = []
    }

    // Get latest campaign insights for current performance
    if (entityType === 'campaign' && entityId) {
      try {
        const latestInsights = await campaignInsightsCache.getLatestMetrics(entityId)
        analyticsData.currentMetrics = latestInsights
      } catch (cacheError) {
        logger.warn('Failed to get latest metrics', { entityId, error: cacheError })
      }
    }

    // Get performance trends and anomalies
    if (analyticsData.timeSeries?.length > 0) {
      const trends = calculateTrends(analyticsData.timeSeries)
      const anomalies = detectAnomalies(analyticsData.timeSeries)

      analyticsData.trends = trends
      analyticsData.anomalies = anomalies
    }

    // Get real-time data if requested
    if (realTime) {
      // Subscribe client to real-time updates for this entity
      await webSocketManager.joinRoom(session.user.id, `analytics:${entityType}:${entityId || accountId}`)

      // Send initial real-time notification
      await webSocketManager.sendToUser(session.user.id, 'analytics_subscribed', {
        entityType,
        entityId: entityId || accountId,
        type,
        timestamp: new Date().toISOString()
      })
    }

    // Calculate summary statistics
    if (analyticsData.timeSeries?.length > 0) {
      const summary = calculateSummaryStats(analyticsData.timeSeries)
      analyticsData.summary = summary
    }

    logger.logApiResponse(requestId, '/api/pipeline/analytics', 'GET', 200, Date.now() - startTime, {
      type,
      entityType,
      entityId: entityId || accountId,
      timeframe,
      dataPoints: analyticsData.timeSeries?.length || 0
    })

    return NextResponse.json(analyticsData)

  } catch (error) {
    logger.error('Failed to get analytics data', error, { requestId })
    logger.logApiResponse(requestId, '/api/pipeline/analytics', 'GET', 500, Date.now() - startTime)

    return NextResponse.json({
      error: 'Failed to get analytics data',
      message: error instanceof Error ? error.message : 'Unknown error'
    }, { status: 500 })
  }
}

// Add custom analytics data point
export async function POST(request: NextRequest) {
  const startTime = Date.now()
  const requestId = logger.logApiRequest('/api/pipeline/analytics', 'POST')

  try {
    const session = await getServerSession(authOptions)
    if (!session) {
      logger.logApiResponse(requestId, '/api/pipeline/analytics', 'POST', 401, Date.now() - startTime)
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
    }

    const body = await request.json()
    const {
      key,
      value,
      metadata = {},
      timestamp = Date.now(),
      broadcastUpdate = true
    } = body

    if (!key || value === undefined) {
      logger.logApiResponse(requestId, '/api/pipeline/analytics', 'POST', 400, Date.now() - startTime)
      return NextResponse.json({ error: 'key and value are required' }, { status: 400 })
    }

    // Add data point to time-series
    const success = await timeSeriesManager.addDataPoint(key, {
      timestamp,
      value,
      metadata: {
        ...metadata,
        addedBy: session.user.id,
        source: 'manual'
      }
    })

    if (!success) {
      logger.logApiResponse(requestId, '/api/pipeline/analytics', 'POST', 500, Date.now() - startTime)
      return NextResponse.json({ error: 'Failed to add data point' }, { status: 500 })
    }

    // Broadcast real-time update if requested
    if (broadcastUpdate) {
      await webSocketManager.sendToRoom(`analytics:${key}`, 'analytics_data_added', {
        key,
        value,
        metadata,
        timestamp: new Date(timestamp).toISOString(),
        addedBy: session.user.id
      })
    }

    logger.logApiResponse(requestId, '/api/pipeline/analytics', 'POST', 200, Date.now() - startTime, {
      key,
      value,
      broadcastUpdate
    })

    return NextResponse.json({
      success: true,
      key,
      value,
      metadata,
      timestamp: new Date(timestamp).toISOString(),
      message: 'Data point added successfully'
    })

  } catch (error) {
    logger.error('Failed to add analytics data point', error, { requestId })
    logger.logApiResponse(requestId, '/api/pipeline/analytics', 'POST', 500, Date.now() - startTime)

    return NextResponse.json({
      error: 'Failed to add data point',
      message: error instanceof Error ? error.message : 'Unknown error'
    }, { status: 500 })
  }
}

// Helper functions for analytics calculations
function calculateTrends(timeSeries: any[]): any {
  if (timeSeries.length < 2) return null

  const values = timeSeries.map(point => point.value)
  const timestamps = timeSeries.map(point => point.timestamp)

  // Calculate simple linear regression for trend
  const n = values.length
  const sumX = timestamps.reduce((sum, time) => sum + time, 0)
  const sumY = values.reduce((sum, val) => sum + val, 0)
  const sumXY = timestamps.reduce((sum, time, index) => sum + (time * values[index]), 0)
  const sumXX = timestamps.reduce((sum, time) => sum + (time * time), 0)

  const slope = (n * sumXY - sumX * sumY) / (n * sumXX - sumX * sumX)
  const intercept = (sumY - slope * sumX) / n

  // Calculate trend direction and strength
  const direction = slope > 0 ? 'increasing' : slope < 0 ? 'decreasing' : 'stable'
  const strength = Math.abs(slope)

  // Calculate rate of change
  const firstValue = values[0]
  const lastValue = values[values.length - 1]
  const percentChange = firstValue !== 0 ? ((lastValue - firstValue) / firstValue) * 100 : 0

  return {
    direction,
    strength,
    slope,
    intercept,
    percentChange,
    confidence: calculateTrendConfidence(values, slope, intercept, timestamps)
  }
}

function detectAnomalies(timeSeries: any[]): any[] {
  if (timeSeries.length < 10) return []

  const values = timeSeries.map(point => point.value)
  const mean = values.reduce((sum, val) => sum + val, 0) / values.length
  const variance = values.reduce((sum, val) => sum + Math.pow(val - mean, 2), 0) / values.length
  const standardDeviation = Math.sqrt(variance)

  const threshold = 2 * standardDeviation // 2-sigma rule
  const anomalies = []

  for (let i = 0; i < timeSeries.length; i++) {
    const value = values[i]
    const deviation = Math.abs(value - mean)

    if (deviation > threshold) {
      anomalies.push({
        timestamp: timeSeries[i].timestamp,
        value,
        deviation,
        severity: deviation > (3 * standardDeviation) ? 'high' : 'medium',
        type: value > mean ? 'spike' : 'dip'
      })
    }
  }

  return anomalies
}

function calculateTrendConfidence(values: number[], slope: number, intercept: number, timestamps: number[]): number {
  // Calculate R-squared for trend confidence
  const meanY = values.reduce((sum, val) => sum + val, 0) / values.length

  let ssRes = 0 // Sum of squares of residuals
  let ssTot = 0 // Total sum of squares

  for (let i = 0; i < values.length; i++) {
    const predicted = slope * timestamps[i] + intercept
    ssRes += Math.pow(values[i] - predicted, 2)
    ssTot += Math.pow(values[i] - meanY, 2)
  }

  const rSquared = ssTot === 0 ? 0 : 1 - (ssRes / ssTot)
  return Math.max(0, Math.min(1, rSquared)) // Clamp between 0 and 1
}

function calculateSummaryStats(timeSeries: any[]): any {
  if (timeSeries.length === 0) return null

  const values = timeSeries.map(point => point.value)
  const sortedValues = [...values].sort((a, b) => a - b)

  const sum = values.reduce((sum, val) => sum + val, 0)
  const mean = sum / values.length
  const median = sortedValues.length % 2 === 0
    ? (sortedValues[sortedValues.length / 2 - 1] + sortedValues[sortedValues.length / 2]) / 2
    : sortedValues[Math.floor(sortedValues.length / 2)]

  const variance = values.reduce((sum, val) => sum + Math.pow(val - mean, 2), 0) / values.length
  const standardDeviation = Math.sqrt(variance)

  const min = Math.min(...values)
  const max = Math.max(...values)
  const range = max - min

  // Calculate percentiles
  const p25Index = Math.floor(sortedValues.length * 0.25)
  const p75Index = Math.floor(sortedValues.length * 0.75)
  const p25 = sortedValues[p25Index]
  const p75 = sortedValues[p75Index]

  return {
    count: values.length,
    sum,
    mean,
    median,
    min,
    max,
    range,
    standardDeviation,
    variance,
    percentiles: {
      p25,
      p50: median,
      p75
    },
    timeRange: {
      start: new Date(timeSeries[0].timestamp).toISOString(),
      end: new Date(timeSeries[timeSeries.length - 1].timestamp).toISOString()
    }
  }
}