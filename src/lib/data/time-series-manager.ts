import { redisManager, RedisDatabase } from '@/lib/redis-manager'
import { logger } from '@/lib/logger'
import { z } from 'zod'

export interface TimeSeriesDataPoint {
  timestamp: number
  value: number | string | Record<string, any>
  metadata?: Record<string, any>
}

export interface TimeSeriesQuery {
  key: string
  startTime?: number
  endTime?: number
  limit?: number
  aggregation?: 'avg' | 'sum' | 'min' | 'max' | 'count' | 'last' | 'first'
  interval?: number // for aggregation grouping
  filters?: Record<string, any>
}

export interface TimeSeriesConfig {
  retention: number // seconds
  maxPoints: number
  compressionEnabled: boolean
  aggregationLevels: Array<{
    interval: number // seconds
    retention: number // seconds
    method: 'avg' | 'sum' | 'min' | 'max' | 'count'
  }>
}

export interface AggregatedDataPoint {
  timestamp: number
  value: number
  count: number
  aggregationMethod: string
  interval: number
}

export interface PerformanceMetrics {
  campaignId: string
  timestamp: number
  metrics: {
    impressions: number
    clicks: number
    spend: number
    conversions: number
    cpm: number
    cpc: number
    ctr: number
    roas: number
    conversionRate: number
  }
  breakdown?: {
    age?: Record<string, any>
    gender?: Record<string, any>
    placement?: Record<string, any>
    device?: Record<string, any>
    country?: Record<string, any>
  }
}

export interface EventData {
  eventType: string
  entityId: string
  entityType: 'campaign' | 'adset' | 'ad' | 'account'
  userId?: string
  timestamp: number
  data: Record<string, any>
  tags?: string[]
}

export class TimeSeriesManager {
  private readonly DEFAULT_CONFIG: TimeSeriesConfig = {
    retention: 90 * 24 * 60 * 60, // 90 days
    maxPoints: 100000,
    compressionEnabled: true,
    aggregationLevels: [
      { interval: 300, retention: 7 * 24 * 60 * 60, method: 'avg' }, // 5min for 7 days
      { interval: 3600, retention: 30 * 24 * 60 * 60, method: 'avg' }, // 1hour for 30 days
      { interval: 86400, retention: 365 * 24 * 60 * 60, method: 'avg' } // 1day for 1 year
    ]
  }

  private configs: Map<string, TimeSeriesConfig> = new Map()

  async addDataPoint(key: string, dataPoint: TimeSeriesDataPoint, config?: Partial<TimeSeriesConfig>): Promise<boolean> {
    try {
      const client = redisManager.getConnection(RedisDatabase.ANALYTICS)
      const fullConfig = { ...this.DEFAULT_CONFIG, ...config }

      // Validate data point
      if (!this.validateDataPoint(dataPoint)) {
        logger.error('Invalid data point', { key, dataPoint })
        return false
      }

      // Store raw data point
      const score = dataPoint.timestamp
      const member = JSON.stringify({
        value: dataPoint.value,
        metadata: dataPoint.metadata || {}
      })

      await client.zadd(`ts:raw:${key}`, score, member)

      // Apply retention policy for raw data
      const retentionCutoff = Date.now() - fullConfig.retention * 1000
      await client.zremrangebyscore(`ts:raw:${key}`, 0, retentionCutoff)

      // Maintain max points limit
      const currentCount = await client.zcard(`ts:raw:${key}`)
      if (currentCount > fullConfig.maxPoints) {
        const removeCount = currentCount - fullConfig.maxPoints
        await client.zremrangebyrank(`ts:raw:${key}`, 0, removeCount - 1)
      }

      // Set expiration
      await client.expire(`ts:raw:${key}`, fullConfig.retention)

      // Process aggregations
      if (fullConfig.aggregationLevels.length > 0) {
        await this.processAggregations(key, dataPoint, fullConfig)
      }

      // Store configuration if provided
      if (config) {
        this.configs.set(key, fullConfig)
        await this.saveConfig(key, fullConfig)
      }

      logger.debug('Time series data point added', {
        key,
        timestamp: dataPoint.timestamp,
        valueType: typeof dataPoint.value
      })

      return true

    } catch (error) {
      logger.error('Failed to add time series data point', {
        key,
        error: error instanceof Error ? error.message : 'Unknown error'
      })
      return false
    }
  }

  async addBulkDataPoints(key: string, dataPoints: TimeSeriesDataPoint[], config?: Partial<TimeSeriesConfig>): Promise<number> {
    try {
      const client = redisManager.getConnection(RedisDatabase.ANALYTICS)
      const fullConfig = { ...this.DEFAULT_CONFIG, ...config }

      // Prepare bulk insert data
      const pipeline = client.pipeline()
      let successCount = 0

      for (const dataPoint of dataPoints) {
        if (this.validateDataPoint(dataPoint)) {
          const score = dataPoint.timestamp
          const member = JSON.stringify({
            value: dataPoint.value,
            metadata: dataPoint.metadata || {}
          })

          pipeline.zadd(`ts:raw:${key}`, score, member)
          successCount++
        }
      }

      // Execute bulk insert
      await pipeline.exec()

      // Apply retention and limits
      const retentionCutoff = Date.now() - fullConfig.retention * 1000
      await client.zremrangebyscore(`ts:raw:${key}`, 0, retentionCutoff)

      const currentCount = await client.zcard(`ts:raw:${key}`)
      if (currentCount > fullConfig.maxPoints) {
        const removeCount = currentCount - fullConfig.maxPoints
        await client.zremrangebyrank(`ts:raw:${key}`, 0, removeCount - 1)
      }

      await client.expire(`ts:raw:${key}`, fullConfig.retention)

      logger.info('Bulk time series data added', {
        key,
        totalPoints: dataPoints.length,
        successCount,
        failedCount: dataPoints.length - successCount
      })

      return successCount

    } catch (error) {
      logger.error('Failed to add bulk time series data', {
        key,
        pointCount: dataPoints.length,
        error: error instanceof Error ? error.message : 'Unknown error'
      })
      return 0
    }
  }

  async queryData(query: TimeSeriesQuery): Promise<TimeSeriesDataPoint[]> {
    try {
      const client = redisManager.getConnection(RedisDatabase.ANALYTICS)

      const { key, startTime, endTime, limit = 1000, aggregation } = query

      let dataKey = `ts:raw:${key}`

      // Use aggregated data if aggregation is requested
      if (aggregation && query.interval) {
        dataKey = `ts:agg:${key}:${query.interval}:${aggregation}`
      }

      // Build Redis query parameters
      const min = startTime || 0
      const max = endTime || Date.now()

      // Query data
      let rawData: string[]
      if (limit) {
        rawData = await client.zrevrangebyscore(dataKey, max, min, 'LIMIT', 0, limit)
      } else {
        rawData = await client.zrevrangebyscore(dataKey, max, min)
      }

      // Parse and return data points
      const dataPoints: TimeSeriesDataPoint[] = []

      for (const item of rawData) {
        try {
          const parsed = JSON.parse(item)
          const timestamp = await client.zscore(dataKey, item)

          dataPoints.push({
            timestamp: timestamp || 0,
            value: parsed.value,
            metadata: parsed.metadata
          })
        } catch (parseError) {
          logger.warn('Failed to parse time series data point', { key, item })
        }
      }

      // Apply additional filtering if specified
      let filteredData = dataPoints
      if (query.filters) {
        filteredData = this.applyFilters(dataPoints, query.filters)
      }

      logger.debug('Time series query executed', {
        key,
        resultCount: filteredData.length,
        startTime,
        endTime,
        aggregation
      })

      return filteredData

    } catch (error) {
      logger.error('Failed to query time series data', {
        query,
        error: error instanceof Error ? error.message : 'Unknown error'
      })
      return []
    }
  }

  async getLatestValue(key: string): Promise<TimeSeriesDataPoint | null> {
    try {
      const latest = await this.queryData({
        key,
        limit: 1
      })

      return latest.length > 0 ? latest[0] : null

    } catch (error) {
      logger.error('Failed to get latest value', {
        key,
        error: error instanceof Error ? error.message : 'Unknown error'
      })
      return null
    }
  }

  async calculateStatistics(key: string, startTime?: number, endTime?: number): Promise<{
    count: number
    avg: number
    min: number
    max: number
    sum: number
    stddev: number
  } | null> {
    try {
      const dataPoints = await this.queryData({
        key,
        startTime,
        endTime
      })

      if (dataPoints.length === 0) {
        return null
      }

      const numericValues = dataPoints
        .map(point => typeof point.value === 'number' ? point.value : 0)
        .filter(value => !isNaN(value))

      if (numericValues.length === 0) {
        return null
      }

      const count = numericValues.length
      const sum = numericValues.reduce((acc, val) => acc + val, 0)
      const avg = sum / count
      const min = Math.min(...numericValues)
      const max = Math.max(...numericValues)

      // Calculate standard deviation
      const variance = numericValues.reduce((acc, val) => acc + Math.pow(val - avg, 2), 0) / count
      const stddev = Math.sqrt(variance)

      return {
        count,
        avg: Math.round(avg * 100) / 100,
        min,
        max,
        sum,
        stddev: Math.round(stddev * 100) / 100
      }

    } catch (error) {
      logger.error('Failed to calculate statistics', {
        key,
        error: error instanceof Error ? error.message : 'Unknown error'
      })
      return null
    }
  }

  async storePerformanceMetrics(metrics: PerformanceMetrics): Promise<boolean> {
    try {
      const campaignKey = `campaign:${metrics.campaignId}`

      // Store individual metrics as separate time series
      const metricPromises = Object.entries(metrics.metrics).map(([metricName, value]) =>
        this.addDataPoint(`${campaignKey}:${metricName}`, {
          timestamp: metrics.timestamp,
          value,
          metadata: {
            campaignId: metrics.campaignId,
            metricType: metricName
          }
        })
      )

      // Store complete metrics object
      const completeMetricsPromise = this.addDataPoint(`${campaignKey}:complete`, {
        timestamp: metrics.timestamp,
        value: metrics.metrics,
        metadata: {
          campaignId: metrics.campaignId,
          breakdown: metrics.breakdown
        }
      })

      await Promise.all([...metricPromises, completeMetricsPromise])

      // Store breakdown data if provided
      if (metrics.breakdown) {
        const breakdownPromises = Object.entries(metrics.breakdown).map(([dimension, data]) =>
          this.addDataPoint(`${campaignKey}:breakdown:${dimension}`, {
            timestamp: metrics.timestamp,
            value: data,
            metadata: {
              campaignId: metrics.campaignId,
              dimension
            }
          })
        )

        await Promise.all(breakdownPromises)
      }

      logger.debug('Performance metrics stored', {
        campaignId: metrics.campaignId,
        timestamp: metrics.timestamp,
        metricsCount: Object.keys(metrics.metrics).length
      })

      return true

    } catch (error) {
      logger.error('Failed to store performance metrics', {
        campaignId: metrics.campaignId,
        error: error instanceof Error ? error.message : 'Unknown error'
      })
      return false
    }
  }

  async storeEvent(event: EventData): Promise<boolean> {
    try {
      const eventKey = `events:${event.entityType}:${event.entityId}`

      const success = await this.addDataPoint(eventKey, {
        timestamp: event.timestamp,
        value: event.data,
        metadata: {
          eventType: event.eventType,
          entityType: event.entityType,
          entityId: event.entityId,
          userId: event.userId,
          tags: event.tags
        }
      })

      // Also store in global event stream
      await this.addDataPoint('events:global', {
        timestamp: event.timestamp,
        value: {
          eventType: event.eventType,
          entityType: event.entityType,
          entityId: event.entityId,
          data: event.data
        },
        metadata: {
          userId: event.userId,
          tags: event.tags
        }
      })

      // Store by event type for easier querying
      await this.addDataPoint(`events:type:${event.eventType}`, {
        timestamp: event.timestamp,
        value: {
          entityType: event.entityType,
          entityId: event.entityId,
          data: event.data
        },
        metadata: {
          userId: event.userId,
          tags: event.tags
        }
      })

      return success

    } catch (error) {
      logger.error('Failed to store event', {
        event,
        error: error instanceof Error ? error.message : 'Unknown error'
      })
      return false
    }
  }

  async getPerformanceTrends(
    campaignId: string,
    metric: string,
    timeRange: { start: number; end: number },
    interval: number = 3600 // 1 hour default
  ): Promise<Array<{ timestamp: number; value: number; change?: number }>> {
    try {
      const dataPoints = await this.queryData({
        key: `campaign:${campaignId}:${metric}`,
        startTime: timeRange.start,
        endTime: timeRange.end,
        aggregation: 'avg',
        interval
      })

      // Calculate period-over-period changes
      const trendsWithChange = dataPoints.map((point, index) => {
        const result: { timestamp: number; value: number; change?: number } = {
          timestamp: point.timestamp,
          value: typeof point.value === 'number' ? point.value : 0
        }

        if (index > 0 && typeof dataPoints[index - 1].value === 'number') {
          const previousValue = dataPoints[index - 1].value as number
          if (previousValue !== 0) {
            result.change = ((result.value - previousValue) / previousValue) * 100
          }
        }

        return result
      })

      return trendsWithChange

    } catch (error) {
      logger.error('Failed to get performance trends', {
        campaignId,
        metric,
        error: error instanceof Error ? error.message : 'Unknown error'
      })
      return []
    }
  }

  async detectAnomalies(
    key: string,
    threshold: number = 2.0, // Standard deviations
    windowSize: number = 50
  ): Promise<Array<{ timestamp: number; value: number; expectedValue: number; deviation: number }>> {
    try {
      const recentData = await this.queryData({
        key,
        limit: windowSize * 2 // Get more data for better baseline
      })

      if (recentData.length < windowSize) {
        return [] // Not enough data for anomaly detection
      }

      const anomalies = []
      const baselineData = recentData.slice(windowSize) // Older data for baseline
      const testData = recentData.slice(0, windowSize) // Recent data to test

      // Calculate baseline statistics
      const baselineValues = baselineData
        .map(point => typeof point.value === 'number' ? point.value : 0)
        .filter(value => !isNaN(value))

      if (baselineValues.length === 0) return []

      const baselineAvg = baselineValues.reduce((sum, val) => sum + val, 0) / baselineValues.length
      const baselineVariance = baselineValues.reduce((sum, val) => sum + Math.pow(val - baselineAvg, 2), 0) / baselineValues.length
      const baselineStdDev = Math.sqrt(baselineVariance)

      // Check each test point for anomalies
      for (const point of testData) {
        if (typeof point.value === 'number') {
          const deviation = Math.abs(point.value - baselineAvg) / baselineStdDev

          if (deviation > threshold) {
            anomalies.push({
              timestamp: point.timestamp,
              value: point.value,
              expectedValue: baselineAvg,
              deviation
            })
          }
        }
      }

      return anomalies

    } catch (error) {
      logger.error('Failed to detect anomalies', {
        key,
        error: error instanceof Error ? error.message : 'Unknown error'
      })
      return []
    }
  }

  async deleteTimeSeries(key: string): Promise<boolean> {
    try {
      const client = redisManager.getConnection(RedisDatabase.ANALYTICS)

      // Delete raw data
      await client.del(`ts:raw:${key}`)

      // Delete aggregated data
      const aggregationKeys = await client.keys(`ts:agg:${key}:*`)
      if (aggregationKeys.length > 0) {
        await client.del(...aggregationKeys)
      }

      // Delete configuration
      await client.hdel('ts:configs', key)
      this.configs.delete(key)

      logger.info('Time series deleted', { key })
      return true

    } catch (error) {
      logger.error('Failed to delete time series', {
        key,
        error: error instanceof Error ? error.message : 'Unknown error'
      })
      return false
    }
  }

  private async processAggregations(key: string, dataPoint: TimeSeriesDataPoint, config: TimeSeriesConfig): Promise<void> {
    try {
      const client = redisManager.getConnection(RedisDatabase.ANALYTICS)

      for (const aggLevel of config.aggregationLevels) {
        // Calculate the bucket timestamp for this aggregation level
        const bucketTimestamp = Math.floor(dataPoint.timestamp / (aggLevel.interval * 1000)) * (aggLevel.interval * 1000)
        const aggKey = `ts:agg:${key}:${aggLevel.interval}:${aggLevel.method}`

        // Get existing aggregated value for this bucket
        const existingData = await client.hgetall(`ts:agg:bucket:${aggKey}:${bucketTimestamp}`)

        let newValue: number
        let count = 1

        if (typeof dataPoint.value !== 'number') {
          continue // Skip non-numeric values for aggregation
        }

        if (Object.keys(existingData).length > 0) {
          const existingValue = parseFloat(existingData.value || '0')
          const existingCount = parseInt(existingData.count || '1')

          switch (aggLevel.method) {
            case 'avg':
              newValue = ((existingValue * existingCount) + dataPoint.value) / (existingCount + 1)
              count = existingCount + 1
              break
            case 'sum':
              newValue = existingValue + dataPoint.value
              count = existingCount + 1
              break
            case 'min':
              newValue = Math.min(existingValue, dataPoint.value)
              count = existingCount + 1
              break
            case 'max':
              newValue = Math.max(existingValue, dataPoint.value)
              count = existingCount + 1
              break
            case 'count':
              newValue = existingCount + 1
              count = existingCount + 1
              break
            default:
              newValue = dataPoint.value
          }
        } else {
          newValue = aggLevel.method === 'count' ? 1 : dataPoint.value
        }

        // Store aggregated value
        await client.hset(`ts:agg:bucket:${aggKey}:${bucketTimestamp}`, {
          value: newValue.toString(),
          count: count.toString(),
          lastUpdate: dataPoint.timestamp.toString()
        })

        // Update the sorted set
        await client.zadd(aggKey, bucketTimestamp, JSON.stringify({
          value: newValue,
          count,
          method: aggLevel.method
        }))

        // Apply retention to aggregated data
        const aggRetentionCutoff = Date.now() - aggLevel.retention * 1000
        await client.zremrangebyscore(aggKey, 0, aggRetentionCutoff)

        // Clean up bucket data
        const bucketKeys = await client.keys(`ts:agg:bucket:${aggKey}:*`)
        for (const bucketKey of bucketKeys) {
          const bucketTimestampStr = bucketKey.split(':').pop()
          if (bucketTimestampStr && parseInt(bucketTimestampStr) < aggRetentionCutoff) {
            await client.del(bucketKey)
          }
        }

        await client.expire(aggKey, aggLevel.retention)
      }

    } catch (error) {
      logger.error('Failed to process aggregations', {
        key,
        error: error instanceof Error ? error.message : 'Unknown error'
      })
    }
  }

  private validateDataPoint(dataPoint: TimeSeriesDataPoint): boolean {
    if (!dataPoint.timestamp || dataPoint.timestamp <= 0) {
      return false
    }

    if (dataPoint.value === undefined || dataPoint.value === null) {
      return false
    }

    return true
  }

  private applyFilters(dataPoints: TimeSeriesDataPoint[], filters: Record<string, any>): TimeSeriesDataPoint[] {
    return dataPoints.filter(point => {
      if (!point.metadata) return true

      for (const [filterKey, filterValue] of Object.entries(filters)) {
        const metadataValue = point.metadata[filterKey]

        if (Array.isArray(filterValue)) {
          if (!filterValue.includes(metadataValue)) {
            return false
          }
        } else if (metadataValue !== filterValue) {
          return false
        }
      }

      return true
    })
  }

  private async saveConfig(key: string, config: TimeSeriesConfig): Promise<void> {
    try {
      const client = redisManager.getConnection(RedisDatabase.ANALYTICS)
      await client.hset('ts:configs', key, JSON.stringify(config))

    } catch (error) {
      logger.error('Failed to save time series config', {
        key,
        error: error instanceof Error ? error.message : 'Unknown error'
      })
    }
  }

  private async loadConfig(key: string): Promise<TimeSeriesConfig | null> {
    try {
      const client = redisManager.getConnection(RedisDatabase.ANALYTICS)
      const configData = await client.hget('ts:configs', key)

      return configData ? JSON.parse(configData) : null

    } catch (error) {
      logger.error('Failed to load time series config', {
        key,
        error: error instanceof Error ? error.message : 'Unknown error'
      })
      return null
    }
  }
}

export const timeSeriesManager = new TimeSeriesManager()