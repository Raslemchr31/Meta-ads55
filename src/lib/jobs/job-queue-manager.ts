import Bull, { Queue, Job, JobOptions } from 'bull'
import { redisManager, RedisDatabase } from '@/lib/redis-manager'
import { logger } from '@/lib/logger'
import { auditLogger } from '@/lib/auth/audit-logger'

export type JobType =
  | 'campaign_sync'
  | 'report_generation'
  | 'data_backup'
  | 'performance_optimization'
  | 'email_notification'
  | 'cache_warmup'
  | 'data_cleanup'
  | 'insights_analysis'
  | 'bid_optimization'
  | 'audience_analysis'

export type JobPriority = 'low' | 'normal' | 'high' | 'critical'

export interface BaseJobData {
  userId?: string
  accountId?: string
  campaignId?: string
  timestamp: string
  metadata?: Record<string, any>
}

export interface CampaignSyncJobData extends BaseJobData {
  adAccountId: string
  syncType: 'full' | 'incremental' | 'metrics_only'
  dateRange?: {
    since: string
    until: string
  }
  forceRefresh?: boolean
}

export interface ReportGenerationJobData extends BaseJobData {
  reportType: 'campaign_performance' | 'audience_insights' | 'optimization_summary' | 'custom'
  reportConfig: {
    dateRange: { since: string; until: string }
    metrics: string[]
    breakdown?: string[]
    filters?: Record<string, any>
  }
  outputFormat: 'pdf' | 'excel' | 'csv' | 'json'
  deliveryMethod: 'email' | 'download' | 'webhook'
  recipients?: string[]
}

export interface DataBackupJobData extends BaseJobData {
  backupType: 'full' | 'incremental' | 'logs_only'
  retention: number // days
  encryptionKey?: string
  compressionLevel: number
  destination: 's3' | 'gcs' | 'azure' | 'local'
}

export interface OptimizationJobData extends BaseJobData {
  optimizationType: 'bid_optimization' | 'budget_reallocation' | 'audience_expansion' | 'creative_testing'
  targetEntity: {
    type: 'campaign' | 'adset' | 'ad'
    id: string
  }
  constraints: {
    maxBudgetChange?: number
    minROAS?: number
    maxCPC?: number
  }
  autoApply: boolean
}

export interface JobResult {
  success: boolean
  data?: any
  error?: string
  metrics?: {
    duration: number
    itemsProcessed?: number
    bytesTransferred?: number
    apiCallsUsed?: number
  }
  warnings?: string[]
}

export interface QueueStats {
  name: string
  waiting: number
  active: number
  completed: number
  failed: number
  delayed: number
  paused: boolean
}

export class JobQueueManager {
  private queues: Map<JobType, Queue> = new Map()
  private processors: Map<JobType, Function> = new Map()

  private readonly QUEUE_CONFIG: Record<JobType, {
    concurrency: number
    defaultDelay: number
    attempts: number
    backoff: 'fixed' | 'exponential'
    priority: number
  }> = {
    campaign_sync: {
      concurrency: 5,
      defaultDelay: 0,
      attempts: 3,
      backoff: 'exponential',
      priority: 5
    },
    report_generation: {
      concurrency: 3,
      defaultDelay: 0,
      attempts: 2,
      backoff: 'fixed',
      priority: 3
    },
    data_backup: {
      concurrency: 1,
      defaultDelay: 0,
      attempts: 3,
      backoff: 'exponential',
      priority: 2
    },
    performance_optimization: {
      concurrency: 2,
      defaultDelay: 0,
      attempts: 2,
      backoff: 'exponential',
      priority: 7
    },
    email_notification: {
      concurrency: 10,
      defaultDelay: 0,
      attempts: 3,
      backoff: 'fixed',
      priority: 6
    },
    cache_warmup: {
      concurrency: 3,
      defaultDelay: 0,
      attempts: 2,
      backoff: 'fixed',
      priority: 4
    },
    data_cleanup: {
      concurrency: 1,
      defaultDelay: 0,
      attempts: 1,
      backoff: 'fixed',
      priority: 1
    },
    insights_analysis: {
      concurrency: 4,
      defaultDelay: 0,
      attempts: 2,
      backoff: 'exponential',
      priority: 5
    },
    bid_optimization: {
      concurrency: 3,
      defaultDelay: 0,
      attempts: 3,
      backoff: 'exponential',
      priority: 8
    },
    audience_analysis: {
      concurrency: 2,
      defaultDelay: 0,
      attempts: 2,
      backoff: 'exponential',
      priority: 4
    }
  }

  async initialize(): Promise<void> {
    try {
      const redisConnection = redisManager.getConnection(RedisDatabase.JOBS)

      // Create queues for each job type
      for (const [jobType, config] of Object.entries(this.QUEUE_CONFIG)) {
        const queue = new Bull(jobType, {
          redis: {
            port: 6379,
            host: 'localhost' // This would come from config
          },
          defaultJobOptions: {
            attempts: config.attempts,
            backoff: {
              type: config.backoff,
              delay: config.backoff === 'exponential' ? 2000 : 5000
            },
            removeOnComplete: 50, // Keep last 50 completed jobs
            removeOnFail: 20 // Keep last 20 failed jobs
          },
          settings: {
            stalledInterval: 30 * 1000, // 30 seconds
            maxStalledCount: 1
          }
        })

        this.queues.set(jobType as JobType, queue)

        // Set up queue event handlers
        this.setupQueueEventHandlers(queue, jobType as JobType)
      }

      // Register job processors
      this.registerProcessors()

      logger.info('Job queue manager initialized successfully', {
        queueCount: this.queues.size
      })

    } catch (error) {
      logger.error('Failed to initialize job queue manager', {
        error: error instanceof Error ? error.message : 'Unknown error'
      })
      throw error
    }
  }

  private setupQueueEventHandlers(queue: Queue, jobType: JobType): void {
    queue.on('completed', async (job: Job, result: JobResult) => {
      logger.info('Job completed successfully', {
        jobType,
        jobId: job.id,
        duration: result.metrics?.duration,
        itemsProcessed: result.metrics?.itemsProcessed
      })

      await this.recordJobCompletion(job, result)
    })

    queue.on('failed', async (job: Job, error: Error) => {
      logger.error('Job failed', {
        jobType,
        jobId: job.id,
        error: error.message,
        attempts: job.attemptsMade,
        data: job.data
      })

      await this.recordJobFailure(job, error)
    })

    queue.on('stalled', (job: Job) => {
      logger.warn('Job stalled', {
        jobType,
        jobId: job.id,
        data: job.data
      })
    })

    queue.on('progress', (job: Job, progress: number) => {
      logger.debug('Job progress updated', {
        jobType,
        jobId: job.id,
        progress
      })
    })
  }

  private registerProcessors(): void {
    // Register processors for each job type
    this.processors.set('campaign_sync', this.processCampaignSync.bind(this))
    this.processors.set('report_generation', this.processReportGeneration.bind(this))
    this.processors.set('data_backup', this.processDataBackup.bind(this))
    this.processors.set('performance_optimization', this.processPerformanceOptimization.bind(this))
    this.processors.set('email_notification', this.processEmailNotification.bind(this))
    this.processors.set('cache_warmup', this.processCacheWarmup.bind(this))
    this.processors.set('data_cleanup', this.processDataCleanup.bind(this))
    this.processors.set('insights_analysis', this.processInsightsAnalysis.bind(this))
    this.processors.set('bid_optimization', this.processBidOptimization.bind(this))
    this.processors.set('audience_analysis', this.processAudienceAnalysis.bind(this))

    // Set up processors for each queue
    for (const [jobType, queue] of this.queues) {
      const processor = this.processors.get(jobType)
      const config = this.QUEUE_CONFIG[jobType]

      if (processor) {
        queue.process(config.concurrency, processor)
      }
    }
  }

  async addJob<T extends BaseJobData>(
    jobType: JobType,
    data: T,
    options?: {
      priority?: JobPriority
      delay?: number
      repeat?: {
        cron?: string
        every?: number
      }
      attempts?: number
    }
  ): Promise<Job<T> | null> {
    try {
      const queue = this.queues.get(jobType)
      if (!queue) {
        logger.error('Queue not found for job type', { jobType })
        return null
      }

      const priorityMap: Record<JobPriority, number> = {
        critical: 10,
        high: 7,
        normal: 5,
        low: 2
      }

      const jobOptions: JobOptions = {
        priority: priorityMap[options?.priority || 'normal'],
        delay: options?.delay || 0,
        attempts: options?.attempts || this.QUEUE_CONFIG[jobType].attempts
      }

      if (options?.repeat) {
        jobOptions.repeat = options.repeat
      }

      const job = await queue.add(jobType, {
        ...data,
        timestamp: new Date().toISOString()
      }, jobOptions)

      logger.info('Job added to queue', {
        jobType,
        jobId: job.id,
        priority: options?.priority || 'normal',
        delay: options?.delay || 0
      })

      // Log job creation for audit
      if (data.userId) {
        await auditLogger.logEvent({
          eventType: 'api_access',
          userId: data.userId,
          ipAddress: '127.0.0.1', // Server-side job
          userAgent: 'job-queue-manager',
          riskLevel: 'low',
          outcome: 'success',
          source: 'job_queue',
          details: {
            action: 'job_created',
            jobType,
            jobId: job.id
          }
        })
      }

      return job

    } catch (error) {
      logger.error('Failed to add job to queue', {
        jobType,
        error: error instanceof Error ? error.message : 'Unknown error'
      })
      return null
    }
  }

  async getJob(jobType: JobType, jobId: string): Promise<Job | null> {
    try {
      const queue = this.queues.get(jobType)
      if (!queue) return null

      return await queue.getJob(jobId)

    } catch (error) {
      logger.error('Failed to get job', {
        jobType,
        jobId,
        error: error instanceof Error ? error.message : 'Unknown error'
      })
      return null
    }
  }

  async cancelJob(jobType: JobType, jobId: string): Promise<boolean> {
    try {
      const job = await this.getJob(jobType, jobId)
      if (!job) return false

      await job.remove()

      logger.info('Job cancelled', { jobType, jobId })
      return true

    } catch (error) {
      logger.error('Failed to cancel job', {
        jobType,
        jobId,
        error: error instanceof Error ? error.message : 'Unknown error'
      })
      return false
    }
  }

  async pauseQueue(jobType: JobType): Promise<boolean> {
    try {
      const queue = this.queues.get(jobType)
      if (!queue) return false

      await queue.pause()

      logger.info('Queue paused', { jobType })
      return true

    } catch (error) {
      logger.error('Failed to pause queue', {
        jobType,
        error: error instanceof Error ? error.message : 'Unknown error'
      })
      return false
    }
  }

  async resumeQueue(jobType: JobType): Promise<boolean> {
    try {
      const queue = this.queues.get(jobType)
      if (!queue) return false

      await queue.resume()

      logger.info('Queue resumed', { jobType })
      return true

    } catch (error) {
      logger.error('Failed to resume queue', {
        jobType,
        error: error instanceof Error ? error.message : 'Unknown error'
      })
      return false
    }
  }

  async getQueueStats(): Promise<QueueStats[]> {
    const stats: QueueStats[] = []

    for (const [jobType, queue] of this.queues) {
      try {
        const waiting = await queue.waiting()
        const active = await queue.active()
        const completed = await queue.completed()
        const failed = await queue.failed()
        const delayed = await queue.delayed()
        const isPaused = await queue.isPaused()

        stats.push({
          name: jobType,
          waiting: waiting.length,
          active: active.length,
          completed: completed.length,
          failed: failed.length,
          delayed: delayed.length,
          paused: isPaused
        })

      } catch (error) {
        logger.error('Failed to get queue stats', {
          jobType,
          error: error instanceof Error ? error.message : 'Unknown error'
        })
      }
    }

    return stats
  }

  async retryFailedJobs(jobType: JobType, maxRetries: number = 10): Promise<number> {
    try {
      const queue = this.queues.get(jobType)
      if (!queue) return 0

      const failedJobs = await queue.getFailed(0, maxRetries - 1)
      let retriedCount = 0

      for (const job of failedJobs) {
        try {
          await job.retry()
          retriedCount++
        } catch (error) {
          logger.error('Failed to retry job', {
            jobType,
            jobId: job.id,
            error: error instanceof Error ? error.message : 'Unknown error'
          })
        }
      }

      logger.info('Failed jobs retried', { jobType, retriedCount })
      return retriedCount

    } catch (error) {
      logger.error('Failed to retry failed jobs', {
        jobType,
        error: error instanceof Error ? error.message : 'Unknown error'
      })
      return 0
    }
  }

  // Job processors
  private async processCampaignSync(job: Job<CampaignSyncJobData>): Promise<JobResult> {
    const startTime = Date.now()

    try {
      job.progress(10)

      const { adAccountId, syncType, dateRange, forceRefresh } = job.data

      logger.info('Starting campaign sync', {
        jobId: job.id,
        adAccountId,
        syncType
      })

      // Simulate campaign sync process
      job.progress(30)
      await new Promise(resolve => setTimeout(resolve, 2000)) // Simulate API calls

      job.progress(60)
      await new Promise(resolve => setTimeout(resolve, 1000)) // Simulate data processing

      job.progress(90)
      await new Promise(resolve => setTimeout(resolve, 500)) // Simulate cache update

      job.progress(100)

      const duration = Date.now() - startTime

      return {
        success: true,
        data: {
          adAccountId,
          syncType,
          syncedCampaigns: 25,
          syncedAdSets: 150,
          syncedAds: 500
        },
        metrics: {
          duration,
          itemsProcessed: 675,
          apiCallsUsed: 15
        }
      }

    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error',
        metrics: {
          duration: Date.now() - startTime
        }
      }
    }
  }

  private async processReportGeneration(job: Job<ReportGenerationJobData>): Promise<JobResult> {
    const startTime = Date.now()

    try {
      const { reportType, reportConfig, outputFormat, deliveryMethod } = job.data

      logger.info('Starting report generation', {
        jobId: job.id,
        reportType,
        outputFormat
      })

      job.progress(25)
      // Simulate data collection
      await new Promise(resolve => setTimeout(resolve, 3000))

      job.progress(50)
      // Simulate report processing
      await new Promise(resolve => setTimeout(resolve, 2000))

      job.progress(75)
      // Simulate report generation
      await new Promise(resolve => setTimeout(resolve, 1500))

      job.progress(100)

      const duration = Date.now() - startTime

      return {
        success: true,
        data: {
          reportType,
          outputFormat,
          reportSize: '2.5MB',
          downloadUrl: `/reports/download/${job.id}`
        },
        metrics: {
          duration,
          itemsProcessed: 1000,
          bytesTransferred: 2621440
        }
      }

    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error',
        metrics: {
          duration: Date.now() - startTime
        }
      }
    }
  }

  private async processDataBackup(job: Job<DataBackupJobData>): Promise<JobResult> {
    const startTime = Date.now()

    try {
      const { backupType, retention, destination } = job.data

      logger.info('Starting data backup', {
        jobId: job.id,
        backupType,
        destination
      })

      job.progress(20)
      await new Promise(resolve => setTimeout(resolve, 5000)) // Simulate backup

      job.progress(100)

      const duration = Date.now() - startTime

      return {
        success: true,
        data: {
          backupType,
          destination,
          backupSize: '150MB',
          backupPath: `/backups/${Date.now()}.tar.gz`
        },
        metrics: {
          duration,
          bytesTransferred: 157286400
        }
      }

    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error',
        metrics: {
          duration: Date.now() - startTime
        }
      }
    }
  }

  private async processPerformanceOptimization(job: Job<OptimizationJobData>): Promise<JobResult> {
    const startTime = Date.now()

    try {
      const { optimizationType, targetEntity, constraints, autoApply } = job.data

      logger.info('Starting performance optimization', {
        jobId: job.id,
        optimizationType,
        targetEntity
      })

      job.progress(25)
      await new Promise(resolve => setTimeout(resolve, 2000)) // Simulate analysis

      job.progress(75)
      await new Promise(resolve => setTimeout(resolve, 1000)) // Simulate optimization

      job.progress(100)

      const duration = Date.now() - startTime

      return {
        success: true,
        data: {
          optimizationType,
          targetEntity,
          recommendations: 5,
          appliedChanges: autoApply ? 3 : 0,
          estimatedImpact: '15% improvement in ROAS'
        },
        metrics: {
          duration,
          itemsProcessed: 1
        }
      }

    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error',
        metrics: {
          duration: Date.now() - startTime
        }
      }
    }
  }

  // Placeholder processors for other job types
  private async processEmailNotification(job: Job): Promise<JobResult> {
    // Email notification processing logic
    return { success: true, metrics: { duration: 500 } }
  }

  private async processCacheWarmup(job: Job): Promise<JobResult> {
    // Cache warmup processing logic
    return { success: true, metrics: { duration: 2000 } }
  }

  private async processDataCleanup(job: Job): Promise<JobResult> {
    // Data cleanup processing logic
    return { success: true, metrics: { duration: 10000 } }
  }

  private async processInsightsAnalysis(job: Job): Promise<JobResult> {
    // Insights analysis processing logic
    return { success: true, metrics: { duration: 5000 } }
  }

  private async processBidOptimization(job: Job): Promise<JobResult> {
    // Bid optimization processing logic
    return { success: true, metrics: { duration: 3000 } }
  }

  private async processAudienceAnalysis(job: Job): Promise<JobResult> {
    // Audience analysis processing logic
    return { success: true, metrics: { duration: 4000 } }
  }

  private async recordJobCompletion(job: Job, result: JobResult): Promise<void> {
    try {
      const client = redisManager.getConnection(RedisDatabase.ANALYTICS)

      // Store job completion metrics
      const completionData = {
        jobId: job.id,
        jobType: job.name,
        completedAt: new Date().toISOString(),
        duration: result.metrics?.duration || 0,
        success: result.success,
        itemsProcessed: result.metrics?.itemsProcessed || 0
      }

      await client.lpush('job:completions', JSON.stringify(completionData))
      await client.ltrim('job:completions', 0, 9999) // Keep last 10k
      await client.expire('job:completions', 30 * 24 * 60 * 60) // 30 days

    } catch (error) {
      logger.error('Failed to record job completion', {
        jobId: job.id,
        error: error instanceof Error ? error.message : 'Unknown error'
      })
    }
  }

  private async recordJobFailure(job: Job, error: Error): Promise<void> {
    try {
      const client = redisManager.getConnection(RedisDatabase.ANALYTICS)

      // Store job failure data
      const failureData = {
        jobId: job.id,
        jobType: job.name,
        failedAt: new Date().toISOString(),
        error: error.message,
        attempts: job.attemptsMade,
        data: job.data
      }

      await client.lpush('job:failures', JSON.stringify(failureData))
      await client.ltrim('job:failures', 0, 4999) // Keep last 5k
      await client.expire('job:failures', 30 * 24 * 60 * 60) // 30 days

    } catch (error) {
      logger.error('Failed to record job failure', {
        jobId: job.id,
        error: error instanceof Error ? error.message : 'Unknown error'
      })
    }
  }
}

export const jobQueueManager = new JobQueueManager()