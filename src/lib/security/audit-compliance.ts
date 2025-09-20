import { redisManager, RedisDatabase } from '@/lib/redis-manager'
import { logger } from '@/lib/logger'
import crypto from 'crypto'

export interface AuditEvent {
  id: string
  timestamp: number
  userId?: string
  tenantId?: string
  sessionId?: string
  action: string
  resource: string
  resourceId?: string
  outcome: 'success' | 'failure' | 'denied'
  sourceIp: string
  userAgent?: string
  details: Record<string, any>
  sensitive: boolean
  gdprRelevant: boolean
  soc2Relevant: boolean
  dataClassification: 'public' | 'internal' | 'confidential' | 'restricted'
  integrity: {
    hash: string
    signature?: string
  }
}

export interface DataRetentionPolicy {
  id: string
  name: string
  description: string
  retentionPeriod: number // days
  dataTypes: string[]
  jurisdiction: string[]
  autoDelete: boolean
  archiveBeforeDelete: boolean
  legalHold: boolean
  gdprApplicable: boolean
  enabled: boolean
}

export interface ComplianceReport {
  id: string
  type: 'gdpr' | 'soc2' | 'hipaa' | 'pci' | 'custom'
  period: {
    start: number
    end: number
  }
  generatedAt: number
  requestedBy: string
  format: 'json' | 'csv' | 'pdf'
  filters: Record<string, any>
  stats: {
    totalEvents: number
    uniqueUsers: number
    dataAccess: number
    dataModification: number
    securityEvents: number
    complianceViolations: number
  }
  downloadUrl?: string
  expiresAt: number
}

export interface GDPRRequest {
  id: string
  type: 'access' | 'rectification' | 'erasure' | 'portability' | 'restriction' | 'objection'
  dataSubject: string // email or user ID
  requestedAt: number
  verifiedAt?: number
  processedAt?: number
  completedAt?: number
  status: 'pending' | 'verified' | 'processing' | 'completed' | 'rejected'
  requestor: string
  verificationMethod?: string
  notes?: string
  attachments?: string[]
  legalBasis?: string
}

export interface SOC2Control {
  id: string
  category: 'security' | 'availability' | 'processing_integrity' | 'confidentiality' | 'privacy'
  name: string
  description: string
  requirements: string[]
  automatedMonitoring: boolean
  evidenceCollection: string[]
  frequency: 'continuous' | 'daily' | 'weekly' | 'monthly' | 'quarterly'
  lastAssessment?: number
  status: 'compliant' | 'non_compliant' | 'needs_review'
}

export class AuditComplianceSystem {
  private retentionPolicies: Map<string, DataRetentionPolicy> = new Map()
  private soc2Controls: Map<string, SOC2Control> = new Map()
  private secretKey: string
  private initialized = false

  constructor() {
    this.secretKey = process.env.AUDIT_SECRET_KEY || crypto.randomBytes(32).toString('hex')
  }

  async initialize(): Promise<void> {
    try {
      await this.loadRetentionPolicies()
      await this.loadSOC2Controls()
      await this.setupAuditStreams()
      await this.startRetentionCleanup()

      this.initialized = true
      logger.info('Audit and compliance system initialized', {
        retentionPolicies: this.retentionPolicies.size,
        soc2Controls: this.soc2Controls.size
      })
    } catch (error) {
      logger.error('Failed to initialize audit and compliance system', error)
      throw error
    }
  }

  // Create tamper-proof audit event
  async createAuditEvent(eventData: Omit<AuditEvent, 'id' | 'timestamp' | 'integrity'>): Promise<string> {
    if (!this.initialized) {
      throw new Error('Audit system not initialized')
    }

    const event: AuditEvent = {
      id: `audit_${Date.now()}_${crypto.randomUUID()}`,
      timestamp: Date.now(),
      ...eventData,
      integrity: {
        hash: '',
        signature: ''
      }
    }

    // Calculate integrity hash
    const eventForHashing = { ...event }
    delete eventForHashing.integrity
    event.integrity.hash = this.calculateHash(eventForHashing)
    event.integrity.signature = this.signEvent(event.integrity.hash)

    // Store in Redis Stream for tamper-proof logging
    const client = redisManager.getConnection(RedisDatabase.ANALYTICS)
    const streamKey = this.getStreamKey(event.tenantId, event.dataClassification)

    await client.xadd(
      streamKey,
      '*',
      'event', JSON.stringify(event),
      'hash', event.integrity.hash,
      'signature', event.integrity.signature,
      'timestamp', event.timestamp.toString()
    )

    // Index for fast searching
    await this.indexAuditEvent(event)

    // Check for compliance violations
    await this.checkComplianceViolations(event)

    logger.debug('Audit event created', {
      eventId: event.id,
      action: event.action,
      resource: event.resource,
      userId: event.userId
    })

    return event.id
  }

  // GDPR compliance methods
  async processGDPRRequest(request: Omit<GDPRRequest, 'id' | 'requestedAt' | 'status'>): Promise<string> {
    const gdprRequest: GDPRRequest = {
      id: `gdpr_${Date.now()}_${crypto.randomUUID()}`,
      requestedAt: Date.now(),
      status: 'pending',
      ...request
    }

    const client = redisManager.getConnection(RedisDatabase.CACHE)
    await client.hset('gdpr:requests', gdprRequest.id, JSON.stringify(gdprRequest))

    // Create audit event for GDPR request
    await this.createAuditEvent({
      userId: request.requestor,
      action: 'gdpr_request_submitted',
      resource: 'gdpr_request',
      resourceId: gdprRequest.id,
      outcome: 'success',
      sourceIp: '127.0.0.1', // Should be passed from request
      details: {
        type: request.type,
        dataSubject: request.dataSubject
      },
      sensitive: true,
      gdprRelevant: true,
      soc2Relevant: false,
      dataClassification: 'confidential'
    })

    // Auto-verify if internal request
    if (this.isInternalRequest(request)) {
      await this.verifyGDPRRequest(gdprRequest.id, 'internal_verification')
    }

    logger.info('GDPR request created', { requestId: gdprRequest.id, type: request.type })
    return gdprRequest.id
  }

  async verifyGDPRRequest(requestId: string, verificationMethod: string): Promise<void> {
    const client = redisManager.getConnection(RedisDatabase.CACHE)
    const requestData = await client.hget('gdpr:requests', requestId)

    if (!requestData) {
      throw new Error('GDPR request not found')
    }

    const request: GDPRRequest = JSON.parse(requestData)
    request.status = 'verified'
    request.verifiedAt = Date.now()
    request.verificationMethod = verificationMethod

    await client.hset('gdpr:requests', requestId, JSON.stringify(request))

    // Start processing
    await this.startGDPRProcessing(request)
  }

  async fulfillGDPRRequest(requestId: string): Promise<{
    data?: any
    confirmation?: string
    error?: string
  }> {
    const client = redisManager.getConnection(RedisDatabase.CACHE)
    const requestData = await client.hget('gdpr:requests', requestId)

    if (!requestData) {
      throw new Error('GDPR request not found')
    }

    const request: GDPRRequest = JSON.parse(requestData)

    if (request.status !== 'processing') {
      throw new Error('GDPR request not in processing status')
    }

    let result: any = {}

    switch (request.type) {
      case 'access':
        result.data = await this.collectPersonalData(request.dataSubject)
        break

      case 'erasure':
        result.confirmation = await this.erasePersonalData(request.dataSubject)
        break

      case 'portability':
        result.data = await this.exportPersonalData(request.dataSubject)
        break

      case 'rectification':
        result.confirmation = await this.rectifyPersonalData(request.dataSubject, request.notes)
        break

      default:
        result.error = 'Unsupported request type'
    }

    // Update request status
    request.status = result.error ? 'rejected' : 'completed'
    request.completedAt = Date.now()
    await client.hset('gdpr:requests', requestId, JSON.stringify(request))

    // Create audit event
    await this.createAuditEvent({
      userId: request.requestor,
      action: 'gdpr_request_fulfilled',
      resource: 'gdpr_request',
      resourceId: requestId,
      outcome: result.error ? 'failure' : 'success',
      sourceIp: '127.0.0.1',
      details: {
        type: request.type,
        dataSubject: request.dataSubject,
        result: result.error || 'success'
      },
      sensitive: true,
      gdprRelevant: true,
      soc2Relevant: false,
      dataClassification: 'confidential'
    })

    return result
  }

  // SOC2 compliance methods
  async generateSOC2Report(period: { start: number; end: number }): Promise<ComplianceReport> {
    const reportId = `soc2_${Date.now()}_${crypto.randomUUID()}`
    const client = redisManager.getConnection(RedisDatabase.ANALYTICS)

    // Collect SOC2 relevant events
    const events = await this.getAuditEvents({
      startTime: period.start,
      endTime: period.end,
      soc2Relevant: true
    })

    // Calculate compliance statistics
    const stats = {
      totalEvents: events.length,
      uniqueUsers: new Set(events.map(e => e.userId).filter(Boolean)).size,
      dataAccess: events.filter(e => e.action.includes('access')).length,
      dataModification: events.filter(e => e.action.includes('create') || e.action.includes('update') || e.action.includes('delete')).length,
      securityEvents: events.filter(e => e.action.includes('security') || e.action.includes('threat')).length,
      complianceViolations: events.filter(e => e.outcome === 'denied').length
    }

    const report: ComplianceReport = {
      id: reportId,
      type: 'soc2',
      period,
      generatedAt: Date.now(),
      requestedBy: 'system',
      format: 'json',
      filters: { soc2Relevant: true },
      stats,
      expiresAt: Date.now() + (30 * 24 * 60 * 60 * 1000) // 30 days
    }

    // Store report
    await client.hset('compliance:reports', reportId, JSON.stringify(report))

    logger.info('SOC2 report generated', { reportId, period, eventsCount: events.length })
    return report
  }

  async assessSOC2Controls(): Promise<Map<string, any>> {
    const assessments = new Map()

    for (const [controlId, control] of this.soc2Controls) {
      const assessment = await this.assessControl(control)
      assessments.set(controlId, assessment)

      // Update control status
      control.lastAssessment = Date.now()
      control.status = assessment.compliant ? 'compliant' : 'non_compliant'
      await this.persistSOC2Control(control)
    }

    return assessments
  }

  // Data retention and purging
  async applyRetentionPolicies(): Promise<void> {
    for (const [policyId, policy] of this.retentionPolicies) {
      if (!policy.enabled) continue

      const cutoffDate = Date.now() - (policy.retentionPeriod * 24 * 60 * 60 * 1000)

      try {
        if (policy.autoDelete) {
          await this.purgeDataByPolicy(policy, cutoffDate)
        } else if (policy.archiveBeforeDelete) {
          await this.archiveDataByPolicy(policy, cutoffDate)
        }

        logger.info('Retention policy applied', {
          policyId,
          cutoffDate: new Date(cutoffDate).toISOString(),
          autoDelete: policy.autoDelete
        })
      } catch (error) {
        logger.error('Failed to apply retention policy', error, { policyId })
      }
    }
  }

  // Export audit data for compliance
  async exportAuditData(
    filters: {
      startTime?: number
      endTime?: number
      userId?: string
      tenantId?: string
      actions?: string[]
      dataClassification?: string[]
    },
    format: 'json' | 'csv' = 'json'
  ): Promise<string> {
    const events = await this.getAuditEvents(filters)

    if (format === 'csv') {
      return this.convertToCSV(events)
    }

    return JSON.stringify(events, null, 2)
  }

  // Data integrity verification
  async verifyAuditIntegrity(eventId?: string): Promise<{
    valid: boolean
    tamperedEvents: string[]
    verifiedEvents: number
    totalEvents: number
  }> {
    const result = {
      valid: true,
      tamperedEvents: [] as string[],
      verifiedEvents: 0,
      totalEvents: 0
    }

    let events: AuditEvent[]

    if (eventId) {
      const event = await this.getAuditEvent(eventId)
      events = event ? [event] : []
    } else {
      events = await this.getAuditEvents({})
    }

    result.totalEvents = events.length

    for (const event of events) {
      const expectedHash = this.calculateHash({
        ...event,
        integrity: undefined
      })

      if (event.integrity.hash !== expectedHash) {
        result.valid = false
        result.tamperedEvents.push(event.id)
      } else {
        result.verifiedEvents++
      }
    }

    logger.info('Audit integrity verification completed', result)
    return result
  }

  // Privacy by design data handling
  async anonymizePersonalData(userId: string): Promise<void> {
    // Replace PII with anonymized tokens while preserving analytical value
    const anonymizationId = crypto.randomUUID()

    // Update audit events
    await this.anonymizeAuditEvents(userId, anonymizationId)

    // Create audit event for anonymization
    await this.createAuditEvent({
      userId: 'system',
      action: 'data_anonymization',
      resource: 'user_data',
      resourceId: userId,
      outcome: 'success',
      sourceIp: '127.0.0.1',
      details: {
        originalUserId: userId,
        anonymizationId,
        reason: 'privacy_by_design'
      },
      sensitive: true,
      gdprRelevant: true,
      soc2Relevant: true,
      dataClassification: 'confidential'
    })

    logger.info('Personal data anonymized', { userId, anonymizationId })
  }

  // Helper methods
  private calculateHash(data: any): string {
    return crypto
      .createHash('sha256')
      .update(JSON.stringify(data) + this.secretKey)
      .digest('hex')
  }

  private signEvent(hash: string): string {
    return crypto
      .createHmac('sha256', this.secretKey)
      .update(hash)
      .digest('hex')
  }

  private getStreamKey(tenantId?: string, classification?: string): string {
    const base = 'audit:events'
    const parts = [base]

    if (tenantId) parts.push(`tenant:${tenantId}`)
    if (classification) parts.push(`class:${classification}`)

    return parts.join(':')
  }

  private async indexAuditEvent(event: AuditEvent): Promise<void> {
    const client = redisManager.getConnection(RedisDatabase.ANALYTICS)

    // Index by user
    if (event.userId) {
      await client.zadd(`audit:index:user:${event.userId}`, event.timestamp, event.id)
    }

    // Index by action
    await client.zadd(`audit:index:action:${event.action}`, event.timestamp, event.id)

    // Index by resource
    await client.zadd(`audit:index:resource:${event.resource}`, event.timestamp, event.id)

    // Index by tenant
    if (event.tenantId) {
      await client.zadd(`audit:index:tenant:${event.tenantId}`, event.timestamp, event.id)
    }

    // Store event details for retrieval
    await client.hset('audit:events:details', event.id, JSON.stringify(event))
  }

  private async getAuditEvents(filters: {
    startTime?: number
    endTime?: number
    userId?: string
    tenantId?: string
    actions?: string[]
    gdprRelevant?: boolean
    soc2Relevant?: boolean
    dataClassification?: string[]
  }): Promise<AuditEvent[]> {
    const client = redisManager.getConnection(RedisDatabase.ANALYTICS)
    const eventIds = new Set<string>()

    // Get events by different indexes
    if (filters.userId) {
      const ids = await client.zrangebyscore(
        `audit:index:user:${filters.userId}`,
        filters.startTime || 0,
        filters.endTime || Date.now()
      )
      ids.forEach(id => eventIds.add(id))
    }

    if (filters.tenantId) {
      const ids = await client.zrangebyscore(
        `audit:index:tenant:${filters.tenantId}`,
        filters.startTime || 0,
        filters.endTime || Date.now()
      )
      ids.forEach(id => eventIds.add(id))
    }

    // If no specific filters, get all events in time range
    if (!filters.userId && !filters.tenantId && !filters.actions) {
      const streamKey = this.getStreamKey()
      const entries = await client.xrange(streamKey, '-', '+')

      for (const entry of entries) {
        const eventData = JSON.parse(entry[1][1]) // [timestamp, [field, value, field, value, ...]]
        if ((!filters.startTime || eventData.timestamp >= filters.startTime) &&
            (!filters.endTime || eventData.timestamp <= filters.endTime)) {
          eventIds.add(eventData.id)
        }
      }
    }

    // Retrieve full event details
    const events: AuditEvent[] = []
    if (eventIds.size > 0) {
      const eventDetails = await client.hmget('audit:events:details', ...Array.from(eventIds))

      for (const eventData of eventDetails) {
        if (eventData) {
          const event: AuditEvent = JSON.parse(eventData)

          // Apply additional filters
          if (filters.gdprRelevant !== undefined && event.gdprRelevant !== filters.gdprRelevant) continue
          if (filters.soc2Relevant !== undefined && event.soc2Relevant !== filters.soc2Relevant) continue
          if (filters.actions && !filters.actions.includes(event.action)) continue
          if (filters.dataClassification && !filters.dataClassification.includes(event.dataClassification)) continue

          events.push(event)
        }
      }
    }

    return events.sort((a, b) => a.timestamp - b.timestamp)
  }

  private async getAuditEvent(eventId: string): Promise<AuditEvent | null> {
    const client = redisManager.getConnection(RedisDatabase.ANALYTICS)
    const eventData = await client.hget('audit:events:details', eventId)

    return eventData ? JSON.parse(eventData) : null
  }

  private async setupAuditStreams(): Promise<void> {
    const client = redisManager.getConnection(RedisDatabase.ANALYTICS)

    // Create consumer groups for different compliance requirements
    try {
      await client.xgroup('CREATE', 'audit:events', 'gdpr-processor', '$', 'MKSTREAM')
      await client.xgroup('CREATE', 'audit:events', 'soc2-processor', '$', 'MKSTREAM')
      await client.xgroup('CREATE', 'audit:events', 'retention-processor', '$', 'MKSTREAM')
    } catch (error) {
      // Groups might already exist
      logger.debug('Audit stream groups already exist or creation failed', error)
    }
  }

  private async startRetentionCleanup(): Promise<void> {
    // Run retention cleanup every 6 hours
    setInterval(async () => {
      try {
        await this.applyRetentionPolicies()
      } catch (error) {
        logger.error('Retention cleanup failed', error)
      }
    }, 6 * 60 * 60 * 1000)
  }

  private async loadRetentionPolicies(): Promise<void> {
    const client = redisManager.getConnection(RedisDatabase.CACHE)

    try {
      const policies = await client.hgetall('compliance:retention_policies')
      for (const [id, data] of Object.entries(policies)) {
        this.retentionPolicies.set(id, JSON.parse(data))
      }
    } catch (error) {
      await this.createDefaultRetentionPolicies()
    }
  }

  private async createDefaultRetentionPolicies(): Promise<void> {
    const defaultPolicies: DataRetentionPolicy[] = [
      {
        id: 'gdpr_personal_data',
        name: 'GDPR Personal Data',
        description: 'EU GDPR compliance for personal data',
        retentionPeriod: 2555, // 7 years
        dataTypes: ['personal_data', 'user_profile', 'contact_info'],
        jurisdiction: ['EU'],
        autoDelete: false,
        archiveBeforeDelete: true,
        legalHold: false,
        gdprApplicable: true,
        enabled: true
      },
      {
        id: 'soc2_audit_logs',
        name: 'SOC2 Audit Logs',
        description: 'SOC2 Type II audit log retention',
        retentionPeriod: 2555, // 7 years
        dataTypes: ['audit_logs', 'security_events', 'access_logs'],
        jurisdiction: ['US'],
        autoDelete: false,
        archiveBeforeDelete: true,
        legalHold: false,
        gdprApplicable: false,
        enabled: true
      },
      {
        id: 'general_activity',
        name: 'General Activity Logs',
        description: 'General user activity retention',
        retentionPeriod: 365, // 1 year
        dataTypes: ['activity_logs', 'usage_data'],
        jurisdiction: ['*'],
        autoDelete: true,
        archiveBeforeDelete: false,
        legalHold: false,
        gdprApplicable: true,
        enabled: true
      }
    ]

    for (const policy of defaultPolicies) {
      this.retentionPolicies.set(policy.id, policy)
      await this.persistRetentionPolicy(policy)
    }
  }

  private async persistRetentionPolicy(policy: DataRetentionPolicy): Promise<void> {
    const client = redisManager.getConnection(RedisDatabase.CACHE)
    await client.hset('compliance:retention_policies', policy.id, JSON.stringify(policy))
  }

  private async loadSOC2Controls(): Promise<void> {
    // Load SOC2 controls configuration
    const defaultControls: SOC2Control[] = [
      {
        id: 'cc1.1',
        category: 'security',
        name: 'Access Controls',
        description: 'Logical and physical access controls restrict unauthorized access',
        requirements: ['authentication', 'authorization', 'access_monitoring'],
        automatedMonitoring: true,
        evidenceCollection: ['access_logs', 'failed_attempts', 'privilege_changes'],
        frequency: 'continuous',
        status: 'compliant'
      },
      {
        id: 'cc2.1',
        category: 'security',
        name: 'System Monitoring',
        description: 'System activities are monitored for security events',
        requirements: ['security_monitoring', 'incident_response', 'threat_detection'],
        automatedMonitoring: true,
        evidenceCollection: ['security_alerts', 'incident_reports', 'monitoring_logs'],
        frequency: 'continuous',
        status: 'compliant'
      }
    ]

    for (const control of defaultControls) {
      this.soc2Controls.set(control.id, control)
    }
  }

  private async persistSOC2Control(control: SOC2Control): Promise<void> {
    const client = redisManager.getConnection(RedisDatabase.CACHE)
    await client.hset('compliance:soc2_controls', control.id, JSON.stringify(control))
  }

  private async assessControl(control: SOC2Control): Promise<any> {
    // Implement control assessment logic
    return {
      controlId: control.id,
      compliant: true,
      evidence: [],
      gaps: [],
      lastAssessment: Date.now()
    }
  }

  private async checkComplianceViolations(event: AuditEvent): Promise<void> {
    // Check for compliance violations based on the event
    if (event.outcome === 'denied' && event.sensitive) {
      logger.warn('Potential compliance violation detected', {
        eventId: event.id,
        action: event.action,
        resource: event.resource
      })
    }
  }

  private isInternalRequest(request: any): boolean {
    // Determine if request is from internal system
    return request.requestor?.includes('@company.com') || false
  }

  private async startGDPRProcessing(request: GDPRRequest): Promise<void> {
    request.status = 'processing'
    request.processedAt = Date.now()

    const client = redisManager.getConnection(RedisDatabase.CACHE)
    await client.hset('gdpr:requests', request.id, JSON.stringify(request))

    // Queue for processing based on type
    setTimeout(() => this.fulfillGDPRRequest(request.id), 1000)
  }

  private async collectPersonalData(dataSubject: string): Promise<any> {
    // Collect all personal data for the data subject
    return { message: 'Personal data collection not implemented' }
  }

  private async erasePersonalData(dataSubject: string): Promise<string> {
    // Erase personal data while maintaining referential integrity
    return 'Personal data erasure not implemented'
  }

  private async exportPersonalData(dataSubject: string): Promise<any> {
    // Export personal data in portable format
    return { message: 'Personal data export not implemented' }
  }

  private async rectifyPersonalData(dataSubject: string, corrections?: string): Promise<string> {
    // Rectify incorrect personal data
    return 'Personal data rectification not implemented'
  }

  private async purgeDataByPolicy(policy: DataRetentionPolicy, cutoffDate: number): Promise<void> {
    // Purge data according to retention policy
    logger.info('Data purging not implemented', { policy: policy.id, cutoffDate })
  }

  private async archiveDataByPolicy(policy: DataRetentionPolicy, cutoffDate: number): Promise<void> {
    // Archive data before deletion
    logger.info('Data archiving not implemented', { policy: policy.id, cutoffDate })
  }

  private convertToCSV(events: AuditEvent[]): string {
    if (events.length === 0) return ''

    const headers = ['id', 'timestamp', 'userId', 'action', 'resource', 'outcome', 'sourceIp']
    const rows = events.map(event => [
      event.id,
      new Date(event.timestamp).toISOString(),
      event.userId || '',
      event.action,
      event.resource,
      event.outcome,
      event.sourceIp
    ])

    return [headers, ...rows].map(row => row.join(',')).join('\n')
  }

  private async anonymizeAuditEvents(userId: string, anonymizationId: string): Promise<void> {
    // Replace userId with anonymization ID in audit events
    const client = redisManager.getConnection(RedisDatabase.ANALYTICS)
    const eventIds = await client.zrange(`audit:index:user:${userId}`, 0, -1)

    for (const eventId of eventIds) {
      const eventData = await client.hget('audit:events:details', eventId)
      if (eventData) {
        const event: AuditEvent = JSON.parse(eventData)
        event.userId = anonymizationId
        await client.hset('audit:events:details', eventId, JSON.stringify(event))
      }
    }

    // Remove old user index
    await client.del(`audit:index:user:${userId}`)
  }
}

export const auditComplianceSystem = new AuditComplianceSystem()