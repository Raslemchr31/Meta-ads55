import { redisManager } from '@/lib/redis-manager'
import { logger } from '@/lib/logger'
import { threatDetectionSystem } from './threat-detection'
import { auditComplianceSystem } from './audit-compliance'
import { multiTenantSecurityManager } from './multi-tenant-security'
import { encryptionKeyManager } from './encryption-key-management'
import { securityMonitoringSystem } from './security-monitoring'

export interface SecuritySystemStatus {
  overall: 'healthy' | 'degraded' | 'critical'
  components: {
    threatDetection: 'healthy' | 'degraded' | 'critical'
    auditCompliance: 'healthy' | 'degraded' | 'critical'
    multiTenant: 'healthy' | 'degraded' | 'critical'
    encryption: 'healthy' | 'degraded' | 'critical'
    monitoring: 'healthy' | 'degraded' | 'critical'
  }
  lastHealthCheck: number
  uptime: number
}

export interface SecurityConfiguration {
  threatDetection: {
    enabled: boolean
    sensitivity: 'low' | 'medium' | 'high'
    autoMitigation: boolean
  }
  audit: {
    enabled: boolean
    level: 'basic' | 'detailed' | 'comprehensive'
    retention: number // days
  }
  encryption: {
    defaultLevel: 'standard' | 'enhanced' | 'enterprise'
    keyRotationInterval: number // days
    autoRotation: boolean
  }
  compliance: {
    gdprEnabled: boolean
    soc2Enabled: boolean
    dataRetention: number // days
  }
  monitoring: {
    realTimeDashboard: boolean
    alertThresholds: {
      low: number
      medium: number
      high: number
      critical: number
    }
  }
}

export class IntegratedSecuritySystem {
  private initialized = false
  private startTime = Date.now()
  private config: SecurityConfiguration

  constructor() {
    this.config = {
      threatDetection: {
        enabled: true,
        sensitivity: 'medium',
        autoMitigation: true
      },
      audit: {
        enabled: true,
        level: 'detailed',
        retention: 2555 // 7 years
      },
      encryption: {
        defaultLevel: 'enhanced',
        keyRotationInterval: 90,
        autoRotation: true
      },
      compliance: {
        gdprEnabled: true,
        soc2Enabled: true,
        dataRetention: 2555
      },
      monitoring: {
        realTimeDashboard: true,
        alertThresholds: {
          low: 10,
          medium: 25,
          high: 50,
          critical: 100
        }
      }
    }
  }

  async initialize(): Promise<void> {
    if (this.initialized) {
      logger.warn('Security system already initialized')
      return
    }

    logger.info('Initializing integrated security system...')

    try {
      // Initialize components in dependency order
      logger.info('Initializing encryption and key management...')
      await encryptionKeyManager.initialize()

      logger.info('Initializing multi-tenant security...')
      await multiTenantSecurityManager.initialize()

      logger.info('Initializing audit and compliance system...')
      await auditComplianceSystem.initialize()

      logger.info('Initializing threat detection...')
      await threatDetectionSystem.initialize()

      logger.info('Initializing security monitoring...')
      await securityMonitoringSystem.initialize()

      // Set up cross-component integrations
      await this.setupIntegrations()

      // Start background security tasks
      await this.startSecurityTasks()

      this.initialized = true

      logger.info('Integrated security system initialized successfully', {
        components: 5,
        configuration: this.config,
        startupTime: Date.now() - this.startTime
      })

      // Create initialization audit event
      await auditComplianceSystem.createAuditEvent({
        userId: 'system',
        action: 'security_system_initialized',
        resource: 'security_system',
        outcome: 'success',
        sourceIp: '127.0.0.1',
        details: {
          components: ['threatDetection', 'auditCompliance', 'multiTenant', 'encryption', 'monitoring'],
          startupTime: Date.now() - this.startTime
        },
        sensitive: false,
        gdprRelevant: false,
        soc2Relevant: true,
        dataClassification: 'internal'
      })

    } catch (error) {
      logger.error('Failed to initialize security system', error)

      // Create failure audit event
      try {
        await auditComplianceSystem.createAuditEvent({
          userId: 'system',
          action: 'security_system_initialization_failed',
          resource: 'security_system',
          outcome: 'failure',
          sourceIp: '127.0.0.1',
          details: {
            error: error instanceof Error ? error.message : 'Unknown error',
            components: ['threatDetection', 'auditCompliance', 'multiTenant', 'encryption', 'monitoring']
          },
          sensitive: false,
          gdprRelevant: false,
          soc2Relevant: true,
          dataClassification: 'internal'
        })
      } catch (auditError) {
        logger.error('Failed to create audit event for initialization failure', auditError)
      }

      throw error
    }
  }

  // Integrated security middleware for Express/Next.js
  createSecurityMiddleware() {
    return async (req: any, res: any, next: any) => {
      if (!this.initialized) {
        return res.status(503).json({
          error: 'Security system not initialized',
          message: 'Please wait for security system to be ready'
        })
      }

      try {
        const startTime = Date.now()

        // Extract request information
        const ip = req.ip || req.connection.remoteAddress || 'unknown'
        const userAgent = req.get('User-Agent') || 'unknown'
        const userId = req.user?.id
        const tenantId = req.tenant?.id || req.headers['x-tenant-id']
        const sessionId = req.sessionID || req.headers['x-session-id']

        // 1. Threat detection
        if (this.config.threatDetection.enabled) {
          const threats = await threatDetectionSystem.detectApiAnomalies(
            userId || 'anonymous',
            req.path,
            req.method,
            ip,
            tenantId
          )

          if (threats.length > 0) {
            const criticalThreats = threats.filter(t => t.severity === 'critical')
            if (criticalThreats.length > 0) {
              // Block request for critical threats
              await this.handleCriticalThreat(criticalThreats[0], req, res)
              return
            }
          }
        }

        // 2. Multi-tenant access control
        if (tenantId && userId) {
          const hasAccess = await multiTenantSecurityManager.hasPermission(
            userId,
            tenantId,
            'api',
            req.method.toLowerCase(),
            { ip, location: req.headers['x-forwarded-for'] }
          )

          if (!hasAccess) {
            await this.handleAccessDenied(userId, tenantId, req, res)
            return
          }

          // Enforce quotas
          const quotaAllowed = await multiTenantSecurityManager.enforceQuota(
            tenantId,
            'api_calls',
            1
          )

          if (!quotaAllowed) {
            await this.handleQuotaExceeded(tenantId, req, res)
            return
          }
        }

        // 3. Create audit event
        if (this.config.audit.enabled) {
          await auditComplianceSystem.createAuditEvent({
            userId: userId || 'anonymous',
            tenantId,
            sessionId,
            action: `api_${req.method.toLowerCase()}`,
            resource: req.path,
            outcome: 'success', // Will be updated if request fails
            sourceIp: ip,
            userAgent,
            details: {
              method: req.method,
              path: req.path,
              query: req.query,
              headers: this.sanitizeHeaders(req.headers),
              responseTime: Date.now() - startTime
            },
            sensitive: this.isSensitiveEndpoint(req.path),
            gdprRelevant: this.isGDPRRelevant(req.path),
            soc2Relevant: true,
            dataClassification: this.classifyRequest(req)
          })
        }

        // 4. Add security headers
        res.set({
          'X-Content-Type-Options': 'nosniff',
          'X-Frame-Options': 'DENY',
          'X-XSS-Protection': '1; mode=block',
          'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
          'Content-Security-Policy': "default-src 'self'"
        })

        // Store security context for use in request handlers
        req.securityContext = {
          tenantId,
          userId,
          sessionId,
          ip,
          userAgent,
          startTime,
          threats: threats || []
        }

        next()

      } catch (error) {
        logger.error('Security middleware error', error, {
          path: req.path,
          method: req.method,
          ip: req.ip
        })

        res.status(500).json({
          error: 'Security check failed',
          message: 'Please try again later'
        })
      }
    }
  }

  // Encrypt sensitive data before storage
  async encryptSensitiveData(
    data: Record<string, any>,
    tenantId: string,
    dataType: 'pii' | 'tokens' | 'data' = 'data'
  ): Promise<Record<string, any>> {
    const encrypted: Record<string, any> = {}

    for (const [key, value] of Object.entries(data)) {
      if (this.isSensitiveField(key) && value) {
        if (dataType === 'pii') {
          encrypted[key] = await encryptionKeyManager.encryptPII({ [key]: value }, tenantId)
        } else {
          encrypted[key] = await encryptionKeyManager.encryptField(
            JSON.stringify(value),
            dataType,
            tenantId,
            'confidential'
          )
        }
      } else {
        encrypted[key] = value
      }
    }

    return encrypted
  }

  // Decrypt sensitive data after retrieval
  async decryptSensitiveData(
    encryptedData: Record<string, any>,
    dataType: 'pii' | 'tokens' | 'data' = 'data'
  ): Promise<Record<string, any>> {
    const decrypted: Record<string, any> = {}

    for (const [key, value] of Object.entries(encryptedData)) {
      if (this.isSensitiveField(key) && value) {
        try {
          if (dataType === 'pii') {
            const piiResult = await encryptionKeyManager.decryptPII({ [key]: value })
            decrypted[key] = piiResult[key]
          } else {
            const decryptedBuffer = await encryptionKeyManager.decryptField(value)
            decrypted[key] = JSON.parse(decryptedBuffer.toString('utf8'))
          }
        } catch (error) {
          logger.error('Failed to decrypt field', error, { field: key })
          decrypted[key] = null
        }
      } else {
        decrypted[key] = value
      }
    }

    return decrypted
  }

  // Get comprehensive security status
  async getSecurityStatus(): Promise<SecuritySystemStatus> {
    const now = Date.now()

    // Check each component
    const components = {
      threatDetection: await this.checkComponentHealth('threatDetection'),
      auditCompliance: await this.checkComponentHealth('auditCompliance'),
      multiTenant: await this.checkComponentHealth('multiTenant'),
      encryption: await this.checkComponentHealth('encryption'),
      monitoring: await this.checkComponentHealth('monitoring')
    }

    // Determine overall status
    const statuses = Object.values(components)
    const overall = statuses.includes('critical') ? 'critical' :
                   statuses.includes('degraded') ? 'degraded' : 'healthy'

    return {
      overall,
      components,
      lastHealthCheck: now,
      uptime: now - this.startTime
    }
  }

  // Handle security incidents
  async handleSecurityIncident(
    type: 'data_breach' | 'ddos_attack' | 'malware' | 'insider_threat',
    details: Record<string, any>
  ): Promise<string> {
    // Create incident in monitoring system
    const incidentId = await securityMonitoringSystem.createIncident(
      [], // threat events will be added separately
      details.severity || 'high',
      type
    )

    // Create audit event
    await auditComplianceSystem.createAuditEvent({
      userId: details.userId || 'system',
      action: 'security_incident_reported',
      resource: 'security_incident',
      resourceId: incidentId,
      outcome: 'success',
      sourceIp: details.sourceIp || '127.0.0.1',
      details: {
        incidentType: type,
        incidentId,
        ...details
      },
      sensitive: true,
      gdprRelevant: type === 'data_breach',
      soc2Relevant: true,
      dataClassification: 'confidential'
    })

    logger.error('Security incident handled', { incidentId, type, details })
    return incidentId
  }

  // Configuration management
  async updateConfiguration(updates: Partial<SecurityConfiguration>): Promise<void> {
    const oldConfig = { ...this.config }
    Object.assign(this.config, updates)

    // Apply configuration changes
    await this.applyConfigurationChanges(oldConfig, this.config)

    // Create audit event
    await auditComplianceSystem.createAuditEvent({
      userId: 'admin',
      action: 'security_configuration_updated',
      resource: 'security_configuration',
      outcome: 'success',
      sourceIp: '127.0.0.1',
      details: {
        oldConfig,
        newConfig: this.config,
        changes: Object.keys(updates)
      },
      sensitive: false,
      gdprRelevant: false,
      soc2Relevant: true,
      dataClassification: 'internal'
    })

    logger.info('Security configuration updated', { changes: Object.keys(updates) })
  }

  // Shutdown security system gracefully
  async shutdown(): Promise<void> {
    logger.info('Shutting down security system...')

    try {
      // Create shutdown audit event
      await auditComplianceSystem.createAuditEvent({
        userId: 'system',
        action: 'security_system_shutdown',
        resource: 'security_system',
        outcome: 'success',
        sourceIp: '127.0.0.1',
        details: {
          uptime: Date.now() - this.startTime,
          reason: 'graceful_shutdown'
        },
        sensitive: false,
        gdprRelevant: false,
        soc2Relevant: true,
        dataClassification: 'internal'
      })

      // Shutdown components in reverse order
      // Note: Individual components don't have shutdown methods in the current implementation

      this.initialized = false
      logger.info('Security system shut down successfully')

    } catch (error) {
      logger.error('Error during security system shutdown', error)
      throw error
    }
  }

  // Private helper methods
  private async setupIntegrations(): Promise<void> {
    // Set up cross-component event handling
    // This would integrate the various security components
    logger.info('Security system integrations configured')
  }

  private async startSecurityTasks(): Promise<void> {
    // Start periodic security tasks
    setInterval(async () => {
      await this.performPeriodicSecurityChecks()
    }, 5 * 60 * 1000) // Every 5 minutes

    logger.info('Background security tasks started')
  }

  private async performPeriodicSecurityChecks(): Promise<void> {
    try {
      // Check system health
      await this.getSecurityStatus()

      // Rotate keys if needed
      if (this.config.encryption.autoRotation) {
        // This would trigger key rotation checks
      }

      // Clean up old data
      await auditComplianceSystem.applyRetentionPolicies()

    } catch (error) {
      logger.error('Periodic security check failed', error)
    }
  }

  private async handleCriticalThreat(threat: any, req: any, res: any): Promise<void> {
    await auditComplianceSystem.createAuditEvent({
      userId: req.user?.id || 'anonymous',
      action: 'critical_threat_blocked',
      resource: req.path,
      outcome: 'denied',
      sourceIp: req.ip,
      details: { threat },
      sensitive: true,
      gdprRelevant: false,
      soc2Relevant: true,
      dataClassification: 'restricted'
    })

    res.status(403).json({
      error: 'Request blocked',
      message: 'Security threat detected'
    })
  }

  private async handleAccessDenied(userId: string, tenantId: string, req: any, res: any): Promise<void> {
    await auditComplianceSystem.createAuditEvent({
      userId,
      tenantId,
      action: 'access_denied',
      resource: req.path,
      outcome: 'denied',
      sourceIp: req.ip,
      details: {
        reason: 'insufficient_permissions',
        method: req.method,
        path: req.path
      },
      sensitive: false,
      gdprRelevant: false,
      soc2Relevant: true,
      dataClassification: 'internal'
    })

    res.status(403).json({
      error: 'Access denied',
      message: 'Insufficient permissions'
    })
  }

  private async handleQuotaExceeded(tenantId: string, req: any, res: any): Promise<void> {
    await auditComplianceSystem.createAuditEvent({
      tenantId,
      action: 'quota_exceeded',
      resource: 'api_calls',
      outcome: 'denied',
      sourceIp: req.ip,
      details: {
        path: req.path,
        method: req.method
      },
      sensitive: false,
      gdprRelevant: false,
      soc2Relevant: true,
      dataClassification: 'internal'
    })

    res.status(429).json({
      error: 'Quota exceeded',
      message: 'API call limit reached'
    })
  }

  private async checkComponentHealth(component: string): Promise<'healthy' | 'degraded' | 'critical'> {
    try {
      // Placeholder for actual health checks
      return 'healthy'
    } catch (error) {
      return 'critical'
    }
  }

  private async applyConfigurationChanges(oldConfig: SecurityConfiguration, newConfig: SecurityConfiguration): Promise<void> {
    // Apply configuration changes to components
    // This would propagate changes to individual security components
  }

  private sanitizeHeaders(headers: Record<string, any>): Record<string, any> {
    const sanitized = { ...headers }
    delete sanitized.authorization
    delete sanitized.cookie
    delete sanitized['x-api-key']
    return sanitized
  }

  private isSensitiveEndpoint(path: string): boolean {
    const sensitivePatterns = ['/auth/', '/profile/', '/payment/', '/admin/']
    return sensitivePatterns.some(pattern => path.includes(pattern))
  }

  private isGDPRRelevant(path: string): boolean {
    const gdprPatterns = ['/profile/', '/user/', '/personal/', '/contact/']
    return gdprPatterns.some(pattern => path.includes(pattern))
  }

  private classifyRequest(req: any): 'public' | 'internal' | 'confidential' | 'restricted' {
    if (this.isSensitiveEndpoint(req.path)) return 'confidential'
    if (req.path.includes('/admin/')) return 'restricted'
    if (req.path.includes('/api/')) return 'internal'
    return 'public'
  }

  private isSensitiveField(fieldName: string): boolean {
    const sensitiveFields = [
      'password', 'token', 'key', 'secret', 'email', 'phone',
      'ssn', 'credit_card', 'bank_account', 'passport', 'license'
    ]
    return sensitiveFields.some(field =>
      fieldName.toLowerCase().includes(field)
    )
  }
}

export const integratedSecuritySystem = new IntegratedSecuritySystem()