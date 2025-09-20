import { redisManager, RedisDatabase } from '@/lib/redis-manager'
import { logger } from '@/lib/logger'
import crypto from 'crypto'

export interface Tenant {
  id: string
  name: string
  domain?: string
  plan: 'starter' | 'professional' | 'enterprise'
  status: 'active' | 'suspended' | 'deleted'
  createdAt: number
  settings: {
    dataRegion: string
    encryptionLevel: 'standard' | 'enhanced' | 'enterprise'
    auditLevel: 'basic' | 'detailed' | 'comprehensive'
    retentionPeriod: number
    allowCrossTenantSharing: boolean
    ipWhitelist?: string[]
    ssoEnabled: boolean
    mfaRequired: boolean
  }
  limits: {
    users: number
    storage: number // bytes
    apiCalls: number // per hour
    dataTransfer: number // bytes per month
  }
  usage: {
    users: number
    storage: number
    apiCalls: number
    dataTransfer: number
    lastReset: number
  }
  security: {
    encryptionKey: string
    dataClassification: 'public' | 'internal' | 'confidential' | 'restricted'
    complianceRequirements: string[]
    isolationLevel: 'shared' | 'dedicated' | 'private'
  }
}

export interface Permission {
  id: string
  name: string
  resource: string
  actions: string[]
  conditions?: {
    timeRestriction?: {
      startTime: string
      endTime: string
      timezone: string
    }
    ipRestriction?: string[]
    locationRestriction?: string[]
    dataClassification?: string[]
  }
}

export interface Role {
  id: string
  tenantId: string
  name: string
  description: string
  permissions: string[]
  isSystemRole: boolean
  createdAt: number
  updatedAt: number
}

export interface User {
  id: string
  tenantId: string
  email: string
  roles: string[]
  status: 'active' | 'inactive' | 'suspended'
  lastLogin?: number
  mfaEnabled: boolean
  preferences: {
    dataRegion?: string
    encryptionPreference?: 'standard' | 'enhanced'
  }
  quotas: {
    apiCalls: number
    storage: number
    dataTransfer: number
  }
  usage: {
    apiCalls: number
    storage: number
    dataTransfer: number
    lastReset: number
  }
}

export interface DataSharingAgreement {
  id: string
  sourceTenantId: string
  targetTenantId: string
  resourceType: string
  resourceIds: string[]
  permissions: string[]
  conditions: {
    expiresAt?: number
    maxAccess?: number
    requireApproval: boolean
    auditLevel: 'none' | 'basic' | 'detailed'
  }
  status: 'pending' | 'approved' | 'active' | 'suspended' | 'expired'
  createdAt: number
  approvedAt?: number
  approvedBy?: string
}

export interface ResourceQuota {
  tenantId: string
  resourceType: string
  limit: number
  current: number
  resetPeriod: 'hourly' | 'daily' | 'monthly'
  lastReset: number
  warningThreshold: number // percentage
  hardLimit: boolean
}

export class MultiTenantSecurityManager {
  private tenants: Map<string, Tenant> = new Map()
  private roles: Map<string, Role> = new Map()
  private permissions: Map<string, Permission> = new Map()
  private sharingAgreements: Map<string, DataSharingAgreement> = new Map()
  private initialized = false

  async initialize(): Promise<void> {
    try {
      await this.loadTenants()
      await this.loadRoles()
      await this.loadPermissions()
      await this.loadSharingAgreements()
      await this.setupDefaultPermissions()
      await this.startQuotaMonitoring()

      this.initialized = true
      logger.info('Multi-tenant security manager initialized', {
        tenants: this.tenants.size,
        roles: this.roles.size,
        permissions: this.permissions.size,
        sharingAgreements: this.sharingAgreements.size
      })
    } catch (error) {
      logger.error('Failed to initialize multi-tenant security manager', error)
      throw error
    }
  }

  // Tenant isolation and namespace management
  getNamespace(tenantId: string, resourceType: string): string {
    if (!this.isValidTenant(tenantId)) {
      throw new Error(`Invalid tenant ID: ${tenantId}`)
    }

    const tenant = this.tenants.get(tenantId)!
    const isolationLevel = tenant.security.isolationLevel

    switch (isolationLevel) {
      case 'private':
        return `private:${tenantId}:${resourceType}`
      case 'dedicated':
        return `dedicated:${tenantId}:${resourceType}`
      case 'shared':
      default:
        return `shared:${resourceType}:${tenantId}`
    }
  }

  async isolateData(tenantId: string, key: string, data: any): Promise<void> {
    const tenant = this.tenants.get(tenantId)
    if (!tenant) {
      throw new Error(`Tenant not found: ${tenantId}`)
    }

    const namespace = this.getNamespace(tenantId, 'data')
    const isolatedKey = `${namespace}:${key}`

    // Encrypt data based on tenant encryption level
    const encryptedData = await this.encryptTenantData(data, tenant)

    const client = redisManager.getConnection(RedisDatabase.CACHE)
    await client.set(isolatedKey, JSON.stringify(encryptedData))

    // Add to tenant's data index
    await client.sadd(`${namespace}:index`, key)

    logger.debug('Data isolated for tenant', { tenantId, key: isolatedKey })
  }

  async retrieveData(tenantId: string, key: string, userId?: string): Promise<any> {
    // Verify tenant access
    if (!this.isValidTenant(tenantId)) {
      throw new Error('Invalid tenant')
    }

    // Verify user permissions if provided
    if (userId && !await this.hasPermission(userId, tenantId, 'data', 'read')) {
      throw new Error('Access denied')
    }

    const namespace = this.getNamespace(tenantId, 'data')
    const isolatedKey = `${namespace}:${key}`

    const client = redisManager.getConnection(RedisDatabase.CACHE)
    const encryptedData = await client.get(isolatedKey)

    if (!encryptedData) {
      return null
    }

    const tenant = this.tenants.get(tenantId)!
    const data = await this.decryptTenantData(JSON.parse(encryptedData), tenant)

    return data
  }

  // Role-based access control (RBAC)
  async hasPermission(
    userId: string,
    tenantId: string,
    resource: string,
    action: string,
    context?: {
      ip?: string
      location?: string
      dataClassification?: string
    }
  ): Promise<boolean> {
    try {
      const user = await this.getUser(userId)
      if (!user || user.tenantId !== tenantId || user.status !== 'active') {
        return false
      }

      // Check user roles and permissions
      for (const roleId of user.roles) {
        const role = this.roles.get(roleId)
        if (!role || role.tenantId !== tenantId) continue

        for (const permissionId of role.permissions) {
          const permission = this.permissions.get(permissionId)
          if (!permission) continue

          if (this.matchesPermission(permission, resource, action, context)) {
            return true
          }
        }
      }

      return false
    } catch (error) {
      logger.error('Permission check failed', error, { userId, tenantId, resource, action })
      return false
    }
  }

  async enforceQuota(tenantId: string, resourceType: string, amount: number = 1): Promise<boolean> {
    const tenant = this.tenants.get(tenantId)
    if (!tenant) {
      throw new Error('Tenant not found')
    }

    const quotaKey = `quota:${tenantId}:${resourceType}`
    const client = redisManager.getConnection(RedisDatabase.RATE_LIMITING)

    try {
      // Get current usage
      const currentUsage = await client.get(quotaKey) || '0'
      const usage = parseInt(currentUsage) + amount

      // Check limits based on resource type
      let limit: number
      switch (resourceType) {
        case 'api_calls':
          limit = tenant.limits.apiCalls
          break
        case 'storage':
          limit = tenant.limits.storage
          break
        case 'data_transfer':
          limit = tenant.limits.dataTransfer
          break
        default:
          limit = 1000 // default limit
      }

      if (usage > limit) {
        logger.warn('Quota exceeded', { tenantId, resourceType, usage, limit })
        return false
      }

      // Update usage
      await client.set(quotaKey, usage.toString())

      // Set expiration based on reset period
      const resetPeriod = this.getResetPeriod(resourceType)
      await client.expire(quotaKey, resetPeriod)

      // Check if warning threshold reached
      const warningThreshold = limit * 0.8 // 80%
      if (usage > warningThreshold) {
        await this.sendQuotaWarning(tenantId, resourceType, usage, limit)
      }

      return true
    } catch (error) {
      logger.error('Quota enforcement failed', error, { tenantId, resourceType })
      return false
    }
  }

  // Cross-tenant data protection
  async validateCrossTenantAccess(
    sourceTenantId: string,
    targetTenantId: string,
    resourceType: string,
    resourceId: string,
    action: string
  ): Promise<boolean> {
    const sourceTenant = this.tenants.get(sourceTenantId)
    const targetTenant = this.tenants.get(targetTenantId)

    if (!sourceTenant || !targetTenant) {
      return false
    }

    // Check if cross-tenant sharing is allowed
    if (!targetTenant.settings.allowCrossTenantSharing) {
      return false
    }

    // Check for active sharing agreement
    const agreement = await this.findSharingAgreement(sourceTenantId, targetTenantId, resourceType, resourceId)
    if (!agreement || agreement.status !== 'active') {
      return false
    }

    // Verify permission is included in agreement
    if (!agreement.permissions.includes(action)) {
      return false
    }

    // Check conditions
    if (agreement.conditions.expiresAt && Date.now() > agreement.conditions.expiresAt) {
      return false
    }

    if (agreement.conditions.maxAccess) {
      const accessCount = await this.getAccessCount(agreement.id)
      if (accessCount >= agreement.conditions.maxAccess) {
        return false
      }
    }

    return true
  }

  async createSharingAgreement(agreement: Omit<DataSharingAgreement, 'id' | 'createdAt' | 'status'>): Promise<string> {
    const agreementId = `share_${Date.now()}_${crypto.randomUUID()}`

    const newAgreement: DataSharingAgreement = {
      id: agreementId,
      ...agreement,
      status: agreement.conditions.requireApproval ? 'pending' : 'active',
      createdAt: Date.now()
    }

    this.sharingAgreements.set(agreementId, newAgreement)
    await this.persistSharingAgreement(newAgreement)

    logger.info('Sharing agreement created', {
      agreementId,
      sourceTenant: agreement.sourceTenantId,
      targetTenant: agreement.targetTenantId
    })

    return agreementId
  }

  // Secure data sharing and collaboration
  async shareResource(
    sourceTenantId: string,
    targetTenantId: string,
    resourceType: string,
    resourceId: string,
    permissions: string[],
    conditions?: any
  ): Promise<string> {
    // Validate tenants
    if (!this.isValidTenant(sourceTenantId) || !this.isValidTenant(targetTenantId)) {
      throw new Error('Invalid tenant')
    }

    // Create sharing agreement
    const agreementId = await this.createSharingAgreement({
      sourceTenantId,
      targetTenantId,
      resourceType,
      resourceIds: [resourceId],
      permissions,
      conditions: conditions || {
        requireApproval: false,
        auditLevel: 'basic'
      }
    })

    // Create shared access key
    const sharedKey = this.generateSharedKey(sourceTenantId, targetTenantId, resourceType, resourceId)

    // Store shared resource metadata
    const client = redisManager.getConnection(RedisDatabase.CACHE)
    await client.hset('shared:resources', sharedKey, JSON.stringify({
      agreementId,
      sourceTenantId,
      targetTenantId,
      resourceType,
      resourceId,
      permissions,
      createdAt: Date.now()
    }))

    return sharedKey
  }

  async accessSharedResource(
    sharedKey: string,
    tenantId: string,
    action: string
  ): Promise<any> {
    const client = redisManager.getConnection(RedisDatabase.CACHE)
    const sharedResourceData = await client.hget('shared:resources', sharedKey)

    if (!sharedResourceData) {
      throw new Error('Shared resource not found')
    }

    const sharedResource = JSON.parse(sharedResourceData)

    // Verify tenant has access
    if (sharedResource.targetTenantId !== tenantId) {
      throw new Error('Access denied')
    }

    // Verify action is permitted
    if (!sharedResource.permissions.includes(action)) {
      throw new Error('Action not permitted')
    }

    // Validate cross-tenant access
    const hasAccess = await this.validateCrossTenantAccess(
      sharedResource.sourceTenantId,
      tenantId,
      sharedResource.resourceType,
      sharedResource.resourceId,
      action
    )

    if (!hasAccess) {
      throw new Error('Cross-tenant access denied')
    }

    // Retrieve the actual resource
    const resource = await this.retrieveData(
      sharedResource.sourceTenantId,
      sharedResource.resourceId
    )

    // Record access for auditing
    await this.recordSharedAccess(sharedKey, tenantId, action)

    return resource
  }

  // Tenant management
  async createTenant(tenantData: Omit<Tenant, 'id' | 'createdAt' | 'usage'>): Promise<string> {
    const tenantId = `tenant_${Date.now()}_${crypto.randomUUID()}`

    const tenant: Tenant = {
      id: tenantId,
      ...tenantData,
      createdAt: Date.now(),
      usage: {
        users: 0,
        storage: 0,
        apiCalls: 0,
        dataTransfer: 0,
        lastReset: Date.now()
      }
    }

    // Generate encryption key for tenant
    tenant.security.encryptionKey = crypto.randomBytes(32).toString('hex')

    this.tenants.set(tenantId, tenant)
    await this.persistTenant(tenant)

    // Create default roles for tenant
    await this.createDefaultRoles(tenantId)

    logger.info('Tenant created', { tenantId, name: tenant.name })
    return tenantId
  }

  async updateTenant(tenantId: string, updates: Partial<Tenant>): Promise<void> {
    const tenant = this.tenants.get(tenantId)
    if (!tenant) {
      throw new Error('Tenant not found')
    }

    Object.assign(tenant, updates)
    this.tenants.set(tenantId, tenant)
    await this.persistTenant(tenant)

    logger.info('Tenant updated', { tenantId, updates: Object.keys(updates) })
  }

  async suspendTenant(tenantId: string, reason: string): Promise<void> {
    const tenant = this.tenants.get(tenantId)
    if (!tenant) {
      throw new Error('Tenant not found')
    }

    tenant.status = 'suspended'
    await this.persistTenant(tenant)

    // Disable all user sessions for this tenant
    await this.disableTenantSessions(tenantId)

    logger.warn('Tenant suspended', { tenantId, reason })
  }

  // Helper methods
  private async encryptTenantData(data: any, tenant: Tenant): Promise<any> {
    if (tenant.security.encryptionLevel === 'standard') {
      return data // No encryption for standard level
    }

    const algorithm = 'aes-256-gcm'
    const key = Buffer.from(tenant.security.encryptionKey, 'hex')
    const iv = crypto.randomBytes(12)

    const cipher = crypto.createCipher(algorithm, key)
    const encrypted = Buffer.concat([cipher.update(JSON.stringify(data), 'utf8'), cipher.final()])
    const authTag = cipher.getAuthTag()

    return {
      encrypted: encrypted.toString('base64'),
      iv: iv.toString('base64'),
      authTag: authTag.toString('base64'),
      algorithm
    }
  }

  private async decryptTenantData(encryptedData: any, tenant: Tenant): Promise<any> {
    if (!encryptedData.encrypted) {
      return encryptedData // Not encrypted
    }

    const algorithm = encryptedData.algorithm
    const key = Buffer.from(tenant.security.encryptionKey, 'hex')
    const iv = Buffer.from(encryptedData.iv, 'base64')
    const authTag = Buffer.from(encryptedData.authTag, 'base64')
    const encrypted = Buffer.from(encryptedData.encrypted, 'base64')

    const decipher = crypto.createDecipher(algorithm, key)
    decipher.setAuthTag(authTag)

    const decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()])
    return JSON.parse(decrypted.toString('utf8'))
  }

  private matchesPermission(
    permission: Permission,
    resource: string,
    action: string,
    context?: any
  ): boolean {
    // Check resource match
    if (permission.resource !== '*' && permission.resource !== resource) {
      return false
    }

    // Check action match
    if (!permission.actions.includes('*') && !permission.actions.includes(action)) {
      return false
    }

    // Check conditions
    if (permission.conditions && context) {
      if (permission.conditions.ipRestriction && context.ip) {
        if (!permission.conditions.ipRestriction.includes(context.ip)) {
          return false
        }
      }

      if (permission.conditions.dataClassification && context.dataClassification) {
        if (!permission.conditions.dataClassification.includes(context.dataClassification)) {
          return false
        }
      }
    }

    return true
  }

  private generateSharedKey(
    sourceTenantId: string,
    targetTenantId: string,
    resourceType: string,
    resourceId: string
  ): string {
    const input = `${sourceTenantId}:${targetTenantId}:${resourceType}:${resourceId}:${Date.now()}`
    return crypto.createHash('sha256').update(input).digest('hex')
  }

  private isValidTenant(tenantId: string): boolean {
    const tenant = this.tenants.get(tenantId)
    return tenant !== undefined && tenant.status === 'active'
  }

  private getResetPeriod(resourceType: string): number {
    switch (resourceType) {
      case 'api_calls':
        return 3600 // 1 hour
      case 'storage':
        return 24 * 3600 // 1 day
      case 'data_transfer':
        return 30 * 24 * 3600 // 1 month
      default:
        return 3600
    }
  }

  private async sendQuotaWarning(
    tenantId: string,
    resourceType: string,
    usage: number,
    limit: number
  ): Promise<void> {
    logger.warn('Quota warning threshold reached', {
      tenantId,
      resourceType,
      usage,
      limit,
      percentage: (usage / limit) * 100
    })
  }

  private async findSharingAgreement(
    sourceTenantId: string,
    targetTenantId: string,
    resourceType: string,
    resourceId: string
  ): Promise<DataSharingAgreement | null> {
    for (const agreement of this.sharingAgreements.values()) {
      if (
        agreement.sourceTenantId === sourceTenantId &&
        agreement.targetTenantId === targetTenantId &&
        agreement.resourceType === resourceType &&
        agreement.resourceIds.includes(resourceId)
      ) {
        return agreement
      }
    }
    return null
  }

  private async getAccessCount(agreementId: string): Promise<number> {
    const client = redisManager.getConnection(RedisDatabase.ANALYTICS)
    const count = await client.get(`access_count:${agreementId}`)
    return count ? parseInt(count) : 0
  }

  private async recordSharedAccess(sharedKey: string, tenantId: string, action: string): Promise<void> {
    const client = redisManager.getConnection(RedisDatabase.ANALYTICS)
    await client.incr(`access_count:${sharedKey}`)
    await client.zadd('shared_access_log', Date.now(), JSON.stringify({
      sharedKey,
      tenantId,
      action,
      timestamp: Date.now()
    }))
  }

  private async getUser(userId: string): Promise<User | null> {
    const client = redisManager.getConnection(RedisDatabase.CACHE)
    const userData = await client.hget('users', userId)
    return userData ? JSON.parse(userData) : null
  }

  private async createDefaultRoles(tenantId: string): Promise<void> {
    const defaultRoles = [
      {
        name: 'Admin',
        description: 'Full access to all resources',
        permissions: ['*']
      },
      {
        name: 'User',
        description: 'Basic user access',
        permissions: ['data:read', 'profile:update']
      },
      {
        name: 'Viewer',
        description: 'Read-only access',
        permissions: ['data:read']
      }
    ]

    for (const roleData of defaultRoles) {
      const roleId = `${tenantId}_${roleData.name.toLowerCase()}`
      const role: Role = {
        id: roleId,
        tenantId,
        ...roleData,
        isSystemRole: true,
        createdAt: Date.now(),
        updatedAt: Date.now()
      }

      this.roles.set(roleId, role)
      await this.persistRole(role)
    }
  }

  private async disableTenantSessions(tenantId: string): Promise<void> {
    // Implementation would disable all active sessions for the tenant
    logger.info('Tenant sessions disabled', { tenantId })
  }

  // Persistence methods
  private async loadTenants(): Promise<void> {
    const client = redisManager.getConnection(RedisDatabase.CACHE)
    try {
      const tenants = await client.hgetall('security:tenants')
      for (const [id, data] of Object.entries(tenants)) {
        this.tenants.set(id, JSON.parse(data))
      }
    } catch (error) {
      logger.info('No existing tenants found')
    }
  }

  private async persistTenant(tenant: Tenant): Promise<void> {
    const client = redisManager.getConnection(RedisDatabase.CACHE)
    await client.hset('security:tenants', tenant.id, JSON.stringify(tenant))
  }

  private async loadRoles(): Promise<void> {
    const client = redisManager.getConnection(RedisDatabase.CACHE)
    try {
      const roles = await client.hgetall('security:roles')
      for (const [id, data] of Object.entries(roles)) {
        this.roles.set(id, JSON.parse(data))
      }
    } catch (error) {
      logger.info('No existing roles found')
    }
  }

  private async persistRole(role: Role): Promise<void> {
    const client = redisManager.getConnection(RedisDatabase.CACHE)
    await client.hset('security:roles', role.id, JSON.stringify(role))
  }

  private async loadPermissions(): Promise<void> {
    const client = redisManager.getConnection(RedisDatabase.CACHE)
    try {
      const permissions = await client.hgetall('security:permissions')
      for (const [id, data] of Object.entries(permissions)) {
        this.permissions.set(id, JSON.parse(data))
      }
    } catch (error) {
      await this.setupDefaultPermissions()
    }
  }

  private async setupDefaultPermissions(): Promise<void> {
    const defaultPermissions: Permission[] = [
      {
        id: 'data:read',
        name: 'Read Data',
        resource: 'data',
        actions: ['read']
      },
      {
        id: 'data:write',
        name: 'Write Data',
        resource: 'data',
        actions: ['create', 'update']
      },
      {
        id: 'data:delete',
        name: 'Delete Data',
        resource: 'data',
        actions: ['delete']
      },
      {
        id: 'admin:all',
        name: 'Admin Access',
        resource: '*',
        actions: ['*']
      }
    ]

    for (const permission of defaultPermissions) {
      this.permissions.set(permission.id, permission)
      await this.persistPermission(permission)
    }
  }

  private async persistPermission(permission: Permission): Promise<void> {
    const client = redisManager.getConnection(RedisDatabase.CACHE)
    await client.hset('security:permissions', permission.id, JSON.stringify(permission))
  }

  private async loadSharingAgreements(): Promise<void> {
    const client = redisManager.getConnection(RedisDatabase.CACHE)
    try {
      const agreements = await client.hgetall('security:sharing_agreements')
      for (const [id, data] of Object.entries(agreements)) {
        this.sharingAgreements.set(id, JSON.parse(data))
      }
    } catch (error) {
      logger.info('No existing sharing agreements found')
    }
  }

  private async persistSharingAgreement(agreement: DataSharingAgreement): Promise<void> {
    const client = redisManager.getConnection(RedisDatabase.CACHE)
    await client.hset('security:sharing_agreements', agreement.id, JSON.stringify(agreement))
  }

  private async startQuotaMonitoring(): Promise<void> {
    // Reset quotas periodically
    setInterval(async () => {
      await this.resetQuotas()
    }, 60 * 60 * 1000) // Every hour
  }

  private async resetQuotas(): Promise<void> {
    const client = redisManager.getConnection(RedisDatabase.RATE_LIMITING)
    const now = Date.now()

    for (const tenant of this.tenants.values()) {
      // Reset hourly quotas
      if (now - tenant.usage.lastReset > 60 * 60 * 1000) {
        tenant.usage.apiCalls = 0
        tenant.usage.lastReset = now
        await this.persistTenant(tenant)
        await client.del(`quota:${tenant.id}:api_calls`)
      }
    }
  }
}

export const multiTenantSecurityManager = new MultiTenantSecurityManager()