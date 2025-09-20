import { redisManager, RedisDatabase } from '@/lib/redis-manager'
import { logger } from '@/lib/logger'
import crypto from 'crypto'
import { promisify } from 'util'

export interface EncryptionKey {
  id: string
  algorithm: 'aes-256-gcm' | 'aes-256-cbc' | 'chacha20-poly1305'
  key: Buffer
  iv?: Buffer
  purpose: 'data' | 'pii' | 'tokens' | 'communications' | 'storage'
  createdAt: number
  expiresAt?: number
  rotatedAt?: number
  version: number
  status: 'active' | 'retired' | 'compromised'
  metadata: {
    tenantId?: string
    dataClassification: 'public' | 'internal' | 'confidential' | 'restricted'
    complianceRequirements: string[]
  }
}

export interface KeyRotationPolicy {
  id: string
  purpose: string
  rotationInterval: number // milliseconds
  retentionPeriod: number // milliseconds
  autoRotate: boolean
  notifyBeforeRotation: number // milliseconds
  enabled: boolean
}

export interface EncryptedData {
  data: string
  algorithm: string
  keyId: string
  iv: string
  authTag?: string
  timestamp: number
}

export interface KeyDerivationConfig {
  algorithm: 'pbkdf2' | 'argon2' | 'scrypt'
  iterations?: number
  memory?: number // for argon2
  parallelism?: number // for argon2
  saltLength: number
  keyLength: number
}

export interface HSMConfig {
  enabled: boolean
  provider: 'aws-cloudhsm' | 'azure-hsm' | 'local-hsm'
  endpoint?: string
  credentials?: {
    accessKey?: string
    secretKey?: string
    region?: string
  }
  keyLabels: {
    master: string
    data: string
    pii: string
  }
}

export class EncryptionKeyManager {
  private keys: Map<string, EncryptionKey> = new Map()
  private rotationPolicies: Map<string, KeyRotationPolicy> = new Map()
  private masterKey: Buffer
  private hsmConfig: HSMConfig
  private keyDerivationConfig: KeyDerivationConfig
  private initialized = false

  constructor() {
    this.masterKey = this.loadOrGenerateMasterKey()
    this.hsmConfig = {
      enabled: process.env.HSM_ENABLED === 'true',
      provider: (process.env.HSM_PROVIDER as any) || 'local-hsm',
      endpoint: process.env.HSM_ENDPOINT,
      credentials: {
        accessKey: process.env.HSM_ACCESS_KEY,
        secretKey: process.env.HSM_SECRET_KEY,
        region: process.env.HSM_REGION
      },
      keyLabels: {
        master: process.env.HSM_MASTER_KEY_LABEL || 'meta-ads-master',
        data: process.env.HSM_DATA_KEY_LABEL || 'meta-ads-data',
        pii: process.env.HSM_PII_KEY_LABEL || 'meta-ads-pii'
      }
    }

    this.keyDerivationConfig = {
      algorithm: 'pbkdf2',
      iterations: 100000,
      saltLength: 32,
      keyLength: 32
    }
  }

  async initialize(): Promise<void> {
    try {
      await this.loadKeys()
      await this.loadRotationPolicies()
      await this.setupDefaultRotationPolicies()
      await this.startKeyRotationScheduler()

      if (this.hsmConfig.enabled) {
        await this.initializeHSM()
      }

      this.initialized = true
      logger.info('Encryption key manager initialized', {
        keysLoaded: this.keys.size,
        rotationPolicies: this.rotationPolicies.size,
        hsmEnabled: this.hsmConfig.enabled
      })
    } catch (error) {
      logger.error('Failed to initialize encryption key manager', error)
      throw error
    }
  }

  // Field-level encryption for sensitive data
  async encryptField(
    data: string | Buffer,
    purpose: 'data' | 'pii' | 'tokens' | 'communications' | 'storage',
    tenantId?: string,
    dataClassification: 'public' | 'internal' | 'confidential' | 'restricted' = 'internal'
  ): Promise<EncryptedData> {
    const key = await this.getActiveKey(purpose, tenantId, dataClassification)

    if (!key) {
      throw new Error(`No active encryption key found for purpose: ${purpose}`)
    }

    const iv = crypto.randomBytes(12) // GCM recommends 12 bytes
    const cipher = crypto.createCipher(key.algorithm, key.key)
    cipher.setAAD(Buffer.from(JSON.stringify({
      keyId: key.id,
      purpose,
      tenantId: tenantId || 'global',
      timestamp: Date.now()
    })))

    let encrypted: Buffer
    let authTag: Buffer | undefined

    if (key.algorithm.includes('gcm')) {
      encrypted = Buffer.concat([
        cipher.update(Buffer.isBuffer(data) ? data : Buffer.from(data, 'utf8')),
        cipher.final()
      ])
      authTag = cipher.getAuthTag()
    } else {
      encrypted = Buffer.concat([
        cipher.update(Buffer.isBuffer(data) ? data : Buffer.from(data, 'utf8')),
        cipher.final()
      ])
    }

    const result: EncryptedData = {
      data: encrypted.toString('base64'),
      algorithm: key.algorithm,
      keyId: key.id,
      iv: iv.toString('base64'),
      timestamp: Date.now()
    }

    if (authTag) {
      result.authTag = authTag.toString('base64')
    }

    return result
  }

  async decryptField(encryptedData: EncryptedData): Promise<Buffer> {
    const key = this.keys.get(encryptedData.keyId)

    if (!key) {
      throw new Error(`Encryption key not found: ${encryptedData.keyId}`)
    }

    if (key.status === 'compromised') {
      throw new Error('Cannot decrypt with compromised key')
    }

    const iv = Buffer.from(encryptedData.iv, 'base64')
    const data = Buffer.from(encryptedData.data, 'base64')
    const decipher = crypto.createDecipher(encryptedData.algorithm, key.key)

    if (encryptedData.authTag) {
      decipher.setAuthTag(Buffer.from(encryptedData.authTag, 'base64'))
    }

    decipher.setAAD(Buffer.from(JSON.stringify({
      keyId: encryptedData.keyId,
      purpose: key.purpose,
      tenantId: key.metadata.tenantId || 'global',
      timestamp: encryptedData.timestamp
    })))

    const decrypted = Buffer.concat([
      decipher.update(data),
      decipher.final()
    ])

    return decrypted
  }

  // Automatic key rotation with zero downtime
  async rotateKey(keyId: string): Promise<string> {
    const oldKey = this.keys.get(keyId)
    if (!oldKey) {
      throw new Error(`Key not found: ${keyId}`)
    }

    // Create new key with same parameters
    const newKey = await this.createKey(
      oldKey.purpose,
      oldKey.algorithm,
      oldKey.metadata
    )

    // Mark old key as retired
    oldKey.status = 'retired'
    oldKey.rotatedAt = Date.now()
    await this.persistKey(oldKey)

    logger.info('Key rotated', {
      oldKeyId: keyId,
      newKeyId: newKey.id,
      purpose: oldKey.purpose
    })

    // Schedule old key deletion after retention period
    await this.scheduleKeyDeletion(oldKey)

    return newKey.id
  }

  async rotateAllKeys(): Promise<Map<string, string>> {
    const rotations = new Map<string, string>()

    for (const [keyId, key] of this.keys) {
      if (key.status === 'active' && this.shouldRotate(key)) {
        try {
          const newKeyId = await this.rotateKey(keyId)
          rotations.set(keyId, newKeyId)
        } catch (error) {
          logger.error('Failed to rotate key', error, { keyId })
        }
      }
    }

    logger.info('Bulk key rotation completed', {
      rotatedKeys: rotations.size
    })

    return rotations
  }

  // Secure key derivation functions
  async deriveKey(
    password: string,
    salt: Buffer | string,
    config?: Partial<KeyDerivationConfig>
  ): Promise<Buffer> {
    const derivationConfig = { ...this.keyDerivationConfig, ...config }
    const saltBuffer = Buffer.isBuffer(salt) ? salt : Buffer.from(salt, 'hex')

    switch (derivationConfig.algorithm) {
      case 'pbkdf2':
        return promisify(crypto.pbkdf2)(
          password,
          saltBuffer,
          derivationConfig.iterations!,
          derivationConfig.keyLength,
          'sha256'
        )

      case 'scrypt':
        return promisify(crypto.scrypt)(
          password,
          saltBuffer,
          derivationConfig.keyLength,
          {
            N: derivationConfig.iterations || 16384,
            r: 8,
            p: 1
          }
        ) as Promise<Buffer>

      case 'argon2':
        // Note: Would need argon2 library for production
        throw new Error('Argon2 not implemented - install argon2 library')

      default:
        throw new Error(`Unsupported key derivation algorithm: ${derivationConfig.algorithm}`)
    }
  }

  // End-to-end encryption for communications
  async generateKeyPair(algorithm: 'rsa' | 'ec' = 'ec'): Promise<{
    publicKey: string
    privateKey: string
    keyId: string
  }> {
    let keyPair: crypto.KeyPairSyncResult<string, string>

    if (algorithm === 'rsa') {
      keyPair = crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
      })
    } else {
      keyPair = crypto.generateKeyPairSync('ec', {
        namedCurve: 'secp256r1',
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
      })
    }

    const keyId = `keypair_${Date.now()}_${crypto.randomUUID()}`

    // Store key pair securely
    await this.storeKeyPair(keyId, keyPair.publicKey, keyPair.privateKey)

    return {
      publicKey: keyPair.publicKey,
      privateKey: keyPair.privateKey,
      keyId
    }
  }

  async encryptWithPublicKey(data: string, publicKey: string): Promise<string> {
    const encrypted = crypto.publicEncrypt(
      {
        key: publicKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha256'
      },
      Buffer.from(data, 'utf8')
    )

    return encrypted.toString('base64')
  }

  async decryptWithPrivateKey(encryptedData: string, keyId: string): Promise<string> {
    const privateKey = await this.getPrivateKey(keyId)
    if (!privateKey) {
      throw new Error(`Private key not found: ${keyId}`)
    }

    const decrypted = crypto.privateDecrypt(
      {
        key: privateKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha256'
      },
      Buffer.from(encryptedData, 'base64')
    )

    return decrypted.toString('utf8')
  }

  // Token encryption for API keys and session tokens
  async encryptToken(token: string, tenantId?: string): Promise<string> {
    const encrypted = await this.encryptField(token, 'tokens', tenantId, 'confidential')
    return Buffer.from(JSON.stringify(encrypted)).toString('base64')
  }

  async decryptToken(encryptedToken: string): Promise<string> {
    const encryptedData: EncryptedData = JSON.parse(
      Buffer.from(encryptedToken, 'base64').toString('utf8')
    )
    const decrypted = await this.decryptField(encryptedData)
    return decrypted.toString('utf8')
  }

  // PII encryption with special handling
  async encryptPII(
    piiData: Record<string, any>,
    tenantId: string,
    dataClassification: 'confidential' | 'restricted' = 'restricted'
  ): Promise<Record<string, string>> {
    const encrypted: Record<string, string> = {}

    for (const [field, value] of Object.entries(piiData)) {
      if (value !== null && value !== undefined) {
        const encryptedValue = await this.encryptField(
          JSON.stringify(value),
          'pii',
          tenantId,
          dataClassification
        )
        encrypted[field] = Buffer.from(JSON.stringify(encryptedValue)).toString('base64')
      }
    }

    return encrypted
  }

  async decryptPII(encryptedPII: Record<string, string>): Promise<Record<string, any>> {
    const decrypted: Record<string, any> = {}

    for (const [field, encryptedValue] of Object.entries(encryptedPII)) {
      try {
        const encryptedData: EncryptedData = JSON.parse(
          Buffer.from(encryptedValue, 'base64').toString('utf8')
        )
        const decryptedBuffer = await this.decryptField(encryptedData)
        decrypted[field] = JSON.parse(decryptedBuffer.toString('utf8'))
      } catch (error) {
        logger.error('Failed to decrypt PII field', error, { field })
        decrypted[field] = null
      }
    }

    return decrypted
  }

  // HSM integration preparation
  private async initializeHSM(): Promise<void> {
    if (!this.hsmConfig.enabled) return

    try {
      // HSM initialization would go here
      // This is a placeholder for actual HSM integration
      logger.info('HSM initialization prepared', {
        provider: this.hsmConfig.provider,
        endpoint: this.hsmConfig.endpoint
      })
    } catch (error) {
      logger.error('HSM initialization failed', error)
      throw error
    }
  }

  // Key management utilities
  private async createKey(
    purpose: 'data' | 'pii' | 'tokens' | 'communications' | 'storage',
    algorithm: 'aes-256-gcm' | 'aes-256-cbc' | 'chacha20-poly1305' = 'aes-256-gcm',
    metadata: EncryptionKey['metadata']
  ): Promise<EncryptionKey> {
    const keyId = `key_${purpose}_${Date.now()}_${crypto.randomUUID()}`

    let keyLength: number
    switch (algorithm) {
      case 'aes-256-gcm':
      case 'aes-256-cbc':
        keyLength = 32
        break
      case 'chacha20-poly1305':
        keyLength = 32
        break
      default:
        throw new Error(`Unsupported algorithm: ${algorithm}`)
    }

    const key: EncryptionKey = {
      id: keyId,
      algorithm,
      key: await this.generateSecureKey(keyLength),
      purpose,
      createdAt: Date.now(),
      version: 1,
      status: 'active',
      metadata
    }

    // Set expiration based on rotation policy
    const policy = this.rotationPolicies.get(purpose)
    if (policy && policy.rotationInterval > 0) {
      key.expiresAt = Date.now() + policy.rotationInterval
    }

    this.keys.set(keyId, key)
    await this.persistKey(key)

    logger.info('Encryption key created', {
      keyId,
      purpose,
      algorithm,
      tenantId: metadata.tenantId
    })

    return key
  }

  private async generateSecureKey(length: number): Promise<Buffer> {
    if (this.hsmConfig.enabled) {
      // Generate key using HSM
      return this.generateHSMKey(length)
    } else {
      // Generate key using crypto.randomBytes
      return crypto.randomBytes(length)
    }
  }

  private async generateHSMKey(length: number): Promise<Buffer> {
    // Placeholder for HSM key generation
    // In production, this would interface with actual HSM
    return crypto.randomBytes(length)
  }

  private async getActiveKey(
    purpose: string,
    tenantId?: string,
    dataClassification?: string
  ): Promise<EncryptionKey | null> {
    for (const key of this.keys.values()) {
      if (
        key.purpose === purpose &&
        key.status === 'active' &&
        (!tenantId || key.metadata.tenantId === tenantId) &&
        (!dataClassification || key.metadata.dataClassification === dataClassification)
      ) {
        return key
      }
    }

    // Create new key if none exists
    return await this.createKey(purpose as any, 'aes-256-gcm', {
      tenantId,
      dataClassification: dataClassification as any || 'internal',
      complianceRequirements: []
    })
  }

  private shouldRotate(key: EncryptionKey): boolean {
    if (key.expiresAt && Date.now() > key.expiresAt) {
      return true
    }

    const policy = this.rotationPolicies.get(key.purpose)
    if (!policy || !policy.autoRotate) {
      return false
    }

    const age = Date.now() - key.createdAt
    return age > policy.rotationInterval
  }

  private async scheduleKeyDeletion(key: EncryptionKey): Promise<void> {
    const policy = this.rotationPolicies.get(key.purpose)
    const retentionPeriod = policy?.retentionPeriod || (90 * 24 * 60 * 60 * 1000) // 90 days

    setTimeout(async () => {
      try {
        this.keys.delete(key.id)
        await this.deletePersistedKey(key.id)
        logger.info('Retired key deleted', { keyId: key.id })
      } catch (error) {
        logger.error('Failed to delete retired key', error, { keyId: key.id })
      }
    }, retentionPeriod)
  }

  private loadOrGenerateMasterKey(): Buffer {
    const masterKeyPath = process.env.MASTER_KEY_PATH || './master.key'

    try {
      // In production, this should be loaded from secure storage
      const fs = require('fs')
      if (fs.existsSync(masterKeyPath)) {
        return fs.readFileSync(masterKeyPath)
      }
    } catch (error) {
      logger.warn('Could not load master key from file')
    }

    // Generate new master key
    const masterKey = crypto.randomBytes(32)

    try {
      const fs = require('fs')
      fs.writeFileSync(masterKeyPath, masterKey, { mode: 0o600 })
      logger.info('New master key generated and saved')
    } catch (error) {
      logger.warn('Could not save master key to file', error)
    }

    return masterKey
  }

  // Persistence methods
  private async loadKeys(): Promise<void> {
    const client = redisManager.getConnection(RedisDatabase.CACHE)
    try {
      const keys = await client.hgetall('security:encryption_keys')
      for (const [id, encryptedData] of Object.entries(keys)) {
        try {
          const decryptedData = this.decryptWithMasterKey(encryptedData)
          const key: EncryptionKey = JSON.parse(decryptedData)
          key.key = Buffer.from(key.key as any, 'base64')
          this.keys.set(id, key)
        } catch (error) {
          logger.error('Failed to load encryption key', error, { keyId: id })
        }
      }
    } catch (error) {
      logger.info('No existing encryption keys found')
    }
  }

  private async persistKey(key: EncryptionKey): Promise<void> {
    const client = redisManager.getConnection(RedisDatabase.CACHE)

    // Encrypt key data with master key before storing
    const keyData = {
      ...key,
      key: key.key.toString('base64')
    }

    const encryptedData = this.encryptWithMasterKey(JSON.stringify(keyData))
    await client.hset('security:encryption_keys', key.id, encryptedData)
  }

  private async deletePersistedKey(keyId: string): Promise<void> {
    const client = redisManager.getConnection(RedisDatabase.CACHE)
    await client.hdel('security:encryption_keys', keyId)
  }

  private encryptWithMasterKey(data: string): string {
    const iv = crypto.randomBytes(12)
    const cipher = crypto.createCipher('aes-256-gcm', this.masterKey)

    const encrypted = Buffer.concat([
      cipher.update(data, 'utf8'),
      cipher.final()
    ])

    const authTag = cipher.getAuthTag()

    return JSON.stringify({
      iv: iv.toString('base64'),
      data: encrypted.toString('base64'),
      authTag: authTag.toString('base64')
    })
  }

  private decryptWithMasterKey(encryptedData: string): string {
    const { iv, data, authTag } = JSON.parse(encryptedData)

    const decipher = crypto.createDecipher('aes-256-gcm', this.masterKey)
    decipher.setAuthTag(Buffer.from(authTag, 'base64'))

    const decrypted = Buffer.concat([
      decipher.update(Buffer.from(data, 'base64')),
      decipher.final()
    ])

    return decrypted.toString('utf8')
  }

  private async loadRotationPolicies(): Promise<void> {
    const client = redisManager.getConnection(RedisDatabase.CACHE)
    try {
      const policies = await client.hgetall('security:rotation_policies')
      for (const [id, data] of Object.entries(policies)) {
        this.rotationPolicies.set(id, JSON.parse(data))
      }
    } catch (error) {
      await this.setupDefaultRotationPolicies()
    }
  }

  private async setupDefaultRotationPolicies(): Promise<void> {
    const defaultPolicies: KeyRotationPolicy[] = [
      {
        id: 'data_encryption',
        purpose: 'data',
        rotationInterval: 90 * 24 * 60 * 60 * 1000, // 90 days
        retentionPeriod: 365 * 24 * 60 * 60 * 1000, // 1 year
        autoRotate: true,
        notifyBeforeRotation: 7 * 24 * 60 * 60 * 1000, // 7 days
        enabled: true
      },
      {
        id: 'pii_encryption',
        purpose: 'pii',
        rotationInterval: 30 * 24 * 60 * 60 * 1000, // 30 days
        retentionPeriod: 90 * 24 * 60 * 60 * 1000, // 90 days
        autoRotate: true,
        notifyBeforeRotation: 3 * 24 * 60 * 60 * 1000, // 3 days
        enabled: true
      },
      {
        id: 'token_encryption',
        purpose: 'tokens',
        rotationInterval: 7 * 24 * 60 * 60 * 1000, // 7 days
        retentionPeriod: 30 * 24 * 60 * 60 * 1000, // 30 days
        autoRotate: true,
        notifyBeforeRotation: 1 * 24 * 60 * 60 * 1000, // 1 day
        enabled: true
      }
    ]

    for (const policy of defaultPolicies) {
      this.rotationPolicies.set(policy.id, policy)
      await this.persistRotationPolicy(policy)
    }
  }

  private async persistRotationPolicy(policy: KeyRotationPolicy): Promise<void> {
    const client = redisManager.getConnection(RedisDatabase.CACHE)
    await client.hset('security:rotation_policies', policy.id, JSON.stringify(policy))
  }

  private async startKeyRotationScheduler(): Promise<void> {
    // Check for key rotation every hour
    setInterval(async () => {
      try {
        await this.checkKeyRotations()
      } catch (error) {
        logger.error('Key rotation check failed', error)
      }
    }, 60 * 60 * 1000)
  }

  private async checkKeyRotations(): Promise<void> {
    for (const [keyId, key] of this.keys) {
      if (key.status === 'active' && this.shouldRotate(key)) {
        const policy = this.rotationPolicies.get(key.purpose)

        if (policy?.notifyBeforeRotation) {
          const timeToRotation = (key.expiresAt || 0) - Date.now()
          if (timeToRotation <= policy.notifyBeforeRotation && timeToRotation > 0) {
            logger.warn('Key rotation due soon', {
              keyId,
              purpose: key.purpose,
              expiresAt: new Date(key.expiresAt!).toISOString()
            })
          }
        }

        if (policy?.autoRotate) {
          await this.rotateKey(keyId)
        }
      }
    }
  }

  private async storeKeyPair(keyId: string, publicKey: string, privateKey: string): Promise<void> {
    const client = redisManager.getConnection(RedisDatabase.CACHE)

    // Encrypt private key with master key
    const encryptedPrivateKey = this.encryptWithMasterKey(privateKey)

    await client.hset('security:key_pairs', keyId, JSON.stringify({
      publicKey,
      privateKey: encryptedPrivateKey,
      createdAt: Date.now()
    }))
  }

  private async getPrivateKey(keyId: string): Promise<string | null> {
    const client = redisManager.getConnection(RedisDatabase.CACHE)
    const keyPairData = await client.hget('security:key_pairs', keyId)

    if (!keyPairData) {
      return null
    }

    const { privateKey } = JSON.parse(keyPairData)
    return this.decryptWithMasterKey(privateKey)
  }

  // Public methods for key management
  async getKeyStats(): Promise<{
    totalKeys: number
    activeKeys: number
    retiredKeys: number
    compromisedKeys: number
    keysByPurpose: Record<string, number>
    rotationsDue: number
  }> {
    const stats = {
      totalKeys: this.keys.size,
      activeKeys: 0,
      retiredKeys: 0,
      compromisedKeys: 0,
      keysByPurpose: {} as Record<string, number>,
      rotationsDue: 0
    }

    for (const key of this.keys.values()) {
      switch (key.status) {
        case 'active':
          stats.activeKeys++
          break
        case 'retired':
          stats.retiredKeys++
          break
        case 'compromised':
          stats.compromisedKeys++
          break
      }

      stats.keysByPurpose[key.purpose] = (stats.keysByPurpose[key.purpose] || 0) + 1

      if (this.shouldRotate(key)) {
        stats.rotationsDue++
      }
    }

    return stats
  }

  async markKeyCompromised(keyId: string, reason: string): Promise<void> {
    const key = this.keys.get(keyId)
    if (!key) {
      throw new Error(`Key not found: ${keyId}`)
    }

    key.status = 'compromised'
    await this.persistKey(key)

    // Force immediate rotation
    if (key.status === 'active') {
      await this.rotateKey(keyId)
    }

    logger.error('Key marked as compromised', { keyId, reason })
  }
}

export const encryptionKeyManager = new EncryptionKeyManager()