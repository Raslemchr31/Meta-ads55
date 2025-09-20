import mysql from 'mysql2/promise'
import { createHash } from 'crypto'

interface DatabaseConfig {
  host: string
  port: number
  user: string
  password: string
  database: string
  ssl?: mysql.SslOptions
  connectionLimit: number
  acquireTimeout: number
  timeout: number
  reconnect: boolean
}

export class DatabaseManager {
  private pool: mysql.Pool | null = null
  private config: DatabaseConfig

  constructor() {
    this.config = {
      host: process.env.DB_HOST || 'localhost',
      port: parseInt(process.env.DB_PORT || '3306'),
      user: process.env.DB_USER || 'root',
      password: process.env.DB_PASSWORD || '',
      database: process.env.DB_NAME || 'meta_ads_platform',
      ssl: process.env.DB_SSL === 'true' ? { rejectUnauthorized: false } : undefined,
      connectionLimit: parseInt(process.env.DB_CONNECTION_LIMIT || '10'),
      acquireTimeout: 60000,
      timeout: 60000,
      reconnect: true,
    }
  }

  async getConnection(): Promise<mysql.Pool> {
    if (!this.pool) {
      this.pool = mysql.createPool(this.config)
      
      // Test the connection
      try {
        const connection = await this.pool.getConnection()
        await connection.ping()
        connection.release()
        console.log('Database connection established successfully')
      } catch (error) {
        console.error('Failed to establish database connection:', error)
        throw new Error('Database connection failed')
      }
    }
    return this.pool
  }

  async initializeSchema(): Promise<void> {
    const pool = await this.getConnection()
    
    const queries = [
      // Create daily_insights table as specified in requirements
      `CREATE TABLE IF NOT EXISTS daily_insights (
        id BIGINT AUTO_INCREMENT PRIMARY KEY,
        entity_type ENUM('campaign', 'adset', 'ad') NOT NULL,
        entity_id VARCHAR(255) NOT NULL,
        entity_name VARCHAR(500),
        account_id VARCHAR(255) NOT NULL,
        date_start DATE NOT NULL,
        date_stop DATE NOT NULL,
        spend DECIMAL(10,2) DEFAULT 0,
        impressions BIGINT DEFAULT 0,
        clicks BIGINT DEFAULT 0,
        reach BIGINT DEFAULT 0,
        frequency DECIMAL(10,4) DEFAULT 0,
        ctr DECIMAL(10,4) DEFAULT 0,
        cpc DECIMAL(10,4) DEFAULT 0,
        cpm DECIMAL(10,4) DEFAULT 0,
        cpp DECIMAL(10,4) DEFAULT 0,
        actions_json JSON,
        action_values_json JSON,
        conversions_json JSON,
        conversion_values_json JSON,
        cost_per_action_type_json JSON,
        video_metrics_json JSON,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        UNIQUE KEY unique_entity_date (entity_type, entity_id, date_start),
        INDEX idx_account_date (account_id, date_start),
        INDEX idx_entity_type_date (entity_type, date_start),
        INDEX idx_spend (spend DESC),
        INDEX idx_impressions (impressions DESC),
        INDEX idx_clicks (clicks DESC),
        INDEX idx_updated_at (updated_at)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`,

      // Create ad_accounts table
      `CREATE TABLE IF NOT EXISTS ad_accounts (
        id VARCHAR(255) PRIMARY KEY,
        name VARCHAR(500) NOT NULL,
        account_status INT DEFAULT 1,
        currency VARCHAR(10) NOT NULL,
        timezone_name VARCHAR(100),
        business_id VARCHAR(255),
        business_name VARCHAR(500),
        amount_spent DECIMAL(15,2) DEFAULT 0,
        balance DECIMAL(15,2) DEFAULT 0,
        spend_cap DECIMAL(15,2),
        created_time TIMESTAMP NULL,
        capabilities_json JSON,
        last_sync_at TIMESTAMP NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        INDEX idx_business_id (business_id),
        INDEX idx_last_sync (last_sync_at),
        INDEX idx_amount_spent (amount_spent DESC)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`,

      // Create campaigns table
      `CREATE TABLE IF NOT EXISTS campaigns (
        id VARCHAR(255) PRIMARY KEY,
        name VARCHAR(500) NOT NULL,
        account_id VARCHAR(255) NOT NULL,
        objective VARCHAR(100),
        status VARCHAR(50),
        configured_status VARCHAR(50),
        effective_status VARCHAR(50),
        daily_budget DECIMAL(10,2),
        lifetime_budget DECIMAL(10,2),
        budget_remaining DECIMAL(10,2),
        bid_strategy VARCHAR(100),
        optimization_goal VARCHAR(100),
        spend_cap DECIMAL(10,2),
        start_time TIMESTAMP NULL,
        stop_time TIMESTAMP NULL,
        created_time TIMESTAMP NULL,
        updated_time TIMESTAMP NULL,
        issues_info_json JSON,
        last_sync_at TIMESTAMP NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        INDEX idx_account_id (account_id),
        INDEX idx_status (status),
        INDEX idx_objective (objective),
        INDEX idx_last_sync (last_sync_at),
        FOREIGN KEY (account_id) REFERENCES ad_accounts(id) ON DELETE CASCADE
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`,

      // Create adsets table
      `CREATE TABLE IF NOT EXISTS adsets (
        id VARCHAR(255) PRIMARY KEY,
        name VARCHAR(500) NOT NULL,
        campaign_id VARCHAR(255) NOT NULL,
        account_id VARCHAR(255) NOT NULL,
        status VARCHAR(50),
        configured_status VARCHAR(50),
        effective_status VARCHAR(50),
        daily_budget DECIMAL(10,2),
        lifetime_budget DECIMAL(10,2),
        budget_remaining DECIMAL(10,2),
        bid_amount DECIMAL(10,4),
        optimization_goal VARCHAR(100),
        billing_event VARCHAR(100),
        targeting_json JSON,
        start_time TIMESTAMP NULL,
        end_time TIMESTAMP NULL,
        created_time TIMESTAMP NULL,
        updated_time TIMESTAMP NULL,
        issues_info_json JSON,
        last_sync_at TIMESTAMP NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        INDEX idx_campaign_id (campaign_id),
        INDEX idx_account_id (account_id),
        INDEX idx_status (status),
        INDEX idx_last_sync (last_sync_at),
        FOREIGN KEY (campaign_id) REFERENCES campaigns(id) ON DELETE CASCADE,
        FOREIGN KEY (account_id) REFERENCES ad_accounts(id) ON DELETE CASCADE
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`,

      // Create ads table
      `CREATE TABLE IF NOT EXISTS ads (
        id VARCHAR(255) PRIMARY KEY,
        name VARCHAR(500) NOT NULL,
        adset_id VARCHAR(255) NOT NULL,
        campaign_id VARCHAR(255) NOT NULL,
        account_id VARCHAR(255) NOT NULL,
        status VARCHAR(50),
        configured_status VARCHAR(50),
        effective_status VARCHAR(50),
        creative_json JSON,
        preview_shareable_link TEXT,
        created_time TIMESTAMP NULL,
        updated_time TIMESTAMP NULL,
        issues_info_json JSON,
        last_sync_at TIMESTAMP NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        INDEX idx_adset_id (adset_id),
        INDEX idx_campaign_id (campaign_id),
        INDEX idx_account_id (account_id),
        INDEX idx_status (status),
        INDEX idx_last_sync (last_sync_at),
        FOREIGN KEY (adset_id) REFERENCES adsets(id) ON DELETE CASCADE,
        FOREIGN KEY (campaign_id) REFERENCES campaigns(id) ON DELETE CASCADE,
        FOREIGN KEY (account_id) REFERENCES ad_accounts(id) ON DELETE CASCADE
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`,

      // Create system_tokens table for System User token management
      `CREATE TABLE IF NOT EXISTS system_tokens (
        id INT AUTO_INCREMENT PRIMARY KEY,
        token_type VARCHAR(50) NOT NULL,
        access_token TEXT NOT NULL,
        expires_at TIMESTAMP NULL,
        scope TEXT,
        system_user_id VARCHAR(255),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        INDEX idx_token_type (token_type),
        INDEX idx_expires_at (expires_at)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`,

      // Create rate_limits table for API rate limiting
      `CREATE TABLE IF NOT EXISTS rate_limits (
        id VARCHAR(255) PRIMARY KEY,
        endpoint VARCHAR(255) NOT NULL,
        requests_count INT DEFAULT 1,
        window_start TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        INDEX idx_endpoint_window (endpoint, window_start)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`,

      // Create api_logs table for comprehensive logging
      `CREATE TABLE IF NOT EXISTS api_logs (
        id BIGINT AUTO_INCREMENT PRIMARY KEY,
        endpoint VARCHAR(500) NOT NULL,
        method VARCHAR(10) NOT NULL,
        status_code INT,
        response_time_ms INT,
        request_size_bytes INT,
        response_size_bytes INT,
        error_message TEXT,
        user_id VARCHAR(255),
        ip_address VARCHAR(45),
        user_agent TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        INDEX idx_endpoint (endpoint),
        INDEX idx_status_code (status_code),
        INDEX idx_created_at (created_at),
        INDEX idx_user_id (user_id)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`
    ]

    for (const query of queries) {
      try {
        await pool.execute(query)
        console.log('Schema initialization query executed successfully')
      } catch (error) {
        console.error('Failed to execute schema query:', error)
        throw error
      }
    }

    console.log('Database schema initialized successfully')
  }

  // Daily Insights Operations
  async upsertDailyInsights(data: DailyInsightData): Promise<void> {
    const pool = await this.getConnection()
    
    const query = `
      INSERT INTO daily_insights (
        entity_type, entity_id, entity_name, account_id, date_start, date_stop,
        spend, impressions, clicks, reach, frequency, ctr, cpc, cpm, cpp,
        actions_json, action_values_json, conversions_json, conversion_values_json,
        cost_per_action_type_json, video_metrics_json
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON DUPLICATE KEY UPDATE
        entity_name = VALUES(entity_name),
        date_stop = VALUES(date_stop),
        spend = VALUES(spend),
        impressions = VALUES(impressions),
        clicks = VALUES(clicks),
        reach = VALUES(reach),
        frequency = VALUES(frequency),
        ctr = VALUES(ctr),
        cpc = VALUES(cpc),
        cpm = VALUES(cpm),
        cpp = VALUES(cpp),
        actions_json = VALUES(actions_json),
        action_values_json = VALUES(action_values_json),
        conversions_json = VALUES(conversions_json),
        conversion_values_json = VALUES(conversion_values_json),
        cost_per_action_type_json = VALUES(cost_per_action_type_json),
        video_metrics_json = VALUES(video_metrics_json),
        updated_at = CURRENT_TIMESTAMP
    `

    const values = [
      data.entity_type,
      data.entity_id,
      data.entity_name || null,
      data.account_id,
      data.date_start,
      data.date_stop,
      data.spend || 0,
      data.impressions || 0,
      data.clicks || 0,
      data.reach || 0,
      data.frequency || 0,
      data.ctr || 0,
      data.cpc || 0,
      data.cpm || 0,
      data.cpp || 0,
      data.actions_json ? JSON.stringify(data.actions_json) : null,
      data.action_values_json ? JSON.stringify(data.action_values_json) : null,
      data.conversions_json ? JSON.stringify(data.conversions_json) : null,
      data.conversion_values_json ? JSON.stringify(data.conversion_values_json) : null,
      data.cost_per_action_type_json ? JSON.stringify(data.cost_per_action_type_json) : null,
      data.video_metrics_json ? JSON.stringify(data.video_metrics_json) : null,
    ]

    await pool.execute(query, values)
  }

  async getDailyInsights(params: {
    accountId?: string
    entityType?: 'campaign' | 'adset' | 'ad'
    entityId?: string
    dateStart?: string
    dateEnd?: string
    limit?: number
    offset?: number
  }): Promise<DailyInsightData[]> {
    const pool = await this.getConnection()
    
    let whereClause = 'WHERE 1=1'
    const values: any[] = []
    
    if (params.accountId) {
      whereClause += ' AND account_id = ?'
      values.push(params.accountId)
    }
    
    if (params.entityType) {
      whereClause += ' AND entity_type = ?'
      values.push(params.entityType)
    }
    
    if (params.entityId) {
      whereClause += ' AND entity_id = ?'
      values.push(params.entityId)
    }
    
    if (params.dateStart) {
      whereClause += ' AND date_start >= ?'
      values.push(params.dateStart)
    }
    
    if (params.dateEnd) {
      whereClause += ' AND date_start <= ?'
      values.push(params.dateEnd)
    }

    const query = `
      SELECT * FROM daily_insights 
      ${whereClause}
      ORDER BY date_start DESC, spend DESC
      LIMIT ${params.limit || 1000}
      OFFSET ${params.offset || 0}
    `

    const [rows] = await pool.execute(query, values)
    return rows as DailyInsightData[]
  }

  // Ad Account Operations
  async upsertAdAccount(data: AdAccountData): Promise<void> {
    const pool = await this.getConnection()
    
    const query = `
      INSERT INTO ad_accounts (
        id, name, account_status, currency, timezone_name, business_id, business_name,
        amount_spent, balance, spend_cap, created_time, capabilities_json, last_sync_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())
      ON DUPLICATE KEY UPDATE
        name = VALUES(name),
        account_status = VALUES(account_status),
        currency = VALUES(currency),
        timezone_name = VALUES(timezone_name),
        business_id = VALUES(business_id),
        business_name = VALUES(business_name),
        amount_spent = VALUES(amount_spent),
        balance = VALUES(balance),
        spend_cap = VALUES(spend_cap),
        created_time = VALUES(created_time),
        capabilities_json = VALUES(capabilities_json),
        last_sync_at = NOW(),
        updated_at = CURRENT_TIMESTAMP
    `

    const values = [
      data.id,
      data.name,
      data.account_status || 1,
      data.currency,
      data.timezone_name || null,
      data.business_id || null,
      data.business_name || null,
      data.amount_spent || 0,
      data.balance || 0,
      data.spend_cap || null,
      data.created_time || null,
      data.capabilities_json ? JSON.stringify(data.capabilities_json) : null,
    ]

    await pool.execute(query, values)
  }

  // Rate Limiting
  async checkRateLimit(endpoint: string, limit: number, windowMinutes: number = 60): Promise<boolean> {
    const pool = await this.getConnection()
    const windowStart = new Date(Date.now() - windowMinutes * 60 * 1000)
    const key = createHash('md5').update(`${endpoint}-${Math.floor(Date.now() / (windowMinutes * 60 * 1000))}`).digest('hex')
    
    const [rows] = await pool.execute(
      'SELECT requests_count FROM rate_limits WHERE id = ? AND window_start > ?',
      [key, windowStart]
    )

    if (rows && (rows as any).length > 0) {
      const currentCount = (rows as any)[0].requests_count
      if (currentCount >= limit) {
        return false // Rate limit exceeded
      }
      
      await pool.execute(
        'UPDATE rate_limits SET requests_count = requests_count + 1, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
        [key]
      )
    } else {
      await pool.execute(
        'INSERT INTO rate_limits (id, endpoint, requests_count, window_start) VALUES (?, ?, 1, NOW()) ON DUPLICATE KEY UPDATE requests_count = 1, window_start = NOW()',
        [key, endpoint]
      )
    }
    
    return true // Rate limit not exceeded
  }

  // API Logging
  async logApiCall(data: ApiLogData): Promise<void> {
    const pool = await this.getConnection()
    
    const query = `
      INSERT INTO api_logs (
        endpoint, method, status_code, response_time_ms, request_size_bytes,
        response_size_bytes, error_message, user_id, ip_address, user_agent
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `

    const values = [
      data.endpoint,
      data.method,
      data.status_code || null,
      data.response_time_ms || null,
      data.request_size_bytes || null,
      data.response_size_bytes || null,
      data.error_message || null,
      data.user_id || null,
      data.ip_address || null,
      data.user_agent || null,
    ]

    await pool.execute(query, values)
  }

  async close(): Promise<void> {
    if (this.pool) {
      await this.pool.end()
      this.pool = null
    }
  }
}

// Type Definitions
export interface DailyInsightData {
  entity_type: 'campaign' | 'adset' | 'ad'
  entity_id: string
  entity_name?: string
  account_id: string
  date_start: string
  date_stop: string
  spend?: number
  impressions?: number
  clicks?: number
  reach?: number
  frequency?: number
  ctr?: number
  cpc?: number
  cpm?: number
  cpp?: number
  actions_json?: any[]
  action_values_json?: any[]
  conversions_json?: any[]
  conversion_values_json?: any[]
  cost_per_action_type_json?: any[]
  video_metrics_json?: any
}

export interface AdAccountData {
  id: string
  name: string
  account_status?: number
  currency: string
  timezone_name?: string
  business_id?: string
  business_name?: string
  amount_spent?: number
  balance?: number
  spend_cap?: number
  created_time?: string
  capabilities_json?: string[]
}

export interface ApiLogData {
  endpoint: string
  method: string
  status_code?: number
  response_time_ms?: number
  request_size_bytes?: number
  response_size_bytes?: number
  error_message?: string
  user_id?: string
  ip_address?: string
  user_agent?: string
}

// Singleton instance
export const databaseManager = new DatabaseManager()