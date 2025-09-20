import { NextRequest, NextResponse } from 'next/server'
import { webhookValidator } from '@/lib/middleware'
import { metaGraphApiClient } from '@/lib/api-client'
import { databaseManager } from '@/lib/database'
import { cacheManager } from '@/lib/cache'
import { logger } from '@/lib/logger'

interface WebhookEntry {
  id: string
  time: number
  changes: Array<{
    field: string
    value: any
  }>
}

interface WebhookPayload {
  object: string
  entry: WebhookEntry[]
}

// Handle webhook verification challenge
export async function GET(request: NextRequest) {
  const { searchParams } = new URL(request.url)
  const mode = searchParams.get('hub.mode')
  const token = searchParams.get('hub.verify_token')
  const challenge = searchParams.get('hub.challenge')

  logger.info('Webhook verification request received', {
    mode,
    token: token ? 'present' : 'missing',
    challenge: challenge ? 'present' : 'missing',
  })

  const validatedChallenge = webhookValidator.validateChallenge(
    mode || '',
    token || '',
    challenge || ''
  )

  if (validatedChallenge) {
    logger.info('Webhook verification successful')
    return new NextResponse(validatedChallenge, { status: 200 })
  }

  logger.logSecurityEvent('Webhook verification failed', 'high', {
    mode,
    token: token ? 'present' : 'missing',
    challenge: challenge ? 'present' : 'missing',
  })

  return NextResponse.json({ error: 'Verification failed' }, { status: 403 })
}

// Handle webhook notifications
export async function POST(request: NextRequest) {
  const startTime = Date.now()
  const requestId = logger.logApiRequest('/api/webhooks/meta', 'POST')

  try {
    // Get request body and signature
    const body = await request.text()
    const signature = request.headers.get('x-hub-signature-256')

    if (!signature) {
      logger.logSecurityEvent('Webhook missing signature', 'high', {
        bodyLength: body.length,
      })
      return NextResponse.json({ error: 'Missing signature' }, { status: 400 })
    }

    // Validate webhook signature
    if (!webhookValidator.validateSignature(body, signature)) {
      logger.logSecurityEvent('Webhook signature validation failed', 'critical', {
        signature: signature.substring(0, 20) + '...',
        bodyLength: body.length,
      })
      return NextResponse.json({ error: 'Invalid signature' }, { status: 403 })
    }

    // Parse webhook payload
    let payload: WebhookPayload
    try {
      payload = JSON.parse(body)
    } catch (error) {
      logger.error('Failed to parse webhook payload', error, {
        bodyLength: body.length,
        bodyPreview: body.substring(0, 200),
      })
      return NextResponse.json({ error: 'Invalid JSON payload' }, { status: 400 })
    }

    logger.logWebhookReceived(
      payload.object,
      payload.entry?.[0]?.id || 'unknown',
      payload.entry?.[0]?.changes || []
    )

    // Process webhook entries
    for (const entry of payload.entry || []) {
      await processWebhookEntry(entry, payload.object)
    }

    logger.logApiResponse(requestId, '/api/webhooks/meta', 'POST', 200, Date.now() - startTime, {
      entriesProcessed: payload.entry?.length || 0,
      object: payload.object,
    })

    return NextResponse.json({ received: true }, { status: 200 })

  } catch (error) {
    logger.error('Webhook processing failed', error, {
      requestId,
      endpoint: '/api/webhooks/meta',
    })

    logger.logApiResponse(requestId, '/api/webhooks/meta', 'POST', 500, Date.now() - startTime)

    return NextResponse.json(
      { 
        error: 'Webhook processing failed',
        message: error instanceof Error ? error.message : 'Unknown error',
      },
      { status: 500 }
    )
  }
}

async function processWebhookEntry(entry: WebhookEntry, objectType: string): Promise<void> {
  const { id: objectId, time, changes } = entry

  logger.info(`Processing webhook entry: ${objectType}/${objectId}`, {
    objectType,
    objectId,
    changesCount: changes.length,
    timestamp: time,
  })

  for (const change of changes) {
    try {
      await processWebhookChange(objectId, objectType, change, time)
    } catch (error) {
      logger.error(`Failed to process webhook change`, error, {
        objectId,
        objectType,
        field: change.field,
        changeValue: change.value,
      })
      // Continue processing other changes even if one fails
    }
  }
}

async function processWebhookChange(
  objectId: string,
  objectType: string,
  change: { field: string; value: any },
  timestamp: number
): Promise<void> {
  const { field, value } = change

  logger.debug(`Processing webhook change: ${field}`, {
    objectId,
    objectType,
    field,
    hasValue: !!value,
  })

  switch (objectType) {
    case 'ad_account':
      await handleAdAccountChange(objectId, field, value, timestamp)
      break
    
    case 'campaign':
      await handleCampaignChange(objectId, field, value, timestamp)
      break
    
    case 'adset':
      await handleAdSetChange(objectId, field, value, timestamp)
      break
    
    case 'ad':
      await handleAdChange(objectId, field, value, timestamp)
      break
    
    case 'page':
      await handlePageChange(objectId, field, value, timestamp)
      break
    
    default:
      logger.warn(`Unhandled webhook object type: ${objectType}`, {
        objectId,
        objectType,
        field,
      })
  }
}

async function handleAdAccountChange(
  accountId: string,
  field: string,
  value: any,
  timestamp: number
): Promise<void> {
  logger.info(`Ad account change: ${field}`, {
    accountId,
    field,
    timestamp,
  })

  // Invalidate account cache
  await cacheManager.del(`account:${accountId}`)
  await cacheManager.del(`campaigns:${accountId}`)

  switch (field) {
    case 'account_status':
    case 'amount_spent':
    case 'balance':
    case 'spend_cap':
      // Refresh account data from API
      try {
        const accountData = await metaGraphApiClient.get(`/${accountId}`, {
          fields: 'id,name,account_status,currency,timezone_name,business,amount_spent,balance,spend_cap,capabilities',
        })

        await databaseManager.upsertAdAccount({
          id: accountData.id,
          name: accountData.name,
          account_status: accountData.account_status,
          currency: accountData.currency,
          timezone_name: accountData.timezone_name,
          business_id: accountData.business?.id,
          business_name: accountData.business?.name,
          amount_spent: parseFloat(accountData.amount_spent || '0'),
          balance: parseFloat(accountData.balance || '0'),
          spend_cap: accountData.spend_cap ? parseFloat(accountData.spend_cap) : undefined,
          capabilities_json: accountData.capabilities,
        })

        logger.logDataSync('account', accountId, accountId, 1)
      } catch (error) {
        logger.error(`Failed to refresh account data for ${accountId}`, error)
      }
      break

    default:
      logger.debug(`Unhandled ad account field: ${field}`, { accountId, field })
  }
}

async function handleCampaignChange(
  campaignId: string,
  field: string,
  value: any,
  timestamp: number
): Promise<void> {
  logger.info(`Campaign change: ${field}`, {
    campaignId,
    field,
    timestamp,
  })

  // Get account ID from campaign data
  let accountId: string | undefined
  try {
    const campaignData = await metaGraphApiClient.get(`/${campaignId}`, {
      fields: 'account_id',
    })
    accountId = campaignData.account_id
  } catch (error) {
    logger.error(`Failed to get account ID for campaign ${campaignId}`, error)
    return
  }

  // Invalidate related caches
  if (accountId) {
    await cacheManager.del(`campaigns:${accountId}`)
    await cacheManager.del(`insights:${accountId}:campaign`)
  }

  switch (field) {
    case 'status':
    case 'configured_status':
    case 'effective_status':
    case 'daily_budget':
    case 'lifetime_budget':
    case 'budget_remaining':
    case 'bid_strategy':
    case 'optimization_goal':
      // Refresh campaign data from API
      try {
        const campaignData = await metaGraphApiClient.get(`/${campaignId}`, {
          fields: 'id,name,account_id,objective,status,configured_status,effective_status,daily_budget,lifetime_budget,budget_remaining,bid_strategy,optimization_goal,spend_cap,start_time,stop_time,created_time,updated_time,issues_info',
        })

        if (accountId) {
          const pool = await databaseManager.getConnection()
          const query = `
            UPDATE campaigns SET
              name = ?, objective = ?, status = ?, configured_status = ?, effective_status = ?,
              daily_budget = ?, lifetime_budget = ?, budget_remaining = ?, bid_strategy = ?,
              optimization_goal = ?, spend_cap = ?, start_time = ?, stop_time = ?,
              created_time = ?, updated_time = ?, issues_info_json = ?, last_sync_at = NOW(),
              updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
          `

          const values = [
            campaignData.name,
            campaignData.objective || null,
            campaignData.status,
            campaignData.configured_status || null,
            campaignData.effective_status || null,
            campaignData.daily_budget ? parseFloat(campaignData.daily_budget) : null,
            campaignData.lifetime_budget ? parseFloat(campaignData.lifetime_budget) : null,
            campaignData.budget_remaining ? parseFloat(campaignData.budget_remaining) : null,
            campaignData.bid_strategy || null,
            campaignData.optimization_goal || null,
            campaignData.spend_cap ? parseFloat(campaignData.spend_cap) : null,
            campaignData.start_time || null,
            campaignData.stop_time || null,
            campaignData.created_time || null,
            campaignData.updated_time || null,
            campaignData.issues_info ? JSON.stringify(campaignData.issues_info) : null,
            campaignId,
          ]

          await pool.execute(query, values)
          logger.logDataSync('campaign', campaignId, accountId, 1)
        }
      } catch (error) {
        logger.error(`Failed to refresh campaign data for ${campaignId}`, error)
      }
      break

    default:
      logger.debug(`Unhandled campaign field: ${field}`, { campaignId, field })
  }
}

async function handleAdSetChange(
  adsetId: string,
  field: string,
  value: any,
  timestamp: number
): Promise<void> {
  logger.info(`AdSet change: ${field}`, {
    adsetId,
    field,
    timestamp,
  })

  // Similar implementation for adsets
  // Get account and campaign IDs, invalidate caches, refresh data
  // Implementation would be similar to handleCampaignChange
}

async function handleAdChange(
  adId: string,
  field: string,
  value: any,
  timestamp: number
): Promise<void> {
  logger.info(`Ad change: ${field}`, {
    adId,
    field,
    timestamp,
  })

  // Similar implementation for ads
  // Get account, campaign, and adset IDs, invalidate caches, refresh data
  // Implementation would be similar to handleCampaignChange
}

async function handlePageChange(
  pageId: string,
  field: string,
  value: any,
  timestamp: number
): Promise<void> {
  logger.info(`Page change: ${field}`, {
    pageId,
    field,
    timestamp,
  })

  // Handle page-related changes
  // This would involve updating page data and invalidating related caches
}

// Helper function to get rate limit headers for webhook responses
function getRateLimitHeaders(): HeadersInit {
  return {
    'X-RateLimit-Limit': '1000',
    'X-RateLimit-Remaining': '999',
    'X-RateLimit-Reset': (Date.now() + 3600000).toString(), // 1 hour from now
  }
}