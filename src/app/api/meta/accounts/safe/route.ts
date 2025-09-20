import { NextRequest, NextResponse } from 'next/server'
import { getServerSession } from 'next-auth'
import { authOptions } from '@/lib/auth'
import { metaApiCache } from '@/lib/cache/meta-api-cache'
import { logger } from '@/lib/logger'

export async function GET(request: NextRequest) {
  try {
    const session = await getServerSession(authOptions)

    if (!session?.user?.id) {
      return NextResponse.json(
        { error: 'Authentication required' },
        { status: 401 }
      )
    }

    // Get ad accounts from cache or Meta API
    const cacheKey = `meta:ad_accounts:${session.user.id}`

    let adAccounts = await metaApiCache.get(cacheKey)

    if (!adAccounts) {
      // Mock data for development - replace with actual Meta API call
      const mockAdAccounts = [
        {
          id: '123456789',
          name: 'Demo Ad Account',
          account_status: 1,
          currency: 'USD',
          timezone_name: 'America/Los_Angeles',
          spend_cap: '1000000'
        }
      ]

      // Cache the result
      await metaApiCache.set(cacheKey, mockAdAccounts, {
        cacheKey,
        ttl: 3600,
        strategy: 'standard',
        tags: ['meta-api', 'ad-accounts']
      })

      adAccounts = {
        data: mockAdAccounts,
        metadata: {
          cachedAt: new Date().toISOString(),
          expiresAt: new Date(Date.now() + 3600000).toISOString(),
          strategy: 'standard' as const,
          tags: ['meta-api', 'ad-accounts'],
          dependencies: [],
          hitCount: 0,
          lastAccessed: new Date().toISOString(),
          priority: 1,
          size: JSON.stringify(mockAdAccounts).length,
          compressed: false
        }
      }
    }

    return NextResponse.json({
      success: true,
      data: adAccounts.data || adAccounts,
      cached: !!adAccounts.metadata
    })

  } catch (error) {
    logger.error('Safe ad accounts API error', {
      error: error instanceof Error ? error.message : 'Unknown error',
      stack: error instanceof Error ? error.stack : undefined
    })

    return NextResponse.json(
      { error: 'Failed to fetch ad accounts' },
      { status: 500 }
    )
  }
}