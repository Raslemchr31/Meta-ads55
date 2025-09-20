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

    const url = new URL(request.url)
    const accountId = url.searchParams.get('accountId')

    if (!accountId) {
      return NextResponse.json(
        { error: 'Account ID is required' },
        { status: 400 }
      )
    }

    // Get campaigns from cache or Meta API
    const cacheKey = `meta:campaigns:${accountId}:${session.user.id}`

    let campaigns = await metaApiCache.get(cacheKey)

    if (!campaigns) {
      // Mock data for development - replace with actual Meta API call
      const mockCampaigns = [
        {
          id: '987654321',
          name: 'Demo Campaign 1',
          status: 'ACTIVE',
          objective: 'LINK_CLICKS',
          spend: '250.00',
          impressions: '15432',
          clicks: '234',
          ctr: '1.52'
        },
        {
          id: '987654322',
          name: 'Demo Campaign 2',
          status: 'PAUSED',
          objective: 'CONVERSIONS',
          spend: '180.50',
          impressions: '12100',
          clicks: '189',
          ctr: '1.56'
        }
      ]

      // Cache the result
      await metaApiCache.set(cacheKey, mockCampaigns, {
        cacheKey,
        ttl: 1800, // 30 minutes for campaign data
        strategy: 'standard',
        tags: ['meta-api', 'campaigns', `account-${accountId}`]
      })

      campaigns = { data: mockCampaigns }
    }

    return NextResponse.json({
      success: true,
      data: campaigns.data || campaigns,
      cached: !!campaigns.metadata,
      accountId
    })

  } catch (error) {
    logger.error('Safe campaigns API error', {
      error: error instanceof Error ? error.message : 'Unknown error',
      stack: error instanceof Error ? error.stack : undefined
    })

    return NextResponse.json(
      { error: 'Failed to fetch campaigns' },
      { status: 500 }
    )
  }
}