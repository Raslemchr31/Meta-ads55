import { NextRequest, NextResponse } from 'next/server'
import { getServerSession } from 'next-auth/next'
import { authOptions } from '@/lib/auth'

export async function POST(request: NextRequest) {
  try {
    const session = await getServerSession(authOptions)
    if (!session?.user) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
    }

    const body = await request.json()
    const { objective, campaignName, audience, budget, schedule } = body

    // Validate required fields
    if (!objective || !campaignName) {
      return NextResponse.json(
        { error: 'Objective and campaign name are required' },
        { status: 400 }
      )
    }

    // Here you would typically:
    // 1. Create campaign in database
    // 2. Create campaign via Meta Marketing API
    // 3. Return campaign details

    const campaignId = `camp_${Date.now()}`

    const campaign = {
      id: campaignId,
      name: campaignName,
      objective,
      status: 'draft',
      createdAt: new Date().toISOString(),
      userId: session.user.id,
      settings: {
        audience,
        budget,
        schedule
      }
    }

    return NextResponse.json(campaign, { status: 201 })
  } catch (error) {
    console.error('Campaign creation error:', error)
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    )
  }
}

export async function GET(request: NextRequest) {
  try {
    const session = await getServerSession(authOptions)
    if (!session?.user) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
    }

    // Here you would typically:
    // 1. Fetch campaigns from database
    // 2. Fetch campaigns from Meta API
    // 3. Return combined data

    const mockCampaigns = [
      {
        id: 'camp_1',
        name: 'Summer Sale 2024',
        objective: 'conversions',
        status: 'active',
        performance: {
          impressions: 45200,
          clicks: 1823,
          conversions: 127,
          spend: 1250,
          roas: 4.2
        },
        createdAt: '2024-01-15T00:00:00.000Z'
      },
      {
        id: 'camp_2',
        name: 'Brand Awareness Q1',
        objective: 'brand_awareness',
        status: 'active',
        performance: {
          impressions: 67800,
          clicks: 1245,
          conversions: 89,
          spend: 980,
          roas: 3.1
        },
        createdAt: '2024-01-10T00:00:00.000Z'
      }
    ]

    return NextResponse.json(mockCampaigns)
  } catch (error) {
    console.error('Campaigns fetch error:', error)
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    )
  }
}