import { NextRequest, NextResponse } from 'next/server'
import { getServerSession } from 'next-auth/next'
import { authOptions } from '@/lib/auth'

export async function POST(request: NextRequest) {
  try {
    const session = await getServerSession(authOptions)
    if (!session?.user) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
    }

    const formData = await request.formData()
    const file = formData.get('file') as File | null
    const title = formData.get('title') as string
    const type = formData.get('type') as string
    const tags = formData.get('tags') as string

    if (!title || !type) {
      return NextResponse.json(
        { error: 'Title and type are required' },
        { status: 400 }
      )
    }

    const creativeId = `creative_${Date.now()}`

    // Here you would typically:
    // 1. Upload file to storage (S3, Cloudinary, etc.)
    // 2. Save creative metadata to database
    // 3. Process image/video if needed

    const creative = {
      id: creativeId,
      title,
      type,
      format: file ? file.type.split('/')[1].toUpperCase() : 'TEXT',
      dimensions: type === 'image' ? '1200x628' : type === 'video' ? '1920x1080' : 'N/A',
      fileSize: file ? `${(file.size / 1024).toFixed(1)} KB` : '2 KB',
      status: 'draft',
      performance: {
        score: 0,
        impressions: 0,
        clicks: 0,
        ctr: 0,
        cpc: 0,
        conversions: 0,
        roas: 0
      },
      thumbnail: file ? URL.createObjectURL(file) : '',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      tags: tags ? tags.split(',').map(tag => tag.trim()) : [],
      aiGenerated: false
    }

    return NextResponse.json(creative, { status: 201 })
  } catch (error) {
    console.error('Creative upload error:', error)
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

    // Mock creatives data
    const mockCreatives = [
      {
        id: '1',
        title: 'Summer Sale Hero Banner',
        type: 'image',
        format: 'JPG',
        dimensions: '1200x628',
        fileSize: '245 KB',
        status: 'active',
        performance: {
          score: 92,
          impressions: 45200,
          clicks: 1823,
          ctr: 4.03,
          cpc: 0.68,
          conversions: 127,
          roas: 4.2
        },
        thumbnail: 'https://images.unsplash.com/photo-1607083206325-cad6b0710adb?w=400&h=300&fit=crop',
        createdAt: '2024-01-15T00:00:00.000Z',
        updatedAt: '2024-01-20T00:00:00.000Z',
        tags: ['summer', 'sale', 'banner', 'hero'],
        campaign: 'Summer Sale 2024',
        aiGenerated: false
      },
      {
        id: '2',
        title: 'Product Demo Video',
        type: 'video',
        format: 'MP4',
        dimensions: '1920x1080',
        fileSize: '12.3 MB',
        status: 'active',
        performance: {
          score: 88,
          impressions: 23400,
          clicks: 891,
          ctr: 3.81,
          cpc: 0.72,
          conversions: 156,
          roas: 5.8
        },
        thumbnail: 'https://images.unsplash.com/photo-1586717791821-3f44a563fa4c?w=400&h=300&fit=crop',
        createdAt: '2024-01-18T00:00:00.000Z',
        updatedAt: '2024-01-22T00:00:00.000Z',
        tags: ['product', 'demo', 'video', 'tutorial'],
        campaign: 'Product Launch',
        aiGenerated: true
      }
    ]

    return NextResponse.json(mockCreatives)
  } catch (error) {
    console.error('Creatives fetch error:', error)
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    )
  }
}