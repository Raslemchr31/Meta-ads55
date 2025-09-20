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
    const { title, description, priority, assigneeId, dueDate, labels } = body

    // Validate required fields
    if (!title) {
      return NextResponse.json(
        { error: 'Title is required' },
        { status: 400 }
      )
    }

    const taskId = `task_${Date.now()}`

    const task = {
      id: taskId,
      title,
      description: description || '',
      priority: priority || 'medium',
      status: 'todo',
      assignee: {
        id: assigneeId || session.user.id,
        name: session.user.name || 'Unknown User',
        avatar: session.user.image || '',
        initials: (session.user.name || 'U').split(' ').map(n => n[0]).join('')
      },
      labels: labels || [],
      dueDate: dueDate || new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString().split('T')[0], // 7 days from now
      comments: 0,
      attachments: 0,
      createdAt: new Date().toISOString()
    }

    return NextResponse.json(task, { status: 201 })
  } catch (error) {
    console.error('Task creation error:', error)
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

    // Mock tasks data - in real app, fetch from database
    const mockTasks = [
      {
        id: 'task_1',
        title: 'Design new ad creatives',
        description: 'Create new visual assets for summer sale campaign',
        priority: 'high',
        status: 'todo',
        assignee: {
          id: '1',
          name: 'Sarah Chen',
          avatar: 'https://images.unsplash.com/photo-1494790108755-2616b89c8bce?w=150&h=150&fit=crop&crop=face',
          initials: 'SC'
        },
        labels: ['Design'],
        dueDate: '2024-01-25',
        comments: 0,
        attachments: 0,
        createdAt: '2024-01-20T00:00:00.000Z'
      },
      {
        id: 'task_2',
        title: 'Write copy for social media posts',
        description: 'Create engaging copy for all social media platforms',
        priority: 'medium',
        status: 'in_progress',
        assignee: {
          id: '2',
          name: 'Mike Johnson',
          avatar: 'https://images.unsplash.com/photo-1472099645785-5658abf4ff4e?w=150&h=150&fit=crop&crop=face',
          initials: 'MJ'
        },
        labels: ['Copywriting'],
        dueDate: '2024-01-30',
        comments: 2,
        attachments: 1,
        createdAt: '2024-01-18T00:00:00.000Z'
      }
    ]

    return NextResponse.json(mockTasks)
  } catch (error) {
    console.error('Tasks fetch error:', error)
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    )
  }
}

export async function PATCH(request: NextRequest) {
  try {
    const session = await getServerSession(authOptions)
    if (!session?.user) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
    }

    const body = await request.json()
    const { taskId, status, ...updates } = body

    if (!taskId) {
      return NextResponse.json(
        { error: 'Task ID is required' },
        { status: 400 }
      )
    }

    // Here you would typically update the task in the database
    const updatedTask = {
      id: taskId,
      ...updates,
      status: status || updates.status,
      updatedAt: new Date().toISOString()
    }

    return NextResponse.json(updatedTask)
  } catch (error) {
    console.error('Task update error:', error)
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    )
  }
}