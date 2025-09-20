import { Server } from 'socket.io'
import { NextApiRequest } from 'next'
import { Server as HTTPServer } from 'http'

export interface ServerToClientEvents {
  'metrics-update': (data: {
    impressions: number
    reach: number
    clicks: number
    conversions: number
    spend: number
    roas: number
  }) => void
  'campaign-update': (data: {
    id: string
    status: string
    performance: any
  }) => void
  'task-update': (data: {
    id: string
    status: string
    assignee?: any
  }) => void
  'creative-performance': (data: {
    id: string
    score: number
    performance: any
  }) => void
  'ai-insight': (data: {
    type: 'optimization' | 'alert' | 'recommendation'
    message: string
    data?: any
  }) => void
}

export interface ClientToServerEvents {
  'join-workspace': (workspaceId: string) => void
  'leave-workspace': (workspaceId: string) => void
  'task-drag': (data: { taskId: string; columnId: string }) => void
  'creative-like': (creativeId: string) => void
}

let io: Server<ClientToServerEvents, ServerToClientEvents>

export const initializeWebSocket = (server: HTTPServer) => {
  if (!io) {
    io = new Server<ClientToServerEvents, ServerToClientEvents>(server, {
      cors: {
        origin: process.env.NEXTAUTH_URL || 'http://localhost:3000',
        methods: ['GET', 'POST']
      }
    })

    io.on('connection', (socket) => {
      console.log('Client connected:', socket.id)

      socket.on('join-workspace', (workspaceId) => {
        socket.join(`workspace-${workspaceId}`)
        console.log(`Client ${socket.id} joined workspace ${workspaceId}`)
      })

      socket.on('leave-workspace', (workspaceId) => {
        socket.leave(`workspace-${workspaceId}`)
        console.log(`Client ${socket.id} left workspace ${workspaceId}`)
      })

      socket.on('task-drag', (data) => {
        socket.to(`workspace-default`).emit('task-update', {
          id: data.taskId,
          status: data.columnId
        })
      })

      socket.on('creative-like', (creativeId) => {
        socket.to(`workspace-default`).emit('creative-performance', {
          id: creativeId,
          score: Math.floor(Math.random() * 20) + 80,
          performance: {
            impressions: Math.floor(Math.random() * 10000) + 40000,
            clicks: Math.floor(Math.random() * 500) + 1500
          }
        })
      })

      socket.on('disconnect', () => {
        console.log('Client disconnected:', socket.id)
      })
    })

    // Simulate live metrics updates
    setInterval(() => {
      const metricsUpdate = {
        impressions: Math.floor(Math.random() * 1000) + 45000,
        reach: Math.floor(Math.random() * 800) + 38000,
        clicks: Math.floor(Math.random() * 100) + 1800,
        conversions: Math.floor(Math.random() * 10) + 125,
        spend: Math.floor(Math.random() * 50) + 1200,
        roas: Math.random() * 2 + 3.5
      }

      io.to('workspace-default').emit('metrics-update', metricsUpdate)
    }, 5000)

    // Simulate AI insights
    const aiInsights = [
      { type: 'optimization' as const, message: 'Campaign "Summer Sale" showing 15% improvement in CTR' },
      { type: 'alert' as const, message: 'Ad set "Mobile Audience" budget 80% depleted' },
      { type: 'recommendation' as const, message: 'Consider increasing bid for "Brand Keywords" by 12%' },
      { type: 'optimization' as const, message: 'Creative A performing 23% better than Creative B' }
    ]

    setInterval(() => {
      const randomInsight = aiInsights[Math.floor(Math.random() * aiInsights.length)]
      io.to('workspace-default').emit('ai-insight', randomInsight)
    }, 15000)
  }

  return io
}

export const getIO = () => {
  if (!io) {
    throw new Error('WebSocket not initialized')
  }
  return io
}