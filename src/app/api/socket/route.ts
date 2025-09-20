import { NextRequest, NextResponse } from 'next/server'
import { Server } from 'socket.io'
import { initializeWebSocket } from '@/lib/websocket'

export async function GET(request: NextRequest) {
  if (!global.io) {
    console.log('Initializing Socket.IO server...')

    // This is a simplified approach for development
    // In production, you'd want to use a separate server or Socket.IO adapter
    try {
      // Mock server object for Socket.IO initialization
      const mockServer = {
        listen: () => {},
        on: () => {},
        address: () => ({ port: 3000 })
      } as any

      global.io = initializeWebSocket(mockServer)
      console.log('Socket.IO server initialized')
    } catch (error) {
      console.error('Failed to initialize Socket.IO:', error)
      return NextResponse.json({ error: 'Failed to initialize WebSocket' }, { status: 500 })
    }
  }

  return NextResponse.json({
    message: 'WebSocket server running',
    status: 'connected',
    clients: global.io?.engine?.clientsCount || 0
  })
}

// Health check endpoint
export async function POST(request: NextRequest) {
  const body = await request.json()

  if (body.action === 'broadcast' && global.io) {
    global.io.emit(body.event, body.data)
    return NextResponse.json({ success: true, message: 'Event broadcasted' })
  }

  return NextResponse.json({ error: 'Invalid action' }, { status: 400 })
}