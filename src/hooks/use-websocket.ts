import { useEffect, useRef, useState } from 'react'
import { io, Socket } from 'socket.io-client'
import { ServerToClientEvents, ClientToServerEvents } from '@/lib/websocket'

type SocketInstance = Socket<ServerToClientEvents, ClientToServerEvents>

interface WebSocketHook {
  socket: SocketInstance | null
  isConnected: boolean
  emit: (event: keyof ClientToServerEvents, data?: any) => void
}

export const useWebSocket = (workspaceId: string = 'default'): WebSocketHook => {
  const [isConnected, setIsConnected] = useState(false)
  const socketRef = useRef<SocketInstance | null>(null)

  useEffect(() => {
    // Initialize socket connection
    socketRef.current = io(process.env.NEXT_PUBLIC_WS_URL || window.location.origin, {
      transports: ['websocket', 'polling']
    })

    const socket = socketRef.current

    socket.on('connect', () => {
      setIsConnected(true)
      socket.emit('join-workspace', workspaceId)
    })

    socket.on('disconnect', () => {
      setIsConnected(false)
    })

    // Cleanup on unmount
    return () => {
      if (socket) {
        socket.emit('leave-workspace', workspaceId)
        socket.disconnect()
      }
    }
  }, [workspaceId])

  const emit = (event: keyof ClientToServerEvents, data?: any) => {
    if (socketRef.current?.connected) {
      socketRef.current.emit(event, data)
    }
  }

  return {
    socket: socketRef.current,
    isConnected,
    emit
  }
}

export const useMetricsUpdates = (onUpdate: (data: any) => void) => {
  const { socket } = useWebSocket()

  useEffect(() => {
    if (!socket) return

    socket.on('metrics-update', onUpdate)

    return () => {
      socket.off('metrics-update', onUpdate)
    }
  }, [socket, onUpdate])
}

export const useTaskUpdates = (onUpdate: (data: any) => void) => {
  const { socket } = useWebSocket()

  useEffect(() => {
    if (!socket) return

    socket.on('task-update', onUpdate)

    return () => {
      socket.off('task-update', onUpdate)
    }
  }, [socket, onUpdate])
}

export const useCreativeUpdates = (onUpdate: (data: any) => void) => {
  const { socket } = useWebSocket()

  useEffect(() => {
    if (!socket) return

    socket.on('creative-performance', onUpdate)

    return () => {
      socket.off('creative-performance', onUpdate)
    }
  }, [socket, onUpdate])
}

export const useAIInsights = (onInsight: (data: any) => void) => {
  const { socket } = useWebSocket()

  useEffect(() => {
    if (!socket) return

    socket.on('ai-insight', onInsight)

    return () => {
      socket.off('ai-insight', onInsight)
    }
  }, [socket, onInsight])
}