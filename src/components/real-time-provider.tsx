'use client'

import { createContext, useContext, useEffect, useState, ReactNode } from 'react'
import { io, Socket } from 'socket.io-client'
import { ServerToClientEvents, ClientToServerEvents } from '@/lib/websocket'

type SocketInstance = Socket<ServerToClientEvents, ClientToServerEvents>

interface RealTimeContextType {
  socket: SocketInstance | null
  isConnected: boolean
  connectionStatus: 'connecting' | 'connected' | 'disconnected' | 'error'
}

const RealTimeContext = createContext<RealTimeContextType>({
  socket: null,
  isConnected: false,
  connectionStatus: 'disconnected'
})

export const useRealTime = () => {
  const context = useContext(RealTimeContext)
  if (!context) {
    throw new Error('useRealTime must be used within a RealTimeProvider')
  }
  return context
}

interface RealTimeProviderProps {
  children: ReactNode
}

export default function RealTimeProvider({ children }: RealTimeProviderProps) {
  const [socket, setSocket] = useState<SocketInstance | null>(null)
  const [isConnected, setIsConnected] = useState(false)
  const [connectionStatus, setConnectionStatus] = useState<'connecting' | 'connected' | 'disconnected' | 'error'>('disconnected')

  useEffect(() => {
    if (typeof window === 'undefined') return

    console.log('Initializing WebSocket connection...')
    setConnectionStatus('connecting')

    // Initialize socket connection
    const socketInstance = io(window.location.origin, {
      transports: ['websocket', 'polling'],
      timeout: 20000,
      forceNew: true
    })

    socketInstance.on('connect', () => {
      console.log('WebSocket connected:', socketInstance.id)
      setIsConnected(true)
      setConnectionStatus('connected')

      // Join default workspace
      socketInstance.emit('join-workspace', 'default')
    })

    socketInstance.on('disconnect', (reason) => {
      console.log('WebSocket disconnected:', reason)
      setIsConnected(false)
      setConnectionStatus('disconnected')
    })

    socketInstance.on('connect_error', (error) => {
      console.error('WebSocket connection error:', error)
      setConnectionStatus('error')
    })

    socketInstance.on('reconnect', (attemptNumber) => {
      console.log('WebSocket reconnected after', attemptNumber, 'attempts')
      setIsConnected(true)
      setConnectionStatus('connected')
    })

    setSocket(socketInstance)

    // Cleanup on unmount
    return () => {
      console.log('Cleaning up WebSocket connection')
      if (socketInstance) {
        socketInstance.emit('leave-workspace', 'default')
        socketInstance.disconnect()
      }
    }
  }, [])

  const value = {
    socket,
    isConnected,
    connectionStatus
  }

  return (
    <RealTimeContext.Provider value={value}>
      {children}
    </RealTimeContext.Provider>
  )
}