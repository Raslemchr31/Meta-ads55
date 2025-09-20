import { Server as SocketIOServer } from 'socket.io'
import { createAdapter } from '@socket.io/redis-adapter'
import { redisManager, RedisDatabase } from '@/lib/redis-manager'
import { sessionManager } from '@/lib/auth/session-manager'
import { auditLogger } from '@/lib/auth/audit-logger'
import { logger } from '@/lib/logger'
import { NextApiRequest } from 'next'

export interface WebSocketUser {
  userId: string
  socketId: string
  sessionId: string
  rooms: string[]
  metadata: {
    userAgent: string
    ipAddress: string
    connectedAt: string
    lastActivity: string
    permissions: string[]
  }
}

export interface NotificationPayload {
  type: string
  title: string
  message: string
  priority: 'low' | 'medium' | 'high' | 'critical'
  data?: any
  targetUsers?: string[]
  targetRooms?: string[]
  expiresAt?: string
}

export interface RealTimeUpdate {
  type: 'campaign_update' | 'bid_change' | 'performance_alert' | 'system_notification' | 'collaboration_event'
  entityId: string
  entityType: 'campaign' | 'adset' | 'ad' | 'account' | 'user'
  data: any
  userId?: string
  timestamp: string
  metadata?: any
}

export interface PresenceInfo {
  userId: string
  status: 'online' | 'away' | 'offline'
  lastSeen: string
  currentPage?: string
  activeEntity?: string
  collaborators?: string[]
}

export class WebSocketManager {
  private io: SocketIOServer | null = null
  private connectedUsers: Map<string, WebSocketUser> = new Map()
  private userSockets: Map<string, Set<string>> = new Map() // userId -> Set of socketIds
  private socketUsers: Map<string, string> = new Map() // socketId -> userId

  async initialize(server: any): Promise<void> {
    try {
      // Create Socket.IO server
      this.io = new SocketIOServer(server, {
        cors: {
          origin: process.env.ALLOWED_ORIGINS?.split(',') || ['http://localhost:3000'],
          methods: ['GET', 'POST'],
          credentials: true
        },
        transports: ['websocket', 'polling']
      })

      // Set up Redis adapter for horizontal scaling
      const pubClient = redisManager.getConnection(RedisDatabase.REALTIME)
      const subClient = redisManager.getConnection(RedisDatabase.REALTIME)

      this.io.adapter(createAdapter(pubClient, subClient))

      // Set up middleware
      this.setupAuthentication()
      this.setupEventHandlers()

      // Set up Redis pub/sub for external updates
      await this.setupRedisSubscriptions()

      logger.info('WebSocket manager initialized successfully')

    } catch (error) {
      logger.error('Failed to initialize WebSocket manager', {
        error: error instanceof Error ? error.message : 'Unknown error'
      })
      throw error
    }
  }

  private setupAuthentication(): void {
    if (!this.io) return

    this.io.use(async (socket, next) => {
      try {
        const token = socket.handshake.auth.token || socket.handshake.headers.authorization

        if (!token) {
          return next(new Error('Authentication token required'))
        }

        // Validate session
        const sessionId = token.replace('Bearer ', '')
        const sessionData = await sessionManager.getSession(sessionId)

        if (!sessionData) {
          return next(new Error('Invalid or expired session'))
        }

        // Attach user info to socket
        socket.userId = sessionData.userId
        socket.sessionId = sessionId
        socket.userData = sessionData

        // Log connection attempt
        await auditLogger.logEvent({
          eventType: 'api_access',
          userId: sessionData.userId,
          sessionId,
          ipAddress: socket.handshake.address,
          userAgent: socket.handshake.headers['user-agent'] || '',
          riskLevel: 'low',
          outcome: 'success',
          source: 'websocket',
          details: {
            action: 'socket_authentication',
            socketId: socket.id
          }
        })

        next()

      } catch (error) {
        logger.warn('WebSocket authentication failed', {
          socketId: socket.id,
          error: error instanceof Error ? error.message : 'Unknown error'
        })
        next(new Error('Authentication failed'))
      }
    })
  }

  private setupEventHandlers(): void {
    if (!this.io) return

    this.io.on('connection', async (socket) => {
      try {
        const userId = socket.userId
        const sessionId = socket.sessionId

        // Register user connection
        await this.registerUserConnection(socket)

        logger.info('User connected via WebSocket', {
          userId,
          socketId: socket.id,
          sessionId
        })

        // Join user to personal room
        socket.join(`user:${userId}`)

        // Handle disconnection
        socket.on('disconnect', async () => {
          await this.handleUserDisconnection(socket)
        })

        // Handle room joining
        socket.on('join_room', async (data) => {
          await this.handleJoinRoom(socket, data)
        })

        // Handle room leaving
        socket.on('leave_room', async (data) => {
          await this.handleLeaveRoom(socket, data)
        })

        // Handle presence updates
        socket.on('presence_update', async (data) => {
          await this.handlePresenceUpdate(socket, data)
        })

        // Handle collaboration events
        socket.on('collaboration_event', async (data) => {
          await this.handleCollaborationEvent(socket, data)
        })

        // Handle ping for connection health
        socket.on('ping', () => {
          socket.emit('pong', { timestamp: Date.now() })
        })

        // Send initial presence and notifications
        await this.sendInitialData(socket)

      } catch (error) {
        logger.error('Error handling WebSocket connection', {
          socketId: socket.id,
          error: error instanceof Error ? error.message : 'Unknown error'
        })
        socket.disconnect()
      }
    })
  }

  private async setupRedisSubscriptions(): Promise<void> {
    try {
      const subClient = redisManager.getConnection(RedisDatabase.REALTIME)

      // Subscribe to various channels
      await subClient.subscribe(
        'notifications:broadcast',
        'notifications:targeted',
        'campaign:updates',
        'bid:updates',
        'performance:alerts',
        'system:notifications',
        'collaboration:events'
      )

      subClient.on('message', async (channel, message) => {
        try {
          const data = JSON.parse(message)
          await this.handleRedisMessage(channel, data)
        } catch (error) {
          logger.error('Error processing Redis message', {
            channel,
            error: error instanceof Error ? error.message : 'Unknown error'
          })
        }
      })

      logger.info('Redis subscriptions set up successfully')

    } catch (error) {
      logger.error('Failed to set up Redis subscriptions', {
        error: error instanceof Error ? error.message : 'Unknown error'
      })
    }
  }

  private async registerUserConnection(socket: any): Promise<void> {
    const userId = socket.userId
    const socketId = socket.id

    // Create user connection record
    const userConnection: WebSocketUser = {
      userId,
      socketId,
      sessionId: socket.sessionId,
      rooms: [`user:${userId}`],
      metadata: {
        userAgent: socket.handshake.headers['user-agent'] || '',
        ipAddress: socket.handshake.address,
        connectedAt: new Date().toISOString(),
        lastActivity: new Date().toISOString(),
        permissions: socket.userData?.permissions || []
      }
    }

    // Store connection info
    this.connectedUsers.set(socketId, userConnection)
    this.socketUsers.set(socketId, userId)

    // Add to user's socket set
    if (!this.userSockets.has(userId)) {
      this.userSockets.set(userId, new Set())
    }
    this.userSockets.get(userId)!.add(socketId)

    // Store in Redis for cross-server communication
    const client = redisManager.getConnection(RedisDatabase.REALTIME)
    await client.hset(
      'websocket:connections',
      socketId,
      JSON.stringify(userConnection)
    )

    // Update user presence
    await this.updateUserPresence(userId, 'online', {
      currentPage: socket.handshake.headers.referer
    })
  }

  private async handleUserDisconnection(socket: any): Promise<void> {
    const userId = socket.userId
    const socketId = socket.id

    logger.info('User disconnected from WebSocket', { userId, socketId })

    // Remove from local maps
    this.connectedUsers.delete(socketId)
    this.socketUsers.delete(socketId)

    // Remove from user's socket set
    const userSockets = this.userSockets.get(userId)
    if (userSockets) {
      userSockets.delete(socketId)
      if (userSockets.size === 0) {
        this.userSockets.delete(userId)
        // User completely disconnected
        await this.updateUserPresence(userId, 'offline')
      }
    }

    // Remove from Redis
    const client = redisManager.getConnection(RedisDatabase.REALTIME)
    await client.hdel('websocket:connections', socketId)

    // Log disconnection
    await auditLogger.logEvent({
      eventType: 'api_access',
      userId,
      sessionId: socket.sessionId,
      ipAddress: socket.handshake.address,
      userAgent: socket.handshake.headers['user-agent'] || '',
      riskLevel: 'low',
      outcome: 'success',
      source: 'websocket',
      details: {
        action: 'socket_disconnection',
        socketId
      }
    })
  }

  private async handleJoinRoom(socket: any, data: { room: string; entityType?: string }): Promise<void> {
    const { room, entityType } = data
    const userId = socket.userId

    // Validate room access permissions
    const hasAccess = await this.validateRoomAccess(userId, room, entityType)

    if (!hasAccess) {
      socket.emit('error', { message: 'Access denied to room', room })
      return
    }

    // Join the room
    socket.join(room)

    // Update user connection record
    const userConnection = this.connectedUsers.get(socket.id)
    if (userConnection) {
      userConnection.rooms.push(room)
    }

    // Notify others in the room
    socket.to(room).emit('user_joined_room', {
      userId,
      room,
      timestamp: new Date().toISOString()
    })

    logger.debug('User joined room', { userId, room, socketId: socket.id })
  }

  private async handleLeaveRoom(socket: any, data: { room: string }): Promise<void> {
    const { room } = data
    const userId = socket.userId

    socket.leave(room)

    // Update user connection record
    const userConnection = this.connectedUsers.get(socket.id)
    if (userConnection) {
      userConnection.rooms = userConnection.rooms.filter(r => r !== room)
    }

    // Notify others in the room
    socket.to(room).emit('user_left_room', {
      userId,
      room,
      timestamp: new Date().toISOString()
    })

    logger.debug('User left room', { userId, room, socketId: socket.id })
  }

  private async handlePresenceUpdate(socket: any, data: PresenceInfo): Promise<void> {
    const userId = socket.userId

    await this.updateUserPresence(userId, data.status, {
      currentPage: data.currentPage,
      activeEntity: data.activeEntity
    })

    // Broadcast presence update to relevant rooms
    const userConnection = this.connectedUsers.get(socket.id)
    if (userConnection) {
      for (const room of userConnection.rooms) {
        socket.to(room).emit('presence_update', {
          userId,
          status: data.status,
          currentPage: data.currentPage,
          activeEntity: data.activeEntity,
          timestamp: new Date().toISOString()
        })
      }
    }
  }

  private async handleCollaborationEvent(socket: any, data: any): Promise<void> {
    const userId = socket.userId

    // Log collaboration event
    await auditLogger.logEvent({
      eventType: 'data_access',
      userId,
      ipAddress: socket.handshake.address,
      userAgent: socket.handshake.headers['user-agent'] || '',
      riskLevel: 'low',
      outcome: 'success',
      source: 'websocket',
      details: {
        action: 'collaboration_event',
        eventType: data.type,
        entityId: data.entityId
      }
    })

    // Broadcast to relevant room
    if (data.room) {
      socket.to(data.room).emit('collaboration_event', {
        ...data,
        userId,
        timestamp: new Date().toISOString()
      })
    }
  }

  private async handleRedisMessage(channel: string, data: any): Promise<void> {
    if (!this.io) return

    switch (channel) {
      case 'notifications:broadcast':
        this.io.emit('notification', data)
        break

      case 'notifications:targeted':
        if (data.targetUsers) {
          for (const userId of data.targetUsers) {
            this.io.to(`user:${userId}`).emit('notification', data)
          }
        }
        if (data.targetRooms) {
          for (const room of data.targetRooms) {
            this.io.to(room).emit('notification', data)
          }
        }
        break

      case 'campaign:updates':
        this.io.to(`campaign:${data.campaignId}`).emit('campaign_update', data)
        break

      case 'bid:updates':
        this.io.to(`adset:${data.adSetId}`).emit('bid_update', data)
        break

      case 'performance:alerts':
        this.io.to(`account:${data.adAccountId}`).emit('performance_alert', data)
        break

      case 'system:notifications':
        this.io.emit('system_notification', data)
        break

      case 'collaboration:events':
        if (data.room) {
          this.io.to(data.room).emit('collaboration_event', data)
        }
        break
    }
  }

  private async sendInitialData(socket: any): Promise<void> {
    const userId = socket.userId

    try {
      // Send current presence info
      const presence = await this.getUserPresence(userId)
      socket.emit('presence_info', presence)

      // Send pending notifications
      const notifications = await this.getPendingNotifications(userId)
      if (notifications.length > 0) {
        socket.emit('pending_notifications', notifications)
      }

      // Send active collaborators for user's entities
      const collaborators = await this.getActiveCollaborators(userId)
      socket.emit('active_collaborators', collaborators)

    } catch (error) {
      logger.error('Failed to send initial data', {
        userId,
        socketId: socket.id,
        error: error instanceof Error ? error.message : 'Unknown error'
      })
    }
  }

  private async validateRoomAccess(userId: string, room: string, entityType?: string): Promise<boolean> {
    // Basic room access validation - enhance based on your authorization model
    try {
      // Personal rooms are always accessible
      if (room === `user:${userId}`) {
        return true
      }

      // Public rooms (could be enhanced with more sophisticated logic)
      const publicRooms = ['general', 'announcements']
      if (publicRooms.includes(room)) {
        return true
      }

      // Entity-specific rooms require ownership/permission check
      if (room.startsWith('campaign:') || room.startsWith('account:')) {
        // In a real implementation, check user permissions for the specific entity
        return true // Simplified for now
      }

      return false

    } catch (error) {
      logger.error('Room access validation error', {
        userId,
        room,
        error: error instanceof Error ? error.message : 'Unknown error'
      })
      return false
    }
  }

  private async updateUserPresence(userId: string, status: string, metadata?: any): Promise<void> {
    try {
      const client = redisManager.getConnection(RedisDatabase.REALTIME)

      const presenceData = {
        userId,
        status,
        lastSeen: new Date().toISOString(),
        ...metadata
      }

      await client.hset(
        'user:presence',
        userId,
        JSON.stringify(presenceData)
      )

      await client.expire('user:presence', 24 * 60 * 60) // 24 hours

    } catch (error) {
      logger.error('Failed to update user presence', {
        userId,
        status,
        error: error instanceof Error ? error.message : 'Unknown error'
      })
    }
  }

  private async getUserPresence(userId: string): Promise<PresenceInfo | null> {
    try {
      const client = redisManager.getConnection(RedisDatabase.REALTIME)
      const presenceData = await client.hget('user:presence', userId)

      return presenceData ? JSON.parse(presenceData) : null

    } catch (error) {
      logger.error('Failed to get user presence', {
        userId,
        error: error instanceof Error ? error.message : 'Unknown error'
      })
      return null
    }
  }

  private async getPendingNotifications(userId: string): Promise<NotificationPayload[]> {
    try {
      const client = redisManager.getConnection(RedisDatabase.REALTIME)

      // Get notifications from the last 24 hours
      const notifications = await client.lrange(`notifications:${userId}`, 0, 50)

      return notifications.map(notification => JSON.parse(notification))

    } catch (error) {
      logger.error('Failed to get pending notifications', {
        userId,
        error: error instanceof Error ? error.message : 'Unknown error'
      })
      return []
    }
  }

  private async getActiveCollaborators(userId: string): Promise<any[]> {
    try {
      const client = redisManager.getConnection(RedisDatabase.REALTIME)

      // Get all users currently online
      const onlineUsers = await client.hgetall('user:presence')

      const collaborators = []
      for (const [otherUserId, presenceData] of Object.entries(onlineUsers)) {
        if (otherUserId !== userId) {
          const presence = JSON.parse(presenceData)
          if (presence.status === 'online') {
            collaborators.push({
              userId: otherUserId,
              presence
            })
          }
        }
      }

      return collaborators

    } catch (error) {
      logger.error('Failed to get active collaborators', {
        userId,
        error: error instanceof Error ? error.message : 'Unknown error'
      })
      return []
    }
  }

  // Public methods for external use
  async sendNotification(notification: NotificationPayload): Promise<void> {
    if (!this.io) return

    try {
      const client = redisManager.getConnection(RedisDatabase.REALTIME)

      if (notification.targetUsers) {
        // Send targeted notification
        await client.publish('notifications:targeted', JSON.stringify(notification))
      } else {
        // Send broadcast notification
        await client.publish('notifications:broadcast', JSON.stringify(notification))
      }

      // Store notification for offline users
      if (notification.targetUsers) {
        for (const userId of notification.targetUsers) {
          await client.lpush(`notifications:${userId}`, JSON.stringify(notification))
          await client.ltrim(`notifications:${userId}`, 0, 99) // Keep last 100
          await client.expire(`notifications:${userId}`, 7 * 24 * 60 * 60) // 7 days
        }
      }

    } catch (error) {
      logger.error('Failed to send notification', {
        notification,
        error: error instanceof Error ? error.message : 'Unknown error'
      })
    }
  }

  async sendRealTimeUpdate(update: RealTimeUpdate): Promise<void> {
    if (!this.io) return

    try {
      const client = redisManager.getConnection(RedisDatabase.REALTIME)

      // Determine the appropriate channel
      let channel = 'general:updates'

      switch (update.entityType) {
        case 'campaign':
          channel = 'campaign:updates'
          break
        case 'adset':
          channel = 'bid:updates'
          break
        case 'account':
          channel = 'performance:alerts'
          break
      }

      await client.publish(channel, JSON.stringify(update))

    } catch (error) {
      logger.error('Failed to send real-time update', {
        update,
        error: error instanceof Error ? error.message : 'Unknown error'
      })
    }
  }

  getConnectedUsers(): WebSocketUser[] {
    return Array.from(this.connectedUsers.values())
  }

  getConnectionStats(): any {
    return {
      totalConnections: this.connectedUsers.size,
      uniqueUsers: this.userSockets.size,
      averageConnectionsPerUser: this.userSockets.size > 0
        ? Math.round((this.connectedUsers.size / this.userSockets.size) * 100) / 100
        : 0
    }
  }
}

export const webSocketManager = new WebSocketManager()