import { NextRequest, NextResponse } from 'next/server'
import { getServerSession } from 'next-auth'
import { authOptions } from '@/lib/auth'
import { sessionManager } from '@/lib/auth/session-manager'
import { securityManager } from '@/lib/auth/security-manager'
import { metaTokenManager } from '@/lib/auth/meta-token-manager'
import { logger } from '@/lib/logger'
import { z } from 'zod'

const sessionActionSchema = z.object({
  action: z.enum(['refresh', 'terminate', 'validate', 'list']),
  sessionId: z.string().optional(),
  deviceInfo: z.object({
    userAgent: z.string(),
    ipAddress: z.string(),
    fingerprint: z.string().optional()
  }).optional()
})

export async function POST(request: NextRequest) {
  try {
    const session = await getServerSession(authOptions)

    if (!session?.user?.id) {
      return NextResponse.json(
        { error: 'Authentication required' },
        { status: 401 }
      )
    }

    const body = await request.json()
    const { action, sessionId, deviceInfo } = sessionActionSchema.parse(body)

    const userId = session.user.id
    const clientIP = request.headers.get('x-forwarded-for') ||
                     request.headers.get('x-real-ip') ||
                     request.ip || '127.0.0.1'

    switch (action) {
      case 'refresh':
        if (!sessionId) {
          return NextResponse.json(
            { error: 'Session ID required for refresh' },
            { status: 400 }
          )
        }

        const sessionData = await sessionManager.getSession(sessionId, true)

        if (!sessionData) {
          logger.warn('Session refresh failed', {
            userId,
            sessionId,
            reason: 'Session not found or expired',
            ip: clientIP
          })

          return NextResponse.json(
            { error: 'Session refresh failed', reason: 'Session not found or expired' },
            { status: 400 }
          )
        }

        logger.info('Session refreshed successfully', {
          userId,
          sessionId,
          lastActivity: sessionData.lastActivity,
          ip: clientIP
        })

        return NextResponse.json({
          success: true,
          lastActivity: sessionData.lastActivity,
          message: 'Session refreshed successfully'
        })

      case 'terminate':
        if (!sessionId) {
          return NextResponse.json(
            { error: 'Session ID required for termination' },
            { status: 400 }
          )
        }

        await sessionManager.destroySession(sessionId)

        logger.info('Session terminated by user', {
          userId,
          sessionId,
          ip: clientIP
        })

        return NextResponse.json({
          success: true,
          message: 'Session terminated successfully'
        })

      case 'validate':
        if (!sessionId || !deviceInfo) {
          return NextResponse.json(
            { error: 'Session ID and device info required for validation' },
            { status: 400 }
          )
        }

        // Session validation functionality not implemented yet
        const validationSessionData = await sessionManager.getSession(sessionId, false)

        if (!validationSessionData) {
          logger.warn('Session validation failed', {
            userId,
            sessionId,
            reason: 'Session not found',
            ip: clientIP
          })

          return NextResponse.json({
            valid: false,
            reason: 'Session not found',
            riskScore: 100
          })
        }

        return NextResponse.json({
          valid: true,
          reason: 'Session valid',
          riskScore: 0
        })

      case 'list':
        const userSessions = await sessionManager.getUserSessions(userId)

        const sessionsWithDetails = await Promise.all(
          userSessions.map(async (session) => {
            const details = await sessionManager.getSession(session.sessionId)
            return {
              sessionId: session.sessionId,
              createdAt: session.data.createdAt,
              lastActivity: details?.lastActivity,
              ipAddress: details?.ipAddress,
              userAgent: details?.userAgent,
              deviceType: 'unknown',
              location: details?.geographic || {},
              isActive: details !== null
            }
          })
        )

        return NextResponse.json({
          sessions: sessionsWithDetails,
          total: sessionsWithDetails.length
        })

      default:
        return NextResponse.json(
          { error: 'Invalid action' },
          { status: 400 }
        )
    }

  } catch (error) {
    logger.error('Enhanced auth API error', {
      error: error instanceof Error ? error.message : 'Unknown error',
      stack: error instanceof Error ? error.stack : undefined
    })

    if (error instanceof z.ZodError) {
      return NextResponse.json(
        { error: 'Invalid request data', details: error.errors },
        { status: 400 }
      )
    }

    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    )
  }
}

export async function GET(request: NextRequest) {
  try {
    const session = await getServerSession(authOptions)

    if (!session?.user?.id) {
      return NextResponse.json(
        { error: 'Authentication required' },
        { status: 401 }
      )
    }

    const userId = session.user.id
    const url = new URL(request.url)
    const type = url.searchParams.get('type')

    switch (type) {
      case 'security-status':
        // Security status functionality not implemented yet
        return NextResponse.json({
          riskLevel: 'low',
          recentFailedAttempts: 0,
          suspiciousActivity: false,
          lastSecurityEvent: null,
          activeSecurityMeasures: []
        })

      case 'meta-tokens':
        const metaTokens = await metaTokenManager.getUserTokens(userId)

        // Remove sensitive data before sending
        const sanitizedTokens = metaTokens.map(tokenData => ({
          tokenId: tokenData.tokenId,
          type: tokenData.token.tokenType,
          createdAt: tokenData.token.issuedAt,
          expiresAt: tokenData.token.expiresAt,
          lastUsed: tokenData.token.lastRefresh,
          isValid: tokenData.token.expiresAt > Date.now(),
          permissions: [],
          rateLimitRemaining: 100
        }))

        return NextResponse.json({
          tokens: sanitizedTokens,
          total: sanitizedTokens.length
        })

      case 'session-info':
        const sessionId = request.headers.get('x-session-id')

        if (!sessionId) {
          return NextResponse.json(
            { error: 'Session ID not found' },
            { status: 400 }
          )
        }

        const sessionData = await sessionManager.getSession(sessionId)

        if (!sessionData) {
          return NextResponse.json(
            { error: 'Session not found' },
            { status: 404 }
          )
        }

        return NextResponse.json({
          sessionId,
          userId: sessionData.userId,
          createdAt: sessionData.createdAt,
          lastActivity: sessionData.lastActivity,
          expiresAt: sessionData.createdAt + (30 * 24 * 60 * 60 * 1000), // 30 days from creation
          deviceType: 'unknown',
          location: sessionData.geographic,
          isActive: true
        })

      default:
        return NextResponse.json(
          { error: 'Invalid type parameter' },
          { status: 400 }
        )
    }

  } catch (error) {
    logger.error('Enhanced auth GET API error', {
      error: error instanceof Error ? error.message : 'Unknown error',
      stack: error instanceof Error ? error.stack : undefined
    })

    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    )
  }
}