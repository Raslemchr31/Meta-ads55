import { NextRequest, NextResponse } from 'next/server'
import { getToken } from 'next-auth/jwt'
import { createHash, createHmac } from 'crypto'
import { databaseManager } from './database'
import { logger } from './logger'

interface RateLimitOptions {
  windowMs: number // Time window in milliseconds
  max: number // Maximum requests per window
  keyGenerator?: (req: NextRequest) => string
  skip?: (req: NextRequest) => boolean
  message?: string
}

interface SecurityOptions {
  enableCSRF: boolean
  enableRateLimit: boolean
  enableIPWhitelist: boolean
  enableUserAgentValidation: boolean
  allowedOrigins: string[]
  blockedIPs: string[]
  allowedIPs: string[]
  rateLimitOptions: RateLimitOptions
}

class SecurityMiddleware {
  private options: SecurityOptions

  constructor(options: Partial<SecurityOptions> = {}) {
    this.options = {
      enableCSRF: true,
      enableRateLimit: true,
      enableIPWhitelist: false,
      enableUserAgentValidation: true,
      allowedOrigins: [
        process.env.NEXTAUTH_URL || 'http://localhost:3000',
        'https://graph.facebook.com',
        'https://www.facebook.com',
      ],
      blockedIPs: [],
      allowedIPs: [],
      rateLimitOptions: {
        windowMs: 15 * 60 * 1000, // 15 minutes
        max: 100, // 100 requests per window
        keyGenerator: (req) => this.getClientIP(req),
        message: 'Too many requests, please try again later',
      },
      ...options,
    }
  }

  private getClientIP(req: NextRequest): string {
    const forwarded = req.headers.get('x-forwarded-for')
    const real = req.headers.get('x-real-ip')
    const connection = req.headers.get('x-connecting-ip')
    
    if (forwarded) {
      return forwarded.split(',')[0].trim()
    }
    
    return real || connection || '127.0.0.1'
  }

  private async checkRateLimit(req: NextRequest): Promise<{ allowed: boolean; remaining?: number; resetTime?: number }> {
    const { rateLimitOptions } = this.options
    const key = rateLimitOptions.keyGenerator ? rateLimitOptions.keyGenerator(req) : this.getClientIP(req)
    const endpoint = req.nextUrl.pathname
    
    try {
      const allowed = await databaseManager.checkRateLimit(
        `${key}:${endpoint}`,
        rateLimitOptions.max,
        rateLimitOptions.windowMs / (60 * 1000) // Convert to minutes
      )
      
      return { allowed }
    } catch (error) {
      logger.error('Rate limit check failed', error, { 
        key, 
        endpoint,
        ip: this.getClientIP(req),
      })
      // Fail open - allow request if rate limit check fails
      return { allowed: true }
    }
  }

  private validateCSRFToken(req: NextRequest): boolean {
    // Skip CSRF for GET, HEAD, OPTIONS requests
    if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) {
      return true
    }

    const token = req.headers.get('x-csrf-token') || req.headers.get('csrf-token')
    const referer = req.headers.get('referer')
    const origin = req.headers.get('origin')

    // Check if request comes from allowed origin
    const requestOrigin = origin || (referer ? new URL(referer).origin : '')
    
    if (!this.options.allowedOrigins.includes(requestOrigin)) {
      logger.logSecurityEvent('CSRF validation failed - invalid origin', 'medium', {
        origin: requestOrigin,
        referer,
        allowedOrigins: this.options.allowedOrigins,
      })
      return false
    }

    // For API routes, require CSRF token
    if (req.nextUrl.pathname.startsWith('/api/')) {
      if (!token) {
        logger.logSecurityEvent('CSRF validation failed - missing token', 'medium', {
          path: req.nextUrl.pathname,
          method: req.method,
        })
        return false
      }

      // Validate CSRF token format (basic validation)
      if (!/^[a-zA-Z0-9+/]+=*$/.test(token) || token.length < 32) {
        logger.logSecurityEvent('CSRF validation failed - invalid token format', 'high', {
          token: token.substring(0, 10) + '...',
          path: req.nextUrl.pathname,
        })
        return false
      }
    }

    return true
  }

  private validateUserAgent(req: NextRequest): boolean {
    const userAgent = req.headers.get('user-agent')
    
    if (!userAgent) {
      logger.logSecurityEvent('Missing User-Agent header', 'low', {
        path: req.nextUrl.pathname,
        ip: this.getClientIP(req),
      })
      return false
    }

    // Block known bot patterns (but allow legitimate ones)
    const suspiciousPatterns = [
      /bot/i,
      /crawl/i,
      /spider/i,
      /scraper/i,
      /harvest/i,
      /python/i,
      /curl/i,
      /wget/i,
    ]

    // Allow legitimate user agents
    const legitimatePatterns = [
      /googlebot/i,
      /bingbot/i,
      /slackbot/i,
      /facebookexternalhit/i,
      /twitterbot/i,
      /linkedinbot/i,
    ]

    for (const pattern of legitimatePatterns) {
      if (pattern.test(userAgent)) {
        return true
      }
    }

    for (const pattern of suspiciousPatterns) {
      if (pattern.test(userAgent)) {
        logger.logSecurityEvent('Suspicious User-Agent detected', 'medium', {
          userAgent,
          path: req.nextUrl.pathname,
          ip: this.getClientIP(req),
        })
        return false
      }
    }

    return true
  }

  private validateIPAddress(req: NextRequest): boolean {
    const clientIP = this.getClientIP(req)

    // Check blocked IPs
    if (this.options.blockedIPs.includes(clientIP)) {
      logger.logSecurityEvent('Blocked IP attempted access', 'high', {
        ip: clientIP,
        path: req.nextUrl.pathname,
      })
      return false
    }

    // Check allowed IPs (if whitelist is enabled)
    if (this.options.enableIPWhitelist && this.options.allowedIPs.length > 0) {
      if (!this.options.allowedIPs.includes(clientIP)) {
        logger.logSecurityEvent('IP not in whitelist', 'medium', {
          ip: clientIP,
          path: req.nextUrl.pathname,
        })
        return false
      }
    }

    return true
  }

  async validateRequest(req: NextRequest): Promise<NextResponse | null> {
    const startTime = Date.now()
    const clientIP = this.getClientIP(req)
    const userAgent = req.headers.get('user-agent') || 'unknown'
    const path = req.nextUrl.pathname

    try {
      // IP validation
      if (!this.validateIPAddress(req)) {
        return NextResponse.json(
          { error: 'Access denied' },
          { status: 403 }
        )
      }

      // User-Agent validation
      if (this.options.enableUserAgentValidation && !this.validateUserAgent(req)) {
        return NextResponse.json(
          { error: 'Invalid request' },
          { status: 400 }
        )
      }

      // CSRF validation
      if (this.options.enableCSRF && !this.validateCSRFToken(req)) {
        return NextResponse.json(
          { error: 'CSRF validation failed' },
          { status: 403 }
        )
      }

      // Rate limiting
      if (this.options.enableRateLimit) {
        const rateLimitResult = await this.checkRateLimit(req)
        
        if (!rateLimitResult.allowed) {
          logger.logRateLimit(path, this.options.rateLimitOptions.max, {
            ip: clientIP,
            userAgent,
          })
          
          const response = NextResponse.json(
            { 
              error: this.options.rateLimitOptions.message,
              retryAfter: Math.ceil(this.options.rateLimitOptions.windowMs / 1000),
            },
            { status: 429 }
          )
          
          response.headers.set('Retry-After', Math.ceil(this.options.rateLimitOptions.windowMs / 1000).toString())
          response.headers.set('X-RateLimit-Limit', this.options.rateLimitOptions.max.toString())
          response.headers.set('X-RateLimit-Remaining', '0')
          response.headers.set('X-RateLimit-Reset', (Date.now() + this.options.rateLimitOptions.windowMs).toString())
          
          return response
        }
      }

      // Log successful security check
      logger.debug('Security validation passed', {
        ip: clientIP,
        userAgent,
        path,
        method: req.method,
        validationTime: Date.now() - startTime,
      })

      return null // No blocking response needed
    } catch (error) {
      logger.error('Security middleware error', error, {
        ip: clientIP,
        userAgent,
        path,
        method: req.method,
      })
      
      // Fail secure - block request on error
      return NextResponse.json(
        { error: 'Security validation failed' },
        { status: 500 }
      )
    }
  }
}

// Webhook signature validation for Meta webhooks
export class WebhookValidator {
  private appSecret: string

  constructor(appSecret?: string) {
    this.appSecret = appSecret || process.env.FACEBOOK_CLIENT_SECRET || ''
  }

  validateSignature(payload: string, signature: string): boolean {
    if (!this.appSecret) {
      logger.error('App secret not configured for webhook validation')
      return false
    }

    // Meta uses SHA256 HMAC
    const expectedHash = createHmac('sha256', this.appSecret)
      .update(payload)
      .digest('hex')
    
    const expectedSignature = `sha256=${expectedHash}`
    
    // Use constant-time comparison to prevent timing attacks
    return this.constantTimeCompare(signature, expectedSignature)
  }

  private constantTimeCompare(a: string, b: string): boolean {
    if (a.length !== b.length) {
      return false
    }

    let result = 0
    for (let i = 0; i < a.length; i++) {
      result |= a.charCodeAt(i) ^ b.charCodeAt(i)
    }

    return result === 0
  }

  validateChallenge(mode: string, token: string, challenge: string): string | null {
    const verifyToken = process.env.META_WEBHOOK_VERIFY_TOKEN
    
    if (!verifyToken) {
      logger.error('Webhook verify token not configured')
      return null
    }

    if (mode === 'subscribe' && token === verifyToken) {
      logger.info('Webhook challenge validated successfully', { challenge })
      return challenge
    }

    logger.logSecurityEvent('Invalid webhook challenge', 'medium', {
      mode,
      token: token ? 'present' : 'missing',
      challenge,
    })

    return null
  }
}

// Authentication middleware for API routes
export async function requireAuth(req: NextRequest): Promise<NextResponse | null> {
  try {
    const token = await getToken({ req, secret: process.env.NEXTAUTH_SECRET })
    
    if (!token) {
      logger.logAuthEvent('unauthorized_access', undefined, {
        path: req.nextUrl.pathname,
        method: req.method,
        ip: req.headers.get('x-forwarded-for') || req.headers.get('x-real-ip') || 'unknown',
      })
      
      return NextResponse.json(
        { error: 'Authentication required' },
        { status: 401 }
      )
    }

    logger.logAuthEvent('token_refresh', token.sub, {
      path: req.nextUrl.pathname,
      method: req.method,
    })

    return null // Continue processing
  } catch (error) {
    logger.error('Authentication middleware error', error, {
      path: req.nextUrl.pathname,
      method: req.method,
    })
    
    return NextResponse.json(
      { error: 'Authentication failed' },
      { status: 500 }
    )
  }
}

// Create default security middleware instance
export const securityMiddleware = new SecurityMiddleware({
  enableCSRF: process.env.NODE_ENV === 'production',
  enableRateLimit: true,
  enableIPWhitelist: false,
  enableUserAgentValidation: process.env.NODE_ENV === 'production',
  rateLimitOptions: {
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: process.env.NODE_ENV === 'production' ? 100 : 1000, // Higher limit for development
    message: 'Too many requests, please try again later',
  },
})

export const webhookValidator = new WebhookValidator()

// Export types for use in other files
export type { SecurityOptions, RateLimitOptions }