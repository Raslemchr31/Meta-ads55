import { useState, useEffect, useCallback } from 'react'
import { useSession } from 'next-auth/react'
import { useRouter } from 'next/navigation'

export interface SessionInfo {
  sessionId: string
  userId: string
  createdAt: string
  lastActivity: string
  expiresAt: string
  deviceType: string
  location: string
  isActive: boolean
}

export interface SecurityStatus {
  riskLevel: 'low' | 'medium' | 'high' | 'critical'
  recentFailedAttempts: number
  suspiciousActivity: boolean
  lastSecurityEvent: string | null
  activeSecurityMeasures: string[]
}

export interface MetaToken {
  tokenId: string
  type: 'user' | 'system_user'
  createdAt: string
  expiresAt: string
  lastUsed: string | null
  isValid: boolean
  permissions: string[]
  rateLimitRemaining: number
}

export interface UserSession {
  sessionId: string
  createdAt: string
  lastActivity: string
  ipAddress: string
  userAgent: string
  deviceType: string
  location: string
  isActive: boolean
}

export function useEnhancedAuth() {
  const { data: session, status } = useSession()
  const router = useRouter()

  const [sessionInfo, setSessionInfo] = useState<SessionInfo | null>(null)
  const [securityStatus, setSecurityStatus] = useState<SecurityStatus | null>(null)
  const [metaTokens, setMetaTokens] = useState<MetaToken[]>([])
  const [userSessions, setUserSessions] = useState<UserSession[]>([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  // Fetch session information
  const fetchSessionInfo = useCallback(async () => {
    if (!session?.user?.id) return

    try {
      setLoading(true)
      setError(null)

      const response = await fetch('/api/auth/enhanced?type=session-info', {
        method: 'GET',
        headers: {
          'Content-Type': 'application/json'
        }
      })

      if (!response.ok) {
        throw new Error(`Failed to fetch session info: ${response.statusText}`)
      }

      const data = await response.json()
      setSessionInfo(data)

    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to fetch session info')
    } finally {
      setLoading(false)
    }
  }, [session?.user?.id])

  // Fetch security status
  const fetchSecurityStatus = useCallback(async () => {
    if (!session?.user?.id) return

    try {
      const response = await fetch('/api/auth/enhanced?type=security-status', {
        method: 'GET',
        headers: {
          'Content-Type': 'application/json'
        }
      })

      if (!response.ok) {
        throw new Error(`Failed to fetch security status: ${response.statusText}`)
      }

      const data = await response.json()
      setSecurityStatus(data)

    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to fetch security status')
    }
  }, [session?.user?.id])

  // Fetch Meta tokens
  const fetchMetaTokens = useCallback(async () => {
    if (!session?.user?.id) return

    try {
      const response = await fetch('/api/auth/enhanced?type=meta-tokens', {
        method: 'GET',
        headers: {
          'Content-Type': 'application/json'
        }
      })

      if (!response.ok) {
        throw new Error(`Failed to fetch Meta tokens: ${response.statusText}`)
      }

      const data = await response.json()
      setMetaTokens(data.tokens || [])

    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to fetch Meta tokens')
    }
  }, [session?.user?.id])

  // Fetch user sessions
  const fetchUserSessions = useCallback(async () => {
    if (!session?.user?.id) return

    try {
      const response = await fetch('/api/auth/enhanced', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          action: 'list'
        })
      })

      if (!response.ok) {
        throw new Error(`Failed to fetch user sessions: ${response.statusText}`)
      }

      const data = await response.json()
      setUserSessions(data.sessions || [])

    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to fetch user sessions')
    }
  }, [session?.user?.id])

  // Refresh current session
  const refreshSession = useCallback(async (sessionId: string) => {
    try {
      setLoading(true)
      setError(null)

      const response = await fetch('/api/auth/enhanced', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          action: 'refresh',
          sessionId
        })
      })

      if (!response.ok) {
        throw new Error(`Failed to refresh session: ${response.statusText}`)
      }

      const data = await response.json()

      if (data.success) {
        // Refresh session info
        await fetchSessionInfo()
        return { success: true, newExpiry: data.newExpiry }
      } else {
        throw new Error(data.reason || 'Session refresh failed')
      }

    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to refresh session'
      setError(errorMessage)
      return { success: false, error: errorMessage }
    } finally {
      setLoading(false)
    }
  }, [fetchSessionInfo])

  // Terminate a session
  const terminateSession = useCallback(async (sessionId: string) => {
    try {
      setLoading(true)
      setError(null)

      const response = await fetch('/api/auth/enhanced', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          action: 'terminate',
          sessionId
        })
      })

      if (!response.ok) {
        throw new Error(`Failed to terminate session: ${response.statusText}`)
      }

      const data = await response.json()

      if (data.success) {
        // If terminating current session, redirect to login
        if (sessionInfo?.sessionId === sessionId) {
          router.push('/auth/login?reason=session_terminated')
        } else {
          // Refresh sessions list
          await fetchUserSessions()
        }
        return { success: true }
      } else {
        throw new Error('Session termination failed')
      }

    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to terminate session'
      setError(errorMessage)
      return { success: false, error: errorMessage }
    } finally {
      setLoading(false)
    }
  }, [sessionInfo?.sessionId, router, fetchUserSessions])

  // Validate current session
  const validateSession = useCallback(async () => {
    if (!sessionInfo?.sessionId) return { valid: false, reason: 'No session' }

    try {
      const response = await fetch('/api/auth/enhanced', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          action: 'validate',
          sessionId: sessionInfo.sessionId,
          deviceInfo: {
            userAgent: navigator.userAgent,
            ipAddress: '', // Will be filled by server
            fingerprint: await generateBrowserFingerprint()
          }
        })
      })

      if (!response.ok) {
        throw new Error(`Failed to validate session: ${response.statusText}`)
      }

      const data = await response.json()

      if (!data.valid) {
        setError(`Session validation failed: ${data.reason}`)

        // Redirect to login if session is invalid
        router.push('/auth/login?reason=invalid_session')
      }

      return data

    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to validate session'
      setError(errorMessage)
      return { valid: false, reason: errorMessage }
    }
  }, [sessionInfo?.sessionId, router])

  // Initialize data when session is available
  useEffect(() => {
    if (status === 'authenticated' && session?.user?.id) {
      fetchSessionInfo()
      fetchSecurityStatus()
      fetchMetaTokens()
      fetchUserSessions()
    }
  }, [status, session?.user?.id, fetchSessionInfo, fetchSecurityStatus, fetchMetaTokens, fetchUserSessions])

  // Periodic session validation (every 5 minutes)
  useEffect(() => {
    if (!sessionInfo?.sessionId) return

    const interval = setInterval(() => {
      validateSession()
    }, 5 * 60 * 1000) // 5 minutes

    return () => clearInterval(interval)
  }, [sessionInfo?.sessionId, validateSession])

  return {
    // Data
    sessionInfo,
    securityStatus,
    metaTokens,
    userSessions,

    // State
    loading,
    error,
    isAuthenticated: status === 'authenticated',

    // Actions
    refreshSession,
    terminateSession,
    validateSession,

    // Refresh functions
    refreshData: useCallback(() => {
      fetchSessionInfo()
      fetchSecurityStatus()
      fetchMetaTokens()
      fetchUserSessions()
    }, [fetchSessionInfo, fetchSecurityStatus, fetchMetaTokens, fetchUserSessions]),

    refreshSessionInfo: fetchSessionInfo,
    refreshSecurityStatus: fetchSecurityStatus,
    refreshMetaTokens: fetchMetaTokens,
    refreshUserSessions: fetchUserSessions
  }
}

async function generateBrowserFingerprint(): Promise<string> {
  const components = [
    navigator.userAgent,
    navigator.language,
    screen.width,
    screen.height,
    screen.colorDepth,
    new Date().getTimezoneOffset(),
    navigator.platform,
    navigator.cookieEnabled,
    typeof(navigator.doNotTrack) !== 'undefined' ? navigator.doNotTrack : 'unknown'
  ]

  const fingerprint = components.join('|')

  // Simple hash function for browser fingerprint
  let hash = 0
  for (let i = 0; i < fingerprint.length; i++) {
    const char = fingerprint.charCodeAt(i)
    hash = ((hash << 5) - hash) + char
    hash = hash & hash // Convert to 32-bit integer
  }

  return Math.abs(hash).toString(36)
}