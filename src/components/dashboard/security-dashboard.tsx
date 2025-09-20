'use client'

import { useState, useEffect } from 'react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { useEnhancedAuth } from '@/hooks/use-enhanced-auth'
import {
  Shield,
  AlertTriangle,
  Activity,
  Clock,
  MapPin,
  Smartphone,
  Monitor,
  RefreshCw,
  X,
  Eye,
  Calendar
} from 'lucide-react'

interface SecurityDashboardData {
  timeRange: string
  userId: string
  metrics: {
    totalEvents: number
    criticalEvents: number
    highRiskEvents: number
    failedAttempts: number
    activeAlerts: number
    criticalAlerts: number
    averageRiskScore: number
  }
  securityStatus: {
    riskLevel: 'low' | 'medium' | 'high' | 'critical'
    overallScore: number
    lastSecurityEvent: string | null
    activeSecurityMeasures: string[]
  }
  riskSummary: {
    low: number
    medium: number
    high: number
    critical: number
  }
  eventTypeSummary: Record<string, number>
  timeline: Array<{
    timestamp: string
    eventCount: number
    riskScore: number
  }>
  alerts: Array<{
    alertId: string
    alertType: string
    severity: 'low' | 'medium' | 'high' | 'critical'
    title: string
    triggeredAt: string
    status: string
  }>
}

export function SecurityDashboard() {
  const {
    sessionInfo,
    securityStatus,
    userSessions,
    loading: authLoading,
    error: authError,
    terminateSession,
    refreshData
  } = useEnhancedAuth()

  const [dashboardData, setDashboardData] = useState<SecurityDashboardData | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [timeRange, setTimeRange] = useState<'1h' | '24h' | '7d' | '30d'>('24h')

  const fetchDashboardData = async () => {
    try {
      setLoading(true)
      setError(null)

      const response = await fetch(`/api/security/dashboard?timeRange=${timeRange}&includeDetails=true`)

      if (!response.ok) {
        throw new Error(`Failed to fetch dashboard data: ${response.statusText}`)
      }

      const data = await response.json()
      setDashboardData(data)

    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to fetch dashboard data')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchDashboardData()
  }, [timeRange])

  const handleTerminateSession = async (sessionId: string) => {
    const result = await terminateSession(sessionId)
    if (result.success) {
      refreshData()
    }
  }

  const getRiskBadgeColor = (level: string) => {
    switch (level) {
      case 'low': return 'default'
      case 'medium': return 'secondary'
      case 'high': return 'destructive'
      case 'critical': return 'destructive'
      default: return 'default'
    }
  }

  const getSeverityIcon = (severity: string) => {
    switch (severity) {
      case 'critical': return <AlertTriangle className="h-4 w-4 text-red-500" />
      case 'high': return <AlertTriangle className="h-4 w-4 text-orange-500" />
      case 'medium': return <AlertTriangle className="h-4 w-4 text-yellow-500" />
      default: return <Shield className="h-4 w-4 text-blue-500" />
    }
  }

  if (loading || authLoading) {
    return (
      <div className="flex items-center justify-center p-8">
        <RefreshCw className="h-8 w-8 animate-spin" />
        <span className="ml-2">Loading security dashboard...</span>
      </div>
    )
  }

  if (error || authError) {
    return (
      <Alert>
        <AlertTriangle className="h-4 w-4" />
        <AlertDescription>
          {error || authError}
        </AlertDescription>
      </Alert>
    )
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">Security Dashboard</h1>
          <p className="text-muted-foreground">
            Monitor your account security and activity
          </p>
        </div>

        <div className="flex items-center gap-4">
          <select
            value={timeRange}
            onChange={(e) => setTimeRange(e.target.value as any)}
            className="px-3 py-2 border rounded-md"
          >
            <option value="1h">Last Hour</option>
            <option value="24h">Last 24 Hours</option>
            <option value="7d">Last 7 Days</option>
            <option value="30d">Last 30 Days</option>
          </select>

          <Button onClick={() => { refreshData(); fetchDashboardData() }} variant="outline">
            <RefreshCw className="h-4 w-4 mr-2" />
            Refresh
          </Button>
        </div>
      </div>

      {/* Security Status Overview */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Security Level</CardTitle>
            <Shield className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="flex items-center gap-2">
              <Badge variant={getRiskBadgeColor(securityStatus?.riskLevel || 'low')}>
                {securityStatus?.riskLevel || 'Unknown'}
              </Badge>
              <span className="text-2xl font-bold">
                {securityStatus?.overallScore || 0}%
              </span>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Active Alerts</CardTitle>
            <AlertTriangle className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{dashboardData?.metrics.activeAlerts || 0}</div>
            <p className="text-xs text-muted-foreground">
              {dashboardData?.metrics.criticalAlerts || 0} critical
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Recent Events</CardTitle>
            <Activity className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{dashboardData?.metrics.totalEvents || 0}</div>
            <p className="text-xs text-muted-foreground">
              {dashboardData?.metrics.highRiskEvents || 0} high risk
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Risk Score</CardTitle>
            <AlertTriangle className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {Math.round(dashboardData?.metrics.averageRiskScore || 0)}
            </div>
            <p className="text-xs text-muted-foreground">
              Average risk level
            </p>
          </CardContent>
        </Card>
      </div>

      {/* Current Session Info */}
      {sessionInfo && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Monitor className="h-5 w-5" />
              Current Session
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
              <div>
                <p className="text-sm font-medium">Session ID</p>
                <p className="text-xs text-muted-foreground font-mono">
                  {sessionInfo.sessionId.slice(0, 16)}...
                </p>
              </div>
              <div>
                <p className="text-sm font-medium">Device Type</p>
                <p className="text-xs text-muted-foreground">{sessionInfo.deviceType}</p>
              </div>
              <div>
                <p className="text-sm font-medium">Last Activity</p>
                <p className="text-xs text-muted-foreground">
                  {new Date(sessionInfo.lastActivity).toLocaleString()}
                </p>
              </div>
              <div>
                <p className="text-sm font-medium">Location</p>
                <p className="text-xs text-muted-foreground">{sessionInfo.location}</p>
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Active Sessions */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Smartphone className="h-5 w-5" />
            Active Sessions
          </CardTitle>
          <CardDescription>
            Manage your active sessions across all devices
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            {userSessions.map((session) => (
              <div
                key={session.sessionId}
                className="flex items-center justify-between p-4 border rounded-lg"
              >
                <div className="flex items-center gap-4">
                  <div className="flex items-center gap-2">
                    {session.deviceType === 'mobile' ? (
                      <Smartphone className="h-4 w-4" />
                    ) : (
                      <Monitor className="h-4 w-4" />
                    )}
                    <div>
                      <p className="font-medium">{session.deviceType}</p>
                      <p className="text-xs text-muted-foreground">
                        {session.ipAddress}
                      </p>
                    </div>
                  </div>

                  <div className="flex items-center gap-2">
                    <MapPin className="h-3 w-3" />
                    <span className="text-sm">{session.location}</span>
                  </div>

                  <div className="flex items-center gap-2">
                    <Clock className="h-3 w-3" />
                    <span className="text-sm">
                      {new Date(session.lastActivity).toLocaleString()}
                    </span>
                  </div>
                </div>

                <div className="flex items-center gap-2">
                  {session.sessionId === sessionInfo?.sessionId && (
                    <Badge variant="default">Current</Badge>
                  )}

                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => handleTerminateSession(session.sessionId)}
                    disabled={session.sessionId === sessionInfo?.sessionId}
                  >
                    <X className="h-3 w-3" />
                  </Button>
                </div>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* Security Alerts */}
      {dashboardData?.alerts && dashboardData.alerts.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <AlertTriangle className="h-5 w-5" />
              Security Alerts
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-3">
              {dashboardData.alerts.map((alert) => (
                <div
                  key={alert.alertId}
                  className="flex items-center justify-between p-3 border rounded-lg"
                >
                  <div className="flex items-center gap-3">
                    {getSeverityIcon(alert.severity)}
                    <div>
                      <p className="font-medium">{alert.title}</p>
                      <p className="text-xs text-muted-foreground">
                        {new Date(alert.triggeredAt).toLocaleString()}
                      </p>
                    </div>
                  </div>

                  <div className="flex items-center gap-2">
                    <Badge variant={getRiskBadgeColor(alert.severity)}>
                      {alert.severity}
                    </Badge>
                    <Button variant="outline" size="sm">
                      <Eye className="h-3 w-3" />
                    </Button>
                  </div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Risk Summary */}
      {dashboardData?.riskSummary && (
        <Card>
          <CardHeader>
            <CardTitle>Risk Distribution</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              {Object.entries(dashboardData.riskSummary).map(([level, count]) => (
                <div key={level} className="text-center">
                  <div className="text-2xl font-bold">{count}</div>
                  <Badge variant={getRiskBadgeColor(level)} className="text-xs">
                    {level}
                  </Badge>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  )
}