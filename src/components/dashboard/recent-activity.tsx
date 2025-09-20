'use client'

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Avatar, AvatarFallback, AvatarImage } from '@/components/ui/avatar'
import {
  Activity,
  Play,
  Pause,
  Settings,
  TrendingUp,
  TrendingDown,
  User,
  Zap,
  AlertTriangle,
  CheckCircle,
  Clock,
  ArrowRight,
} from 'lucide-react'
import { formatCurrency, getRelativeTime } from '@/lib/utils'

interface ActivityItem {
  id: string
  type: 'campaign' | 'optimization' | 'alert' | 'system' | 'user'
  title: string
  description: string
  timestamp: Date
  status?: 'success' | 'warning' | 'error' | 'info'
  metadata?: {
    campaignName?: string
    amount?: number
    percentage?: number
    user?: string
  }
}

// Mock activity data
const activities: ActivityItem[] = [
  {
    id: '1',
    type: 'campaign',
    title: 'Campaign Performance Alert',
    description: 'Summer Sale campaign exceeded daily budget by 15%',
    timestamp: new Date(Date.now() - 15 * 60 * 1000), // 15 minutes ago
    status: 'warning',
    metadata: {
      campaignName: 'Summer Sale',
      amount: 1250,
      percentage: 15,
    },
  },
  {
    id: '2',
    type: 'optimization',
    title: 'AI Optimization Applied',
    description: 'Automatically adjusted bidding strategy for better ROAS',
    timestamp: new Date(Date.now() - 45 * 60 * 1000), // 45 minutes ago
    status: 'success',
    metadata: {
      campaignName: 'Brand Awareness',
      percentage: 23,
    },
  },
  {
    id: '3',
    type: 'user',
    title: 'New Campaign Created',
    description: 'Holiday Promo campaign was successfully launched',
    timestamp: new Date(Date.now() - 2 * 60 * 60 * 1000), // 2 hours ago
    status: 'success',
    metadata: {
      campaignName: 'Holiday Promo',
      user: 'John Doe',
    },
  },
  {
    id: '4',
    type: 'alert',
    title: 'Low Conversion Rate',
    description: 'Product Launch campaign has a conversion rate below 1%',
    timestamp: new Date(Date.now() - 3 * 60 * 60 * 1000), // 3 hours ago
    status: 'error',
    metadata: {
      campaignName: 'Product Launch',
      percentage: 0.7,
    },
  },
  {
    id: '5',
    type: 'system',
    title: 'Data Sync Completed',
    description: 'Successfully synchronized Facebook Ads data',
    timestamp: new Date(Date.now() - 4 * 60 * 60 * 1000), // 4 hours ago
    status: 'info',
  },
  {
    id: '6',
    type: 'campaign',
    title: 'Campaign Paused',
    description: 'Retargeting campaign was paused due to high CPC',
    timestamp: new Date(Date.now() - 6 * 60 * 60 * 1000), // 6 hours ago
    status: 'warning',
    metadata: {
      campaignName: 'Retargeting',
      amount: 8.50,
    },
  },
]

const getActivityIcon = (type: string, status?: string) => {
  switch (type) {
    case 'campaign':
      return <Play className="h-4 w-4" />
    case 'optimization':
      return <Zap className="h-4 w-4" />
    case 'alert':
      return status === 'error' ? <AlertTriangle className="h-4 w-4" /> : <TrendingDown className="h-4 w-4" />
    case 'system':
      return <Settings className="h-4 w-4" />
    case 'user':
      return <User className="h-4 w-4" />
    default:
      return <Activity className="h-4 w-4" />
  }
}

const getStatusColor = (status?: string) => {
  switch (status) {
    case 'success':
      return 'text-green-600 bg-green-100 dark:text-green-400 dark:bg-green-900/20'
    case 'warning':
      return 'text-yellow-600 bg-yellow-100 dark:text-yellow-400 dark:bg-yellow-900/20'
    case 'error':
      return 'text-red-600 bg-red-100 dark:text-red-400 dark:bg-red-900/20'
    case 'info':
      return 'text-blue-600 bg-blue-100 dark:text-blue-400 dark:bg-blue-900/20'
    default:
      return 'text-gray-600 bg-gray-100 dark:text-gray-400 dark:bg-gray-900/20'
  }
}

export function RecentActivity() {
  const recentActivities = activities.slice(0, 6)

  return (
    <Card className="h-fit">
      <CardHeader>
        <CardTitle className="flex items-center space-x-2">
          <Activity className="h-5 w-5" />
          <span>Recent Activity</span>
          <Badge variant="secondary" className="text-xs">Demo</Badge>
        </CardTitle>
        <CardDescription>
          Latest updates and notifications from your campaigns
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="space-y-4">
          {recentActivities.map((activity) => (
            <div key={activity.id} className="flex items-start space-x-3 p-3 rounded-lg border bg-card/50 hover:bg-card transition-colors">
              <div className={`p-2 rounded-full ${getStatusColor(activity.status)}`}>
                {getActivityIcon(activity.type, activity.status)}
              </div>
              
              <div className="flex-1 space-y-1">
                <div className="flex items-center justify-between">
                  <h4 className="text-sm font-medium">{activity.title}</h4>
                  <span className="text-xs text-muted-foreground">
                    {getRelativeTime(activity.timestamp)}
                  </span>
                </div>
                
                <p className="text-xs text-muted-foreground">
                  {activity.description}
                </p>
                
                {activity.metadata && (
                  <div className="flex items-center space-x-2 text-xs">
                    {activity.metadata.campaignName && (
                      <Badge variant="outline" className="text-xs">
                        {activity.metadata.campaignName}
                      </Badge>
                    )}
                    {activity.metadata.amount && (
                      <span className="text-muted-foreground">
                        {formatCurrency(activity.metadata.amount)}
                      </span>
                    )}
                    {activity.metadata.percentage && (
                      <span className={`font-medium ${
                        activity.status === 'success' ? 'text-green-600' : 
                        activity.status === 'warning' ? 'text-yellow-600' : 
                        'text-red-600'
                      }`}>
                        {activity.metadata.percentage > 0 ? '+' : ''}{activity.metadata.percentage}%
                      </span>
                    )}
                    {activity.metadata.user && (
                      <span className="text-muted-foreground">
                        by {activity.metadata.user}
                      </span>
                    )}
                  </div>
                )}
              </div>
            </div>
          ))}
        </div>
        
        <div className="pt-4 border-t">
          <Button variant="ghost" className="w-full justify-between text-sm">
            <div className="w-full flex items-center justify-between">
              <span>View all activity</span>
              <ArrowRight className="h-4 w-4" />
            </div>
          </Button>
        </div>
      </CardContent>
    </Card>
  )
}