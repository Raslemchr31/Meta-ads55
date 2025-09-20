'use client'

import Link from 'next/link'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { CreateCampaignModal } from './create-campaign-modal'
import {
  PlusCircle,
  Target,
  Search,
  Zap,
  Users,
  BarChart3,
  Facebook,
  TrendingUp,
} from 'lucide-react'

const quickActions = [
  {
    title: 'Create Campaign',
    description: 'Launch a new advertising campaign with AI assistance',
    href: '/dashboard/campaigns/create',
    icon: Target,
    color: 'bg-blue-500',
    badge: 'New',
  },
  {
    title: 'Connect Page',
    description: 'Add a new Facebook page to your account',
    href: '/dashboard/pages/connect',
    icon: Facebook,
    color: 'bg-facebook',
    badge: 'Quick',
  },
  {
    title: 'AI Insights',
    description: 'Get AI-powered recommendations for your campaigns',
    href: '/dashboard/insights',
    icon: Zap,
    color: 'bg-purple-500',
    badge: 'AI',
  },
  {
    title: 'Competitor Research',
    description: 'Analyze competitor strategies and performance',
    href: '/dashboard/competitors',
    icon: Search,
    color: 'bg-green-500',
    badge: 'Pro',
  },
  {
    title: 'Audience Builder',
    description: 'Create custom audiences with advanced targeting',
    href: '/dashboard/audience',
    icon: Users,
    color: 'bg-orange-500',
  },
  {
    title: 'Performance Report',
    description: 'Generate comprehensive analytics reports',
    href: '/dashboard/analytics/reports',
    icon: BarChart3,
    color: 'bg-indigo-500',
  },
]

export function QuickActions() {
  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center space-x-2">
          <PlusCircle className="h-5 w-5" />
          <span>Quick Actions</span>
          <Badge variant="secondary" className="text-xs">Demo Mode</Badge>
        </CardTitle>
        <CardDescription>
          Get started quickly with these common tasks
        </CardDescription>
      </CardHeader>
      <CardContent>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {quickActions.map((action) => {
            const Icon = action.icon

            // Special handling for Create Campaign action
            if (action.title === 'Create Campaign') {
              return (
                <CreateCampaignModal key={action.title}>
                  <Button
                    variant="outline"
                    className="h-auto p-4 flex flex-col items-start space-y-2 hover:shadow-md transition-all duration-200 w-full"
                  >
                    <div className="flex items-center justify-between w-full">
                      <div className={`p-2 rounded-lg ${action.color}`}>
                        <Icon className="h-4 w-4 text-white" />
                      </div>
                      {action.badge && (
                        <Badge variant="secondary" className="text-xs">
                          {action.badge}
                        </Badge>
                      )}
                    </div>
                    <div className="text-left space-y-1">
                      <h3 className="font-medium text-sm">{action.title}</h3>
                      <p className="text-xs text-muted-foreground line-clamp-2">
                        {action.description}
                      </p>
                    </div>
                  </Button>
                </CreateCampaignModal>
              )
            }

            return (
              <Button
                key={action.title}
                asChild
                variant="outline"
                className="h-auto p-4 flex flex-col items-start space-y-2 hover:shadow-md transition-all duration-200"
              >
                <Link href={action.href} className="flex flex-col space-y-2 w-full">
                  <div className="flex items-center justify-between w-full">
                    <div className={`p-2 rounded-lg ${action.color}`}>
                      <Icon className="h-4 w-4 text-white" />
                    </div>
                    {action.badge && (
                      <Badge variant="secondary" className="text-xs">
                        {action.badge}
                      </Badge>
                    )}
                  </div>
                  <div className="text-left space-y-1">
                    <h3 className="font-medium text-sm">{action.title}</h3>
                    <p className="text-xs text-muted-foreground line-clamp-2">
                      {action.description}
                    </p>
                  </div>
                </Link>
              </Button>
            )
          })}
        </div>
      </CardContent>
    </Card>
  )
}