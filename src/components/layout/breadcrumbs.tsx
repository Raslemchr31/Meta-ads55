'use client'

import { usePathname } from 'next/navigation'
import Link from 'next/link'
import { ChevronRight, Home } from 'lucide-react'
import { cn } from '@/lib/utils'

const routeNames: Record<string, string> = {
  dashboard: 'Dashboard',
  'campaign-wizard': 'Campaign Wizard',
  'team-board': 'Team Board',
  'creative-hub': 'Creative Hub',
  'ai-optimization': 'AI Optimization',
  pages: 'Pages Management',
  campaigns: 'Campaigns',
  create: 'Create Campaign',
  templates: 'Templates',
  analytics: 'Analytics & Reports',
  performance: 'Performance',
  audience: 'Audience',
  reports: 'Reports',
  competitors: 'Competitor Research',
  insights: 'AI Insights',
  creative: 'Creative Studio',
  activity: 'Activity',
  data: 'Data Sources',
  notifications: 'Notifications',
  help: 'Help & Support',
  settings: 'Settings',
}

export function Breadcrumbs() {
  const pathname = usePathname()
  const pathSegments = pathname.split('/').filter(Boolean)
  
  // Don't show breadcrumbs on the main dashboard
  if (pathname === '/dashboard') {
    return null
  }

  const breadcrumbs = pathSegments.map((segment, index) => {
    const path = '/' + pathSegments.slice(0, index + 1).join('/')
    const name = routeNames[segment] || segment.charAt(0).toUpperCase() + segment.slice(1)
    const isLast = index === pathSegments.length - 1
    
    return {
      name,
      path,
      isLast,
    }
  })

  return (
    <nav className="flex items-center space-x-1 text-sm text-muted-foreground">
      <Link
        href="/dashboard"
        className="flex items-center hover:text-foreground transition-colors"
      >
        <Home className="h-4 w-4" />
        <span className="sr-only">Dashboard</span>
      </Link>
      
      {breadcrumbs.map((crumb, index) => (
        <div key={crumb.path} className="flex items-center space-x-1">
          <ChevronRight className="h-4 w-4" />
          {crumb.isLast ? (
            <span className="font-medium text-foreground">
              {crumb.name}
            </span>
          ) : (
            <Link
              href={crumb.path}
              className="hover:text-foreground transition-colors"
            >
              {crumb.name}
            </Link>
          )}
        </div>
      ))}
    </nav>
  )
}