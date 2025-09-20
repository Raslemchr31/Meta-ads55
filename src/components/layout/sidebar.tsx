'use client'

import { useState } from 'react'
import Link from 'next/link'
import { usePathname } from 'next/navigation'
import { cn } from '@/lib/utils'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { ConnectionStatus } from '@/components/ui/connection-status'
import {
  BarChart3,
  Users,
  Target,
  TrendingUp,
  Search,
  Settings,
  ChevronLeft,
  ChevronRight,
  Facebook,
  PlusCircle,
  Activity,
  Zap,
  Database,
  Bell,
  HelpCircle,
  FileText} from 'lucide-react'

interface SidebarProps {
  open: boolean
  collapsed: boolean
  onOpenChange: (open: boolean) => void
  onCollapsedChange: (collapsed: boolean) => void
}

const navigation = [
  {
    name: 'Dashboard',
    href: '/dashboard',
    icon: BarChart3,
    current: false,
  },
  {
    name: 'Campaign Wizard',
    href: '/dashboard/campaign-wizard',
    icon: Target,
    current: false,
    badge: 'New',
  },
  {
    name: 'Team Board',
    href: '/dashboard/team-board',
    icon: Users,
    current: false,
  },
  {
    name: 'Analytics & Reports',
    href: '/dashboard/analytics',
    icon: TrendingUp,
    current: false,
    children: [
      { name: 'Overview', href: '/dashboard/analytics' },
      { name: 'Performance', href: '/dashboard/analytics/performance' },
      { name: 'Audience', href: '/dashboard/analytics/audience' },
      { name: 'Reports', href: '/dashboard/analytics/reports' },
    ],
  },
  {
    name: 'Creative Hub',
    href: '/dashboard/creative-hub',
    icon: PlusCircle,
    current: false,
    badge: 'AI',
  },
  {
    name: 'AI Optimization',
    href: '/dashboard/ai-optimization',
    icon: Zap,
    current: false,
    badge: 'Beta',
  },
  {
    name: 'Pages Management',
    href: '/dashboard/pages',
    icon: Facebook,
    current: false,
  },
  {
    name: 'Competitor Research',
    href: '/dashboard/competitors',
    icon: Search,
    current: false,
  },
]

const bottomNavigation = [
  {
    name: 'Activity',
    href: '/dashboard/activity',
    icon: Activity,
  },
  {
    name: 'Data Sources',
    href: '/dashboard/data',
    icon: Database,
  },
  {
    name: 'Notifications',
    href: '/dashboard/notifications',
    icon: Bell,
  },
  {
    name: 'Help & Support',
    href: '/dashboard/help',
    icon: HelpCircle,
  },
  {
    name: 'Settings',
    href: '/dashboard/settings',
    icon: Settings,
  },
]

export function Sidebar({ open, collapsed, onOpenChange, onCollapsedChange }: SidebarProps) {
  const pathname = usePathname()
  const [expandedItems, setExpandedItems] = useState<string[]>([])

  const toggleExpanded = (name: string) => {
    setExpandedItems(prev =>
      prev.includes(name)
        ? prev.filter(item => item !== name)
        : [...prev, name]
    )
  }

  const isActive = (href: string) => {
    if (href === '/dashboard') {
      return pathname === href
    }
    return pathname.startsWith(href)
  }

  return (
    <>
      {/* Desktop sidebar */}
      <div className={cn(
        "hidden lg:flex lg:flex-col lg:fixed lg:inset-y-0 transition-all duration-300 z-30",
        collapsed ? "lg:w-16" : "lg:w-64"
      )}>
        <div className="flex flex-col flex-1 min-h-0 bg-card border-r">
          {/* Logo and collapse button */}
          <div className="flex items-center justify-between h-16 px-4 border-b">
            {!collapsed && (
              <div className="flex items-center space-x-2">
                <div className="w-8 h-8 bg-gradient-to-br from-blue-500 to-purple-600 rounded-lg flex items-center justify-center">
                  <Facebook className="w-5 h-5 text-white" />
                </div>
                <span className="text-lg font-bold gradient-text">
                  Meta AI
                </span>
              </div>
            )}
            <Button
              variant="ghost"
              size="icon"
              onClick={() => onCollapsedChange(!collapsed)}
              className="h-8 w-8"
            >
              {collapsed ? (
                <ChevronRight className="h-4 w-4" />
              ) : (
                <ChevronLeft className="h-4 w-4" />
              )}
            </Button>
          </div>

          {/* Navigation */}
          <nav className="flex-1 px-2 py-4 space-y-1 overflow-y-auto">
            {navigation.map((item) => {
              const isExpanded = expandedItems.includes(item.name)
              const hasChildren = item.children && item.children.length > 0

              return (
                <div key={item.name}>
                  <Link
                    href={!hasChildren ? item.href : '#'}
                    onClick={(e) => {
                      if (hasChildren) {
                        e.preventDefault()
                        if (!collapsed) {
                          toggleExpanded(item.name)
                        }
                      }
                    }}
                    className={cn(
                      'group flex items-center px-2 py-2 text-sm font-medium rounded-md transition-colors',
                      isActive(item.href)
                        ? 'bg-primary text-primary-foreground'
                        : 'text-muted-foreground hover:bg-accent hover:text-accent-foreground',
                      collapsed && 'justify-center'
                    )}
                  >
                    <item.icon className={cn(
                      'flex-shrink-0 h-5 w-5',
                      !collapsed && 'mr-3'
                    )} />
                    {!collapsed && (
                      <>
                        <span className="flex-1">{item.name}</span>
                        {item.badge && (
                          <Badge variant="secondary" className="ml-2 text-xs">
                            {item.badge}
                          </Badge>
                        )}
                        {hasChildren && (
                          <ChevronRight className={cn(
                            'ml-2 h-4 w-4 transition-transform',
                            isExpanded && 'rotate-90'
                          )} />
                        )}
                      </>
                    )}
                  </Link>

                  {/* Submenu */}
                  {hasChildren && !collapsed && isExpanded && (
                    <div className="mt-1 ml-8 space-y-1">
                      {item.children?.map((child) => (
                        <Link
                          key={child.name}
                          href={child.href}
                          className={cn(
                            'group flex items-center px-2 py-1 text-sm rounded-md transition-colors',
                            isActive(child.href)
                              ? 'bg-primary/10 text-primary font-medium'
                              : 'text-muted-foreground hover:bg-accent hover:text-accent-foreground'
                          )}
                        >
                          {child.name}
                        </Link>
                      ))}
                    </div>
                  )}
                </div>
              )
            })}
          </nav>

          {/* Bottom navigation */}
          <div className="px-2 py-4 border-t space-y-1">
            {/* Connection Status */}
            {!collapsed && (
              <div className="flex items-center justify-between px-2 py-2">
                <span className="text-xs text-muted-foreground">Status</span>
                <ConnectionStatus />
              </div>
            )}

            {bottomNavigation.map((item) => (
              <Link
                key={item.name}
                href={item.href}
                className={cn(
                  'group flex items-center px-2 py-2 text-sm font-medium rounded-md transition-colors',
                  isActive(item.href)
                    ? 'bg-primary text-primary-foreground'
                    : 'text-muted-foreground hover:bg-accent hover:text-accent-foreground',
                  collapsed && 'justify-center'
                )}
              >
                <item.icon className={cn(
                  'flex-shrink-0 h-5 w-5',
                  !collapsed && 'mr-3'
                )} />
                {!collapsed && <span>{item.name}</span>}
              </Link>
            ))}
          </div>
        </div>
      </div>

      {/* Mobile sidebar */}
      <div className={cn(
        "lg:hidden fixed inset-y-0 left-0 z-50 w-64 bg-card border-r transform transition-transform duration-300",
        open ? "translate-x-0" : "-translate-x-full"
      )}>
        <div className="flex flex-col h-full">
          {/* Mobile header */}
          <div className="flex items-center justify-between h-16 px-4 border-b">
            <div className="flex items-center space-x-2">
              <div className="w-8 h-8 bg-gradient-to-br from-blue-500 to-purple-600 rounded-lg flex items-center justify-center">
                <Facebook className="w-5 h-5 text-white" />
              </div>
              <span className="text-lg font-bold gradient-text">
                Meta AI
              </span>
            </div>
            <Button
              variant="ghost"
              size="icon"
              onClick={() => onOpenChange(false)}
              className="h-8 w-8"
            >
              <ChevronLeft className="h-4 w-4" />
            </Button>
          </div>

          {/* Mobile navigation - same as desktop but always expanded */}
          <nav className="flex-1 px-2 py-4 space-y-1 overflow-y-auto">
            {navigation.map((item) => {
              const isExpanded = expandedItems.includes(item.name)
              const hasChildren = item.children && item.children.length > 0

              return (
                <div key={item.name}>
                  <Link
                    href={!hasChildren ? item.href : '#'}
                    onClick={(e) => {
                      if (hasChildren) {
                        e.preventDefault()
                        toggleExpanded(item.name)
                      } else {
                        onOpenChange(false)
                      }
                    }}
                    className={cn(
                      'group flex items-center px-2 py-2 text-sm font-medium rounded-md transition-colors',
                      isActive(item.href)
                        ? 'bg-primary text-primary-foreground'
                        : 'text-muted-foreground hover:bg-accent hover:text-accent-foreground'
                    )}
                  >
                    <item.icon className="flex-shrink-0 h-5 w-5 mr-3" />
                    <span className="flex-1">{item.name}</span>
                    {item.badge && (
                      <Badge variant="secondary" className="ml-2 text-xs">
                        {item.badge}
                      </Badge>
                    )}
                    {hasChildren && (
                      <ChevronRight className={cn(
                        'ml-2 h-4 w-4 transition-transform',
                        isExpanded && 'rotate-90'
                      )} />
                    )}
                  </Link>

                  {hasChildren && isExpanded && (
                    <div className="mt-1 ml-8 space-y-1">
                      {item.children?.map((child) => (
                        <Link
                          key={child.name}
                          href={child.href}
                          onClick={() => onOpenChange(false)}
                          className={cn(
                            'group flex items-center px-2 py-1 text-sm rounded-md transition-colors',
                            isActive(child.href)
                              ? 'bg-primary/10 text-primary font-medium'
                              : 'text-muted-foreground hover:bg-accent hover:text-accent-foreground'
                          )}
                        >
                          {child.name}
                        </Link>
                      ))}
                    </div>
                  )}
                </div>
              )
            })}
          </nav>

          {/* Mobile bottom navigation */}
          <div className="px-2 py-4 border-t space-y-1">
            {bottomNavigation.map((item) => (
              <Link
                key={item.name}
                href={item.href}
                onClick={() => onOpenChange(false)}
                className={cn(
                  'group flex items-center px-2 py-2 text-sm font-medium rounded-md transition-colors',
                  isActive(item.href)
                    ? 'bg-primary text-primary-foreground'
                    : 'text-muted-foreground hover:bg-accent hover:text-accent-foreground'
                )}
              >
                <item.icon className="flex-shrink-0 h-5 w-5 mr-3" />
                <span>{item.name}</span>
              </Link>
            ))}
          </div>
        </div>
      </div>
    </>
  )
}