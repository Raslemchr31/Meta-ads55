'use client'

import { useState, useEffect } from 'react'
import { useSession } from 'next-auth/react'
import { Sidebar } from './sidebar'
import { Header } from './header'
import { Breadcrumbs } from './breadcrumbs'
import { cn } from '@/lib/utils'
import { Skeleton } from '@/components/ui/skeleton'

interface DashboardLayoutProps {
  children: React.ReactNode
}

export function DashboardLayout({ children }: DashboardLayoutProps) {
  const [sidebarOpen, setSidebarOpen] = useState(false)
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false)
  const [mounted, setMounted] = useState(false)
  const { data: session, status } = useSession()

  useEffect(() => {
    setMounted(true)
    // Restore sidebar state from localStorage after mount
    const collapsed = localStorage.getItem('sidebar-collapsed') === 'true'
    setSidebarCollapsed(collapsed)
  }, [])

  // Save sidebar state to localStorage
  useEffect(() => {
    if (mounted) {
      localStorage.setItem('sidebar-collapsed', sidebarCollapsed.toString())
    }
  }, [sidebarCollapsed, mounted])

  // Prevent hydration issues by showing skeleton until mounted
  if (!mounted) {
    return <DashboardSkeleton />
  }

  // In demo mode, skip authentication checks for immediate access
  const isDemo = process.env.NODE_ENV === 'development' || process.env.NEXT_PUBLIC_DEMO_MODE === 'true'
  
  if (!isDemo && status === 'loading') {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary"></div>
      </div>
    )
  }

  if (!isDemo && !session) {
    return null
  }

  return (
    <div className="h-screen flex overflow-hidden bg-background">
      {/* Sidebar */}
      <Sidebar
        open={sidebarOpen}
        collapsed={sidebarCollapsed}
        onOpenChange={setSidebarOpen}
        onCollapsedChange={setSidebarCollapsed}
      />

      {/* Main content */}
      <div className="flex flex-col flex-1 overflow-hidden">
        {/* Header */}
        <Header
          onMenuClick={() => setSidebarOpen(true)}
          sidebarCollapsed={sidebarCollapsed}
        />

        {/* Main content area */}
        <main className="flex-1 overflow-y-auto">
          <div className={cn(
            "transition-all duration-300",
            sidebarCollapsed ? "lg:pl-16" : "lg:pl-64"
          )}>
            {/* Breadcrumbs */}
            <div className="border-b bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/60">
              <div className="px-6 py-4">
                <Breadcrumbs />
              </div>
            </div>

            {/* Page content */}
            <div className="p-6">
              {children}
            </div>
          </div>
        </main>
      </div>

      {/* Mobile sidebar overlay */}
      {sidebarOpen && (
        <div
          className="fixed inset-0 z-20 bg-black bg-opacity-50 lg:hidden"
          onClick={() => setSidebarOpen(false)}
        />
      )}
    </div>
  )
}

// Skeleton component to prevent hydration mismatches
function DashboardSkeleton() {
  return (
    <div className="h-screen flex overflow-hidden bg-background">
      {/* Sidebar skeleton */}
      <div className="hidden lg:flex lg:flex-shrink-0">
        <div className="flex flex-col w-64">
          <div className="flex flex-col flex-grow border-r bg-background pt-5 pb-4 overflow-y-auto">
            <div className="flex items-center flex-shrink-0 px-4">
              <Skeleton className="h-8 w-32" />
            </div>
            <div className="mt-8 flex-grow flex flex-col">
              <nav className="flex-1 px-2 space-y-1">
                {Array.from({ length: 6 }).map((_, i) => (
                  <Skeleton key={i} className="h-10 w-full" />
                ))}
              </nav>
            </div>
          </div>
        </div>
      </div>

      {/* Main content skeleton */}
      <div className="flex flex-col flex-1 overflow-hidden">
        {/* Header skeleton */}
        <div className="relative z-10 flex-shrink-0 flex h-16 bg-background border-b">
          <div className="flex-1 px-4 flex justify-between items-center">
            <Skeleton className="h-8 w-48" />
            <div className="flex items-center space-x-2">
              <Skeleton className="h-8 w-8 rounded-full" />
              <Skeleton className="h-8 w-20" />
            </div>
          </div>
        </div>

        {/* Main content area skeleton */}
        <main className="flex-1 overflow-y-auto">
          <div className="p-6">
            <div className="space-y-6">
              <Skeleton className="h-8 w-64" />
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                {Array.from({ length: 4 }).map((_, i) => (
                  <Skeleton key={i} className="h-32 w-full" />
                ))}
              </div>
              <Skeleton className="h-96 w-full" />
            </div>
          </div>
        </main>
      </div>
    </div>
  )
}