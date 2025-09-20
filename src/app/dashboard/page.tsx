import { Metadata } from 'next'
import { getServerSession } from 'next-auth'
import { authOptions } from '@/lib/auth'
import { DashboardOverview } from '@/components/dashboard/dashboard-overview'
import { QuickActions } from '@/components/dashboard/quick-actions'
import { RecentActivity } from '@/components/dashboard/recent-activity'
import { PerformanceMetrics } from '@/components/dashboard/performance-metrics'

export const metadata: Metadata = {
  title: 'Dashboard | Meta Ads Intelligence Platform',
  description: 'Your comprehensive Facebook advertising intelligence dashboard',
}

export default async function DashboardPage() {
  const session = await getServerSession(authOptions)
  
  // In demo mode, provide demo user data
  const userName = session?.user?.name?.split(' ')[0] || 'Demo User'

  return (
    <div className="space-y-8">
      {/* Welcome Section */}
      <div className="space-y-2">
        <h1 className="text-3xl font-bold tracking-tight">
          Welcome back, {userName}!
        </h1>
        <p className="text-muted-foreground">
          Here's what's happening with your Facebook advertising campaigns today.
        </p>
      </div>

      {/* Quick Actions */}
      <QuickActions />

      {/* Performance Metrics */}
      <PerformanceMetrics />

      {/* Main Dashboard Content */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        {/* Dashboard Overview - Takes 2 columns */}
        <div className="lg:col-span-2">
          <DashboardOverview />
        </div>

        {/* Recent Activity - Takes 1 column */}
        <div className="lg:col-span-1">
          <RecentActivity />
        </div>
      </div>
    </div>
  )
}