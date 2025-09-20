'use client'

import { useState, useMemo, Suspense } from 'react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Skeleton } from '@/components/ui/skeleton'
import { Alert, AlertDescription } from '@/components/ui/alert'
import {
  LineChart,
  Line,
  AreaChart,
  Area,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
} from 'recharts'
import { 
  Calendar, 
  Download, 
  TrendingUp, 
  DollarSign,
  Users,
  MousePointer,
  Target,
  AlertCircle,
  RefreshCw
} from 'lucide-react'
import { formatCurrency, formatNumber } from '@/lib/utils'
import { useAdAccounts, useSelectedAccount } from '@/hooks/api/use-ad-accounts'
import { useCampaigns } from '@/hooks/api/use-campaigns'
import { ErrorBoundary } from '@/components/error-boundary'

// Define time range options
const timeRangeOptions = [
  { label: 'Last 7 days', value: '7d', since: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString().split('T')[0] },
  { label: 'Last 30 days', value: '30d', since: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString().split('T')[0] },
  { label: 'Last 90 days', value: '90d', since: new Date(Date.now() - 90 * 24 * 60 * 60 * 1000).toISOString().split('T')[0] },
]

// Mock data for demo purposes (when no real data is available)
const mockPerformanceData = [
  { date: '2024-01-01', spend: 1200, revenue: 4800, clicks: 180, conversions: 12 },
  { date: '2024-01-02', spend: 1350, revenue: 5400, clicks: 195, conversions: 15 },
  { date: '2024-01-03', spend: 1100, revenue: 4200, clicks: 165, conversions: 10 },
  { date: '2024-01-04', spend: 1450, revenue: 6100, clicks: 220, conversions: 18 },
  { date: '2024-01-05', spend: 1600, revenue: 6800, clicks: 245, conversions: 22 },
  { date: '2024-01-06', spend: 1300, revenue: 5500, clicks: 200, conversions: 16 },
  { date: '2024-01-07', spend: 1750, revenue: 7200, clicks: 280, conversions: 25 },
]

const campaignPerformance = [
  { name: 'Summer Sale', spend: 3200, conversions: 45, roas: 4.2, status: 'active' },
  { name: 'Brand Awareness', spend: 2800, conversions: 32, roas: 3.8, status: 'active' },
  { name: 'Holiday Promo', spend: 4100, conversions: 58, roas: 5.1, status: 'active' },
  { name: 'Product Launch', spend: 2200, conversions: 28, roas: 3.5, status: 'paused' },
  { name: 'Retargeting', spend: 1800, conversions: 35, roas: 6.2, status: 'active' },
]

const audienceData = [
  { name: '18-24', value: 25, color: '#3B82F6' },
  { name: '25-34', value: 35, color: '#10B981' },
  { name: '35-44', value: 20, color: '#F59E0B' },
  { name: '45-54', value: 15, color: '#EF4444' },
  { name: '55+', value: 5, color: '#8B5CF6' },
]

const deviceData = [
  { name: 'Mobile', spend: 6500, conversions: 120, color: '#3B82F6' },
  { name: 'Desktop', spend: 4200, conversions: 85, color: '#10B981' },
  { name: 'Tablet', spend: 1750, conversions: 23, color: '#F59E0B' },
]

function CustomTooltip({ active, payload, label }: any) {
  if (active && payload && payload.length) {
    return (
      <div className="bg-background border rounded-lg shadow-lg p-3">
        <p className="text-sm font-medium">{label}</p>
        {payload.map((entry: any, index: number) => (
          <p key={index} className="text-sm" style={{ color: entry.color }}>
            {entry.name}: {
              entry.name.includes('spend') || entry.name.includes('revenue') 
                ? formatCurrency(entry.value)
                : formatNumber(entry.value)
            }
          </p>
        ))}
      </div>
    )
  }
  return null
}

export function DashboardOverview() {
  const [selectedTimeframe, setSelectedTimeframe] = useState('7d')
  
  // Get selected ad account and campaigns
  const { data: selectedAccount, isLoading: accountLoading } = useSelectedAccount()
  const { 
    data: campaignsData, 
    isLoading: campaignsLoading, 
    error: campaignsError,
    refetch: refetchCampaigns 
  } = useCampaigns({
    accountId: selectedAccount?.id || '',
    enabled: !!selectedAccount?.id,
  })

  // Calculate performance data from real campaigns or use demo data
  const performanceData = useMemo(() => {
    if (campaignsData?.data && campaignsData.data.length > 0) {
      // Transform real campaign data to chart format
      return transformCampaignDataToChartData(campaignsData.data)
    }
    return mockPerformanceData
  }, [campaignsData])

  // Get current time range
  const currentTimeRange = timeRangeOptions.find(option => option.value === selectedTimeframe)
  const isDemo = !selectedAccount || !campaignsData?.data?.length

  return (
    <ErrorBoundary>
      <div className="space-y-6 animate-in">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-xl font-semibold">Analytics Overview</h2>
            <p className="text-sm text-muted-foreground">
              {selectedAccount ? `Account: ${selectedAccount.name}` : 'Select an ad account to view performance'}
              {isDemo && <Badge variant="secondary" className="ml-2 text-xs">Demo Data</Badge>}
            </p>
          </div>
          <div className="flex items-center space-x-2">
            <select
              value={selectedTimeframe}
              onChange={(e) => setSelectedTimeframe(e.target.value)}
              className="px-3 py-1 text-sm border border-border rounded-md bg-background"
            >
              {timeRangeOptions.map((option) => (
                <option key={option.value} value={option.value}>
                  {option.label}
                </option>
              ))}
            </select>
            <Button variant="outline" size="sm" onClick={() => refetchCampaigns()}>
              <RefreshCw className="h-4 w-4 mr-2" />
              <span>Refresh</span>
            </Button>
            <Button variant="outline" size="sm">
              <Download className="h-4 w-4 mr-2" />
              <span>Export</span>
            </Button>
          </div>
        </div>

        {/* Loading and Error States */}
        {accountLoading && <DashboardSkeleton />}
        
        {campaignsError && (
          <Alert variant="destructive">
            <AlertCircle className="h-4 w-4" />
            <AlertDescription>
              Failed to load campaign data: {campaignsError.message}
              <Button variant="outline" size="sm" className="ml-2" onClick={() => refetchCampaigns()}>
                Try Again
              </Button>
            </AlertDescription>
          </Alert>
        )}

        {!accountLoading && selectedAccount && (
          <Suspense fallback={<DashboardSkeleton />}>
            <DashboardContent 
              performanceData={performanceData}
              campaignsData={campaignsData}
              isDemo={isDemo}
              isLoading={campaignsLoading}
            />
          </Suspense>
        )}

        {!accountLoading && !selectedAccount && (
          <Card>
            <CardContent className="flex flex-col items-center justify-center py-12">
              <Target className="h-12 w-12 text-muted-foreground mb-4" />
              <h3 className="text-lg font-semibold mb-2">No Ad Account Selected</h3>
              <p className="text-muted-foreground text-center mb-4">
                Please select an ad account to view your campaign performance and analytics.
              </p>
              <Button variant="outline">
                Select Ad Account
              </Button>
            </CardContent>
          </Card>
        )}
      </div>
    </ErrorBoundary>
  )
}

// Separate component for dashboard content to improve performance
function DashboardContent({ 
  performanceData, 
  campaignsData, 
  isDemo, 
  isLoading 
}: {
  performanceData: any[]
  campaignsData: any
  isDemo: boolean
  isLoading: boolean
}) {
  if (isLoading) {
    return <DashboardSkeleton />
  }

  const campaignPerformance = transformCampaignsToPerformanceData(campaignsData?.data || [])

  return (
    <>
      {/* KPI Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <MetricCard
          title="Total Spend"
          value={formatCurrency(calculateTotalSpend(performanceData))}
          change="+12.5%"
          changeType="positive"
          icon={DollarSign}
        />
        <MetricCard
          title="Conversions"
          value={formatNumber(calculateTotalConversions(performanceData))}
          change="+8.2%"
          changeType="positive"
          icon={Target}
        />
        <MetricCard
          title="Clicks"
          value={formatNumber(calculateTotalClicks(performanceData))}
          change="+15.3%"
          changeType="positive"
          icon={MousePointer}
        />
        <MetricCard
          title="ROAS"
          value={calculateROAS(performanceData).toFixed(2) + 'x'}
          change="+5.7%"
          changeType="positive"
          icon={TrendingUp}
        />
      </div>

      {/* Main Charts */}
      <Tabs defaultValue="performance" className="space-y-4">
        <TabsList className="grid w-full grid-cols-4">
          <TabsTrigger value="performance">Performance</TabsTrigger>
          <TabsTrigger value="campaigns">Campaigns</TabsTrigger>
          <TabsTrigger value="audience">Audience</TabsTrigger>
          <TabsTrigger value="devices">Devices</TabsTrigger>
        </TabsList>

        <TabsContent value="performance" className="space-y-4">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            {/* Spend vs Revenue */}
            <Card>
              <CardHeader>
                <CardTitle className="text-base">Spend vs Revenue</CardTitle>
                <CardDescription>
                  Daily comparison of ad spend and generated revenue
                </CardDescription>
              </CardHeader>
              <CardContent>
                <ResponsiveContainer width="100%" height={300}>
                  <AreaChart data={performanceData}>
                    <CartesianGrid strokeDasharray="3 3" />
                    <XAxis 
                      dataKey="date" 
                      tickFormatter={(value) => new Date(value).getDate().toString()}
                    />
                    <YAxis tickFormatter={(value) => `$${value}`} />
                    <Tooltip content={<CustomTooltip />} />
                    <Area 
                      type="monotone" 
                      dataKey="revenue" 
                      stackId="1"
                      stroke="#10B981" 
                      fill="#10B981"
                      fillOpacity={0.6}
                    />
                    <Area 
                      type="monotone" 
                      dataKey="spend" 
                      stackId="2"
                      stroke="#EF4444" 
                      fill="#EF4444"
                      fillOpacity={0.6}
                    />
                  </AreaChart>
                </ResponsiveContainer>
              </CardContent>
            </Card>

            {/* Clicks and Conversions */}
            <Card>
              <CardHeader>
                <CardTitle className="text-base">Clicks & Conversions</CardTitle>
                <CardDescription>
                  Track user engagement and conversion trends
                </CardDescription>
              </CardHeader>
              <CardContent>
                <ResponsiveContainer width="100%" height={300}>
                  <LineChart data={performanceData}>
                    <CartesianGrid strokeDasharray="3 3" />
                    <XAxis 
                      dataKey="date" 
                      tickFormatter={(value) => new Date(value).getDate().toString()}
                    />
                    <YAxis />
                    <Tooltip content={<CustomTooltip />} />
                    <Line 
                      type="monotone" 
                      dataKey="clicks" 
                      stroke="#3B82F6" 
                      strokeWidth={2}
                      dot={{ fill: '#3B82F6', strokeWidth: 2, r: 4 }}
                    />
                    <Line 
                      type="monotone" 
                      dataKey="conversions" 
                      stroke="#F59E0B" 
                      strokeWidth={2}
                      dot={{ fill: '#F59E0B', strokeWidth: 2, r: 4 }}
                    />
                  </LineChart>
                </ResponsiveContainer>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        <TabsContent value="campaigns" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="text-base">Campaign Performance</CardTitle>
              <CardDescription>
                Compare performance across your active campaigns
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                <ResponsiveContainer width="100%" height={300}>
                  <BarChart data={campaignPerformance}>
                    <CartesianGrid strokeDasharray="3 3" />
                    <XAxis dataKey="name" />
                    <YAxis />
                    <Tooltip content={<CustomTooltip />} />
                    <Bar dataKey="spend" fill="#3B82F6" />
                    <Bar dataKey="conversions" fill="#10B981" />
                  </BarChart>
                </ResponsiveContainer>

                {/* Campaign List */}
                <div className="space-y-2">
                  {campaignPerformance.map((campaign) => (
                    <div key={campaign.name} className="flex items-center justify-between p-3 border rounded-lg">
                      <div className="flex items-center space-x-3">
                        <div>
                          <p className="font-medium text-sm">{campaign.name}</p>
                          <div className="flex items-center space-x-2">
                            <Badge 
                              variant={campaign.status === 'active' ? 'default' : 'secondary'}
                              className="text-xs"
                            >
                              {campaign.status}
                            </Badge>
                            <span className="text-xs text-muted-foreground">
                              ROAS: {campaign.roas}x
                            </span>
                          </div>
                        </div>
                      </div>
                      <div className="text-right">
                        <p className="text-sm font-medium">{formatCurrency(campaign.spend)}</p>
                        <p className="text-xs text-muted-foreground">
                          {campaign.conversions} conversions
                        </p>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="audience" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="text-base">Audience Demographics</CardTitle>
              <CardDescription>
                Age distribution of your audience
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="flex items-center space-x-8">
                <ResponsiveContainer width={300} height={300}>
                  <PieChart>
                    <Pie
                      data={audienceData}
                      cx="50%"
                      cy="50%"
                      outerRadius={100}
                      fill="#8884d8"
                      dataKey="value"
                      label={({ name, value }) => `${name}: ${value}%`}
                    >
                      {audienceData.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={entry.color} />
                      ))}
                    </Pie>
                    <Tooltip />
                  </PieChart>
                </ResponsiveContainer>
                
                <div className="space-y-2">
                  {audienceData.map((item) => (
                    <div key={item.name} className="flex items-center space-x-2">
                      <div 
                        className="w-4 h-4 rounded"
                        style={{ backgroundColor: item.color }}
                      />
                      <span className="text-sm">{item.name}</span>
                      <span className="text-sm font-medium">{item.value}%</span>
                    </div>
                  ))}
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="devices" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="text-base">Device Performance</CardTitle>
              <CardDescription>
                Performance breakdown by device type
              </CardDescription>
            </CardHeader>
            <CardContent>
              <ResponsiveContainer width="100%" height={300}>
                <BarChart data={deviceData} layout="horizontal">
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis type="number" />
                  <YAxis dataKey="name" type="category" />
                  <Tooltip content={<CustomTooltip />} />
                  <Bar dataKey="spend" fill="#3B82F6" />
                  <Bar dataKey="conversions" fill="#10B981" />
                </BarChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </>
  )
}

// Utility functions for data transformation
function transformCampaignDataToChartData(campaigns: any[]) {
  // Transform Meta campaigns data to chart format
  // This would typically process insights data
  return mockPerformanceData // Fallback to mock for now
}

function transformCampaignsToPerformanceData(campaigns: any[]) {
  // Transform campaigns to performance table format
  if (!campaigns.length) {
    return [
      { name: 'Summer Sale', spend: 3200, conversions: 45, roas: 4.2, status: 'active' },
      { name: 'Brand Awareness', spend: 2800, conversions: 32, roas: 3.8, status: 'active' },
      { name: 'Holiday Promo', spend: 4100, conversions: 58, roas: 5.1, status: 'active' },
    ]
  }
  
  return campaigns.map(campaign => ({
    name: campaign.name,
    spend: Math.random() * 5000, // Would be from insights
    conversions: Math.random() * 50,
    roas: 2 + Math.random() * 4,
    status: campaign.status === 'ACTIVE' ? 'active' : 'paused',
  }))
}

function calculateTotalSpend(data: any[]) {
  return data.reduce((total, item) => total + (item.spend || 0), 0)
}

function calculateTotalConversions(data: any[]) {
  return data.reduce((total, item) => total + (item.conversions || 0), 0)
}

function calculateTotalClicks(data: any[]) {
  return data.reduce((total, item) => total + (item.clicks || 0), 0)
}

function calculateROAS(data: any[]) {
  const totalSpend = calculateTotalSpend(data)
  const totalRevenue = data.reduce((total, item) => total + (item.revenue || 0), 0)
  return totalSpend > 0 ? totalRevenue / totalSpend : 0
}

// Metric Card Component
interface MetricCardProps {
  title: string
  value: string
  change: string
  changeType: 'positive' | 'negative' | 'neutral'
  icon: React.ComponentType<{ className?: string }>
}

function MetricCard({ title, value, change, changeType, icon: Icon }: MetricCardProps) {
  const changeColor = {
    positive: 'text-green-600',
    negative: 'text-red-600',
    neutral: 'text-gray-600',
  }[changeType]

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
        <CardTitle className="text-sm font-medium">{title}</CardTitle>
        <Icon className="h-4 w-4 text-muted-foreground" />
      </CardHeader>
      <CardContent>
        <div className="text-2xl font-bold">{value}</div>
        <p className={`text-xs ${changeColor}`}>
          {change} from last period
        </p>
      </CardContent>
    </Card>
  )
}

// Dashboard Skeleton Component
function DashboardSkeleton() {
  return (
    <div className="space-y-6">
      {/* KPI Cards Skeleton */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {Array.from({ length: 4 }).map((_, i) => (
          <Card key={i}>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <Skeleton className="h-4 w-20" />
              <Skeleton className="h-4 w-4" />
            </CardHeader>
            <CardContent>
              <Skeleton className="h-8 w-16 mb-2" />
              <Skeleton className="h-3 w-24" />
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Charts Skeleton */}
      <Card>
        <CardHeader>
          <div className="flex justify-between items-center">
            <div>
              <Skeleton className="h-6 w-40 mb-2" />
              <Skeleton className="h-4 w-60" />
            </div>
            <div className="flex space-x-2">
              {Array.from({ length: 4 }).map((_, i) => (
                <Skeleton key={i} className="h-8 w-20" />
              ))}
            </div>
          </div>
        </CardHeader>
        <CardContent>
          <Skeleton className="h-80 w-full" />
        </CardContent>
      </Card>
    </div>
  )
}