'use client'

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { 
  TrendingUp, 
  TrendingDown, 
  DollarSign, 
  Users, 
  MousePointer, 
  Target,
  Eye,
  Zap
} from 'lucide-react'
import { formatCurrency, formatNumber, formatPercentage } from '@/lib/utils'

interface MetricCardProps {
  title: string
  value: string
  change: number
  changeLabel: string
  icon: React.ReactNode
  description?: string
}

function MetricCard({ title, value, change, changeLabel, icon, description }: MetricCardProps) {
  const isPositive = change > 0
  const TrendIcon = isPositive ? TrendingUp : TrendingDown
  
  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
        <CardTitle className="text-sm font-medium">{title}</CardTitle>
        {icon}
      </CardHeader>
      <CardContent>
        <div className="text-2xl font-bold">{value}</div>
        <div className="flex items-center space-x-2 text-xs text-muted-foreground">
          <div className={`flex items-center space-x-1 ${
            isPositive ? 'text-green-600' : 'text-red-600'
          }`}>
            <TrendIcon className="h-3 w-3" />
            <span>{formatPercentage(Math.abs(change) / 100)}</span>
          </div>
          <span>{changeLabel}</span>
        </div>
        {description && (
          <p className="text-xs text-muted-foreground mt-1">{description}</p>
        )}
      </CardContent>
    </Card>
  )
}

// Mock data - in a real app, this would come from your API
const mockMetrics = {
  totalSpend: 12450.50,
  totalSpendChange: 15.3,
  reach: 148750,
  reachChange: -8.2,
  clicks: 3420,
  clicksChange: 22.1,
  conversions: 186,
  conversionsChange: 12.7,
  ctr: 2.31,
  ctrChange: 8.5,
  roas: 4.2,
  roasChange: 18.9,
  cpc: 3.64,
  cpcChange: -12.3,
  impressions: 245670,
  impressionsChange: 5.7,
}

export function PerformanceMetrics() {
  const metrics = [
    {
      title: 'Total Spend',
      value: formatCurrency(mockMetrics.totalSpend),
      change: mockMetrics.totalSpendChange,
      changeLabel: 'from last month',
      icon: <DollarSign className="h-4 w-4 text-muted-foreground" />,
      description: 'Across all active campaigns',
    },
    {
      title: 'Total Reach',
      value: formatNumber(mockMetrics.reach, 'en-US', 'compact'),
      change: mockMetrics.reachChange,
      changeLabel: 'from last month',
      icon: <Users className="h-4 w-4 text-muted-foreground" />,
      description: 'Unique people reached',
    },
    {
      title: 'Total Clicks',
      value: formatNumber(mockMetrics.clicks),
      change: mockMetrics.clicksChange,
      changeLabel: 'from last month',
      icon: <MousePointer className="h-4 w-4 text-muted-foreground" />,
      description: 'Link clicks and engagements',
    },
    {
      title: 'Conversions',
      value: mockMetrics.conversions.toString(),
      change: mockMetrics.conversionsChange,
      changeLabel: 'from last month',
      icon: <Target className="h-4 w-4 text-muted-foreground" />,
      description: 'Completed purchase actions',
    },
    {
      title: 'Click-Through Rate',
      value: `${mockMetrics.ctr}%`,
      change: mockMetrics.ctrChange,
      changeLabel: 'from last month',
      icon: <MousePointer className="h-4 w-4 text-muted-foreground" />,
      description: 'Average across all campaigns',
    },
    {
      title: 'Return on Ad Spend',
      value: `${mockMetrics.roas}x`,
      change: mockMetrics.roasChange,
      changeLabel: 'from last month',
      icon: <Zap className="h-4 w-4 text-muted-foreground" />,
      description: 'Revenue per dollar spent',
    },
    {
      title: 'Cost Per Click',
      value: formatCurrency(mockMetrics.cpc),
      change: mockMetrics.cpcChange,
      changeLabel: 'from last month',
      icon: <DollarSign className="h-4 w-4 text-muted-foreground" />,
      description: 'Average cost per click',
    },
    {
      title: 'Impressions',
      value: formatNumber(mockMetrics.impressions, 'en-US', 'compact'),
      change: mockMetrics.impressionsChange,
      changeLabel: 'from last month',
      icon: <Eye className="h-4 w-4 text-muted-foreground" />,
      description: 'Total ad impressions',
    },
  ]

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-semibold">Performance Overview</h2>
          <p className="text-sm text-muted-foreground">
            Key metrics from your advertising campaigns
            <Badge variant="secondary" className="ml-2 text-xs">Demo Data</Badge>
          </p>
        </div>
        <Badge variant="outline" className="text-xs">
          Last 30 days
        </Badge>
      </div>
      
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {metrics.map((metric) => (
          <MetricCard
            key={metric.title}
            title={metric.title}
            value={metric.value}
            change={metric.change}
            changeLabel={metric.changeLabel}
            icon={metric.icon}
            description={metric.description}
          />
        ))}
      </div>
    </div>
  )
}