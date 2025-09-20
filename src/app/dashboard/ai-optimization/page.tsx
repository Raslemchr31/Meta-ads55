'use client'

import { useState, useEffect, useCallback } from 'react'
import { useAIInsights } from '@/hooks/use-websocket'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from '@/components/ui/dialog'
import { Progress } from '@/components/ui/progress'
import { Separator } from '@/components/ui/separator'
import { Textarea } from '@/components/ui/textarea'
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
  Legend,
  ResponsiveContainer
} from 'recharts'
import {
  Zap,
  Brain,
  TrendingUp,
  TrendingDown,
  Target,
  DollarSign,
  Users,
  Eye,
  MessageSquare,
  Settings,
  Play,
  Pause,
  RotateCcw,
  CheckCircle2,
  AlertTriangle,
  Clock,
  Sparkles,
  Bot,
  BarChart3,
  PieChart,
  Activity,
  Lightbulb,
  Rocket,
  Shield,
  Cpu,
  Plus
} from 'lucide-react'

interface AIInsight {
  id: string
  type: 'opportunity' | 'warning' | 'suggestion' | 'trend'
  title: string
  description: string
  impact: 'high' | 'medium' | 'low'
  confidence: number
  estimatedImprovement: string
  category: 'bidding' | 'targeting' | 'creative' | 'budget' | 'timing'
  actionable: boolean
  implemented: boolean
}

interface AutomationRule {
  id: string
  name: string
  description: string
  trigger: string
  action: string
  status: 'active' | 'paused' | 'draft'
  impact: number
  frequency: string
  lastTriggered?: string
}

interface Prediction {
  metric: string
  current: number
  predicted: number
  change: number
  confidence: number
  timeframe: string
}

const SAMPLE_INSIGHTS: AIInsight[] = [
  {
    id: '1',
    type: 'opportunity',
    title: 'Increase mobile bid adjustment',
    description: 'Mobile traffic shows 23% higher conversion rate but receives only 15% of budget allocation',
    impact: 'high',
    confidence: 89,
    estimatedImprovement: '+$2,400 monthly revenue',
    category: 'bidding',
    actionable: true,
    implemented: false
  },
  {
    id: '2',
    type: 'warning',
    title: 'Creative fatigue detected',
    description: 'Primary ad creative CTR dropped 18% over the last 7 days, indicating audience fatigue',
    impact: 'medium',
    confidence: 94,
    estimatedImprovement: '+15% CTR with refresh',
    category: 'creative',
    actionable: true,
    implemented: false
  },
  {
    id: '3',
    type: 'suggestion',
    title: 'Optimize ad scheduling',
    description: 'Performance data suggests reducing spend on weekends and increasing Thursday-Friday budget',
    impact: 'medium',
    confidence: 76,
    estimatedImprovement: '+8% ROAS',
    category: 'timing',
    actionable: true,
    implemented: false
  },
  {
    id: '4',
    type: 'trend',
    title: 'Emerging audience segment',
    description: 'AI identified a new high-value audience segment: "Eco-conscious millennials" with 3.2x ROAS',
    impact: 'high',
    confidence: 82,
    estimatedImprovement: '+$1,800 monthly',
    category: 'targeting',
    actionable: true,
    implemented: true
  }
]

const AUTOMATION_RULES: AutomationRule[] = [
  {
    id: '1',
    name: 'Auto-pause low performers',
    description: 'Automatically pause campaigns with CTR below 1% and spend over $100',
    trigger: 'CTR < 1% AND Spend > $100',
    action: 'Pause campaign',
    status: 'active',
    impact: 12,
    frequency: 'Daily',
    lastTriggered: '2024-01-25 14:30'
  },
  {
    id: '2',
    name: 'Increase bids for high ROAS',
    description: 'Increase bids by 20% for campaigns with ROAS above 4.0',
    trigger: 'ROAS > 4.0',
    action: 'Increase bid by 20%',
    status: 'active',
    impact: 8,
    frequency: 'Weekly',
    lastTriggered: '2024-01-22 09:00'
  },
  {
    id: '3',
    name: 'Budget reallocation',
    description: 'Move 10% budget from poor performers to top campaigns',
    trigger: 'Weekly performance review',
    action: 'Reallocate budget',
    status: 'paused',
    impact: 15,
    frequency: 'Weekly'
  }
]

const PREDICTIONS: Prediction[] = [
  { metric: 'ROAS', current: 4.2, predicted: 4.8, change: 14.3, confidence: 87, timeframe: '7 days' },
  { metric: 'CPC', current: 0.68, predicted: 0.59, change: -13.2, confidence: 82, timeframe: '7 days' },
  { metric: 'CVR', current: 2.1, predicted: 2.4, change: 14.3, confidence: 79, timeframe: '7 days' },
  { metric: 'CTR', current: 3.42, predicted: 3.89, change: 13.7, confidence: 84, timeframe: '7 days' }
]

const optimizationData = [
  { date: '2024-01-19', baseline: 4.2, optimized: 4.2, predicted: 4.1 },
  { date: '2024-01-20', baseline: 4.1, optimized: 4.3, predicted: 4.2 },
  { date: '2024-01-21', baseline: 3.9, optimized: 4.4, predicted: 4.3 },
  { date: '2024-01-22', baseline: 4.0, optimized: 4.6, predicted: 4.4 },
  { date: '2024-01-23', baseline: 4.2, optimized: 4.8, predicted: 4.6 },
  { date: '2024-01-24', baseline: 4.1, optimized: 4.9, predicted: 4.8 },
  { date: '2024-01-25', baseline: 4.3, optimized: 5.1, predicted: 5.0 },
]

const getInsightIcon = (type: AIInsight['type']) => {
  switch (type) {
    case 'opportunity': return TrendingUp
    case 'warning': return AlertTriangle
    case 'suggestion': return Lightbulb
    case 'trend': return BarChart3
    default: return Brain
  }
}

const getInsightColor = (type: AIInsight['type']) => {
  switch (type) {
    case 'opportunity': return 'bg-green-100 text-green-700 dark:bg-green-900/20 dark:text-green-400'
    case 'warning': return 'bg-red-100 text-red-700 dark:bg-red-900/20 dark:text-red-400'
    case 'suggestion': return 'bg-blue-100 text-blue-700 dark:bg-blue-900/20 dark:text-blue-400'
    case 'trend': return 'bg-purple-100 text-purple-700 dark:bg-purple-900/20 dark:text-purple-400'
    default: return 'bg-gray-100 text-gray-700 dark:bg-gray-900/20 dark:text-gray-400'
  }
}

export default function AIOptimizationPage() {
  const [insights, setInsights] = useState<AIInsight[]>(SAMPLE_INSIGHTS)
  const [automationRules] = useState<AutomationRule[]>(AUTOMATION_RULES)
  const [selectedInsight, setSelectedInsight] = useState<AIInsight | null>(null)
  const [aiAssistantOpen, setAiAssistantOpen] = useState(false)
  const [chatMessages, setChatMessages] = useState<Array<{role: 'user' | 'assistant', content: string}>>([
    { role: 'assistant', content: 'Hello! I\'m your AI optimization assistant. I can help you understand insights, create automation rules, or answer questions about your campaign performance. How can I help you today?' }
  ])
  const [newMessage, setNewMessage] = useState('')

  // Real-time AI insights
  const handleAIInsight = useCallback((data: any) => {
    const newInsight: AIInsight = {
      id: `insight_${Date.now()}`,
      type: data.type,
      title: data.message,
      description: data.message,
      priority: data.type === 'alert' ? 'high' : 'medium',
      impact: 'medium',
      confidence: Math.random() * 30 + 70,
      estimatedImpact: `${Math.floor(Math.random() * 20) + 5}%`,
      category: data.type === 'optimization' ? 'bidding' : data.type === 'alert' ? 'budget' : 'targeting',
      status: 'pending',
      createdAt: new Date().toISOString().split('T')[0],
      data: data.data || {}
    }

    setInsights(prev => [newInsight, ...prev])

    // Show as chat message too
    setChatMessages(prev => [...prev, {
      role: 'assistant',
      content: `🤖 New ${data.type}: ${data.message}`
    }])
  }, [])

  useAIInsights(handleAIInsight)

  const implementInsight = (insightId: string) => {
    // Implementation logic would go here
    console.log(`Implementing insight: ${insightId}`)
  }

  const sendMessage = () => {
    if (!newMessage.trim()) return

    const userMessage = { role: 'user' as const, content: newMessage }
    setChatMessages(prev => [...prev, userMessage])

    // Simulate AI response
    setTimeout(() => {
      const responses = [
        'Based on your campaign data, I recommend implementing the mobile bid adjustment insight first, as it has the highest potential impact.',
        'I\'ve analyzed your recent performance trends. Would you like me to create an automation rule to help with this?',
        'Great question! Let me break down the key metrics for you...',
        'I can see some optimization opportunities in your targeting strategy. Would you like me to explain?'
      ]
      const response = { role: 'assistant' as const, content: responses[Math.floor(Math.random() * responses.length)] }
      setChatMessages(prev => [...prev, response])
    }, 1000)

    setNewMessage('')
  }

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold flex items-center">
            <Brain className="h-8 w-8 mr-3 text-primary" />
            AI Optimization Center
          </h1>
          <p className="text-muted-foreground">
            Advanced AI-powered campaign optimization and automation
          </p>
        </div>

        <div className="flex items-center space-x-2">
          <Button
            variant="outline"
            onClick={() => setAiAssistantOpen(true)}
          >
            <MessageSquare className="h-4 w-4 mr-2" />
            AI Assistant
          </Button>
          <Button>
            <Settings className="h-4 w-4 mr-2" />
            Settings
          </Button>
        </div>
      </div>

      {/* Overview Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <Card>
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-muted-foreground">AI Insights</p>
                <p className="text-3xl font-bold">{insights.length}</p>
                <p className="text-xs text-green-600">+3 new today</p>
              </div>
              <Brain className="h-8 w-8 text-primary" />
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-muted-foreground">Active Rules</p>
                <p className="text-3xl font-bold">{automationRules.filter(r => r.status === 'active').length}</p>
                <p className="text-xs text-blue-600">Saving 12h weekly</p>
              </div>
              <Zap className="h-8 w-8 text-yellow-500" />
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-muted-foreground">Projected ROAS</p>
                <p className="text-3xl font-bold">4.8x</p>
                <p className="text-xs text-green-600">+14.3% improvement</p>
              </div>
              <TrendingUp className="h-8 w-8 text-green-500" />
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-muted-foreground">Cost Savings</p>
                <p className="text-3xl font-bold">$3.2K</p>
                <p className="text-xs text-green-600">This month</p>
              </div>
              <DollarSign className="h-8 w-8 text-green-500" />
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Main Content */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* AI Insights */}
        <div className="lg:col-span-2 space-y-6">
          {/* Performance Prediction Chart */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center">
                <Activity className="h-5 w-5 mr-2" />
                AI Performance Predictions
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="h-80">
                <ResponsiveContainer width="100%" height="100%">
                  <LineChart data={optimizationData}>
                    <CartesianGrid strokeDasharray="3 3" className="opacity-30" />
                    <XAxis
                      dataKey="date"
                      tickFormatter={(value) => new Date(value).toLocaleDateString('en-US', { month: 'short', day: 'numeric' })}
                    />
                    <YAxis />
                    <Tooltip
                      labelFormatter={(value) => new Date(value).toLocaleDateString()}
                      formatter={(value: number) => [`${value}x`, 'ROAS']}
                    />
                    <Legend />
                    <Line
                      type="monotone"
                      dataKey="baseline"
                      stroke="#94a3b8"
                      strokeWidth={2}
                      name="Baseline"
                      strokeDasharray="5 5"
                    />
                    <Line
                      type="monotone"
                      dataKey="optimized"
                      stroke="#8013ec"
                      strokeWidth={2}
                      name="AI Optimized"
                    />
                    <Line
                      type="monotone"
                      dataKey="predicted"
                      stroke="#22c55e"
                      strokeWidth={2}
                      name="Predicted"
                      strokeDasharray="3 3"
                    />
                  </LineChart>
                </ResponsiveContainer>
              </div>
            </CardContent>
          </Card>

          {/* AI Insights List */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center justify-between">
                <div className="flex items-center">
                  <Lightbulb className="h-5 w-5 mr-2" />
                  AI Insights & Recommendations
                </div>
                <Badge variant="secondary">{insights.filter(i => !i.implemented).length} actionable</Badge>
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {insights.map((insight) => {
                  const Icon = getInsightIcon(insight.type)
                  return (
                    <div
                      key={insight.id}
                      className="border rounded-lg p-4 hover:shadow-md transition-shadow cursor-pointer"
                      onClick={() => setSelectedInsight(insight)}
                    >
                      <div className="flex items-start justify-between mb-3">
                        <div className="flex items-center space-x-3">
                          <div className={`p-2 rounded-full ${getInsightColor(insight.type)}`}>
                            <Icon className="h-4 w-4" />
                          </div>
                          <div>
                            <h3 className="font-semibold">{insight.title}</h3>
                            <p className="text-sm text-muted-foreground">
                              {insight.description}
                            </p>
                          </div>
                        </div>

                        {insight.implemented ? (
                          <CheckCircle2 className="h-5 w-5 text-green-500" />
                        ) : (
                          <Badge variant={insight.impact === 'high' ? 'default' : 'secondary'}>
                            {insight.impact} impact
                          </Badge>
                        )}
                      </div>

                      <div className="flex items-center justify-between">
                        <div className="flex items-center space-x-4 text-sm">
                          <div className="flex items-center space-x-1">
                            <span className="text-muted-foreground">Confidence:</span>
                            <span className="font-medium">{insight.confidence}%</span>
                          </div>
                          <div className="flex items-center space-x-1">
                            <span className="text-muted-foreground">Est. Impact:</span>
                            <span className="font-medium text-green-600">{insight.estimatedImprovement}</span>
                          </div>
                        </div>

                        {!insight.implemented && insight.actionable && (
                          <Button
                            size="sm"
                            onClick={(e) => {
                              e.stopPropagation()
                              implementInsight(insight.id)
                            }}
                          >
                            Implement
                          </Button>
                        )}
                      </div>
                    </div>
                  )
                })}
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Sidebar */}
        <div className="space-y-6">
          {/* Performance Predictions */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center">
                <PieChart className="h-5 w-5 mr-2" />
                7-Day Predictions
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {PREDICTIONS.map((prediction, index) => (
                  <div key={index} className="space-y-2">
                    <div className="flex justify-between items-center">
                      <span className="text-sm font-medium">{prediction.metric}</span>
                      <Badge
                        variant={prediction.change > 0 ? 'default' : 'secondary'}
                        className={prediction.change > 0 ? 'bg-green-100 text-green-700' : 'bg-red-100 text-red-700'}
                      >
                        {prediction.change > 0 ? '+' : ''}{prediction.change.toFixed(1)}%
                      </Badge>
                    </div>
                    <div className="flex justify-between text-sm text-muted-foreground">
                      <span>Current: {prediction.current}</span>
                      <span>Predicted: {prediction.predicted}</span>
                    </div>
                    <div className="flex items-center space-x-2">
                      <Progress value={prediction.confidence} className="flex-1" />
                      <span className="text-xs text-muted-foreground">{prediction.confidence}%</span>
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>

          {/* Automation Rules */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center justify-between">
                <div className="flex items-center">
                  <Cpu className="h-5 w-5 mr-2" />
                  Automation Rules
                </div>
                <Button variant="outline" size="sm">
                  <Plus className="h-4 w-4" />
                </Button>
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-3">
                {automationRules.map((rule) => (
                  <div key={rule.id} className="border rounded-lg p-3">
                    <div className="flex items-start justify-between mb-2">
                      <div>
                        <h4 className="text-sm font-medium">{rule.name}</h4>
                        <p className="text-xs text-muted-foreground line-clamp-2">
                          {rule.description}
                        </p>
                      </div>
                      <Badge
                        variant={rule.status === 'active' ? 'default' : 'secondary'}
                        className={rule.status === 'active' ? 'bg-green-100 text-green-700' : ''}
                      >
                        {rule.status}
                      </Badge>
                    </div>

                    <div className="flex items-center justify-between text-xs">
                      <span className="text-muted-foreground">
                        Impact: {rule.impact}% • {rule.frequency}
                      </span>
                      {rule.lastTriggered && (
                        <span className="text-muted-foreground">
                          Last: {new Date(rule.lastTriggered).toLocaleDateString()}
                        </span>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>

          {/* Quick Actions */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center">
                <Rocket className="h-5 w-5 mr-2" />
                Quick Actions
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-2">
                <Button variant="outline" size="sm" className="w-full justify-start">
                  <Sparkles className="h-4 w-4 mr-2" />
                  Generate AI Recommendations
                </Button>
                <Button variant="outline" size="sm" className="w-full justify-start">
                  <RotateCcw className="h-4 w-4 mr-2" />
                  Refresh Insights
                </Button>
                <Button variant="outline" size="sm" className="w-full justify-start">
                  <Shield className="h-4 w-4 mr-2" />
                  Run Safety Check
                </Button>
                <Button variant="outline" size="sm" className="w-full justify-start">
                  <BarChart3 className="h-4 w-4 mr-2" />
                  Performance Report
                </Button>
              </div>
            </CardContent>
          </Card>
        </div>
      </div>

      {/* AI Assistant Dialog */}
      <Dialog open={aiAssistantOpen} onOpenChange={setAiAssistantOpen}>
        <DialogContent className="max-w-2xl h-[600px] flex flex-col">
          <DialogHeader>
            <DialogTitle className="flex items-center">
              <Bot className="h-5 w-5 mr-2" />
              AI Optimization Assistant
            </DialogTitle>
            <DialogDescription>
              Get personalized recommendations and answers to your optimization questions
            </DialogDescription>
          </DialogHeader>

          {/* Chat Messages */}
          <div className="flex-1 overflow-y-auto space-y-4 p-4 border rounded-lg bg-muted/50">
            {chatMessages.map((message, index) => (
              <div
                key={index}
                className={`flex ${message.role === 'user' ? 'justify-end' : 'justify-start'}`}
              >
                <div
                  className={`max-w-[80%] p-3 rounded-lg ${
                    message.role === 'user'
                      ? 'bg-primary text-primary-foreground'
                      : 'bg-background border'
                  }`}
                >
                  <p className="text-sm">{message.content}</p>
                </div>
              </div>
            ))}
          </div>

          {/* Message Input */}
          <div className="flex space-x-2">
            <Input
              placeholder="Ask me about optimization strategies..."
              value={newMessage}
              onChange={(e) => setNewMessage(e.target.value)}
              onKeyPress={(e) => e.key === 'Enter' && sendMessage()}
              className="flex-1"
            />
            <Button onClick={sendMessage} disabled={!newMessage.trim()}>
              Send
            </Button>
          </div>
        </DialogContent>
      </Dialog>

      {/* Insight Detail Dialog */}
      {selectedInsight && (
        <Dialog open={!!selectedInsight} onOpenChange={() => setSelectedInsight(null)}>
          <DialogContent className="max-w-2xl">
            <DialogHeader>
              <DialogTitle className="flex items-center">
                {(() => {
                  const Icon = getInsightIcon(selectedInsight.type)
                  return <Icon className="h-5 w-5 mr-2" />
                })()}
                {selectedInsight.title}
              </DialogTitle>
              <DialogDescription>
                {selectedInsight.description}
              </DialogDescription>
            </DialogHeader>

            <div className="space-y-4 py-4">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <Label className="text-sm font-medium">Impact Level</Label>
                  <Badge variant="secondary" className="mt-1 capitalize">
                    {selectedInsight.impact}
                  </Badge>
                </div>
                <div>
                  <Label className="text-sm font-medium">Confidence</Label>
                  <div className="flex items-center space-x-2 mt-1">
                    <Progress value={selectedInsight.confidence} className="flex-1" />
                    <span className="text-sm">{selectedInsight.confidence}%</span>
                  </div>
                </div>
                <div>
                  <Label className="text-sm font-medium">Category</Label>
                  <Badge variant="outline" className="mt-1 capitalize">
                    {selectedInsight.category}
                  </Badge>
                </div>
                <div>
                  <Label className="text-sm font-medium">Estimated Impact</Label>
                  <p className="text-sm font-medium text-green-600 mt-1">
                    {selectedInsight.estimatedImprovement}
                  </p>
                </div>
              </div>

              {!selectedInsight.implemented && selectedInsight.actionable && (
                <div className="flex space-x-2 pt-4">
                  <Button onClick={() => implementInsight(selectedInsight.id)}>
                    Implement Now
                  </Button>
                  <Button variant="outline">
                    Schedule Implementation
                  </Button>
                  <Button variant="outline">
                    Learn More
                  </Button>
                </div>
              )}
            </div>
          </DialogContent>
        </Dialog>
      )}
    </div>
  )
}