'use client'

import { useState } from 'react'
import { useSession } from 'next-auth/react'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import * as z from 'zod'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Progress } from '@/components/ui/progress'
import { Checkbox } from '@/components/ui/checkbox'
import { Avatar, AvatarFallback, AvatarImage } from '@/components/ui/avatar'
import {
  Form,
  FormControl,
  FormDescription,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from '@/components/ui/form'
import {
  Facebook,
  CheckCircle,
  ArrowRight,
  ArrowLeft,
  Settings,
  Zap,
  Target,
  BarChart3,
  Shield,
  Loader2,
} from 'lucide-react'
import { toast } from 'sonner'
import { useAuthStore } from '@/store/auth-store'

interface PageConnectionWizardProps {
  open: boolean
  onOpenChange: (open: boolean) => void
}

const steps = [
  {
    id: 1,
    title: 'Facebook Permissions',
    description: 'Grant necessary permissions to access your Facebook pages',
  },
  {
    id: 2,
    title: 'Select Pages',
    description: 'Choose which pages you want to connect',
  },
  {
    id: 3,
    title: 'Configuration',
    description: 'Configure settings for your connected pages',
  },
  {
    id: 4,
    title: 'Confirmation',
    description: 'Review and confirm your page connections',
  },
]

const configSchema = z.object({
  autoOptimization: z.boolean().default(true),
  performanceAlerts: z.boolean().default(true),
  weeklyReports: z.boolean().default(false),
  budgetThreshold: z.number().min(1).max(100).default(80),
})

type ConfigFormData = z.infer<typeof configSchema>

// Mock pages data - in real app, this would come from Facebook API
const mockPages = [
  {
    id: '123456789',
    name: 'Awesome Business',
    category: 'Business',
    followerCount: 12500,
    picture: 'https://via.placeholder.com/100',
    isEligible: true,
    permissions: ['pages_read_engagement', 'ads_read'],
  },
  {
    id: '987654321',
    name: 'Creative Agency',
    category: 'Marketing Agency',
    followerCount: 8200,
    picture: 'https://via.placeholder.com/100',
    isEligible: true,
    permissions: ['pages_read_engagement', 'ads_read', 'pages_manage_ads'],
  },
  {
    id: '456789123',
    name: 'Local Restaurant',
    category: 'Restaurant',
    followerCount: 3400,
    picture: 'https://via.placeholder.com/100',
    isEligible: false,
    permissions: ['pages_read_engagement'],
  },
]

export function PageConnectionWizard({ open, onOpenChange }: PageConnectionWizardProps) {
  const [currentStep, setCurrentStep] = useState(1)
  const [selectedPages, setSelectedPages] = useState<string[]>([])
  const [isLoading, setIsLoading] = useState(false)
  const { data: session } = useSession()
  const { addConnectedPage } = useAuthStore()

  const form = useForm<ConfigFormData>({
    resolver: zodResolver(configSchema),
    defaultValues: {
      autoOptimization: true,
      performanceAlerts: true,
      weeklyReports: false,
      budgetThreshold: 80,
    },
  })

  const handleNext = () => {
    if (currentStep < steps.length) {
      setCurrentStep(currentStep + 1)
    }
  }

  const handleBack = () => {
    if (currentStep > 1) {
      setCurrentStep(currentStep - 1)
    }
  }

  const handlePageToggle = (pageId: string) => {
    setSelectedPages(prev =>
      prev.includes(pageId)
        ? prev.filter(id => id !== pageId)
        : [...prev, pageId]
    )
  }

  const handleFinish = async (data: ConfigFormData) => {
    setIsLoading(true)
    
    try {
      // Simulate API call to connect pages
      await new Promise(resolve => setTimeout(resolve, 2000))
      
      // Add connected pages to store
      selectedPages.forEach(pageId => {
        const page = mockPages.find(p => p.id === pageId)
        if (page) {
          addConnectedPage({
            id: page.id,
            name: page.name,
            category: page.category,
            category_list: [{ id: '1', name: page.category }],
            access_token: 'mock_token',
            tasks: page.permissions,
            picture: {
              data: {
                height: 100,
                is_silhouette: false,
                url: page.picture,
                width: 100,
              },
            },
            fan_count: page.followerCount,
          })
        }
      })

      toast.success('Pages connected successfully!', {
        description: `${selectedPages.length} page(s) have been connected to your account.`,
      })

      // Reset form and close wizard
      setCurrentStep(1)
      setSelectedPages([])
      form.reset()
      onOpenChange(false)
    } catch (error) {
      toast.error('Failed to connect pages', {
        description: 'Please try again or contact support if the problem persists.',
      })
    } finally {
      setIsLoading(false)
    }
  }

  const renderStepContent = () => {
    switch (currentStep) {
      case 1:
        return (
          <div className="space-y-6">
            <div className="text-center space-y-4">
              <div className="mx-auto w-16 h-16 bg-facebook rounded-full flex items-center justify-center">
                <Facebook className="w-8 h-8 text-white" />
              </div>
              <div>
                <h3 className="text-lg font-semibold">Connect to Facebook</h3>
                <p className="text-sm text-muted-foreground">
                  We need permission to access your Facebook pages and advertising data
                </p>
              </div>
            </div>

            <div className="space-y-3">
              <div className="flex items-center space-x-3 p-3 border rounded-lg">
                <CheckCircle className="w-5 h-5 text-green-500" />
                <div>
                  <p className="text-sm font-medium">Read page information</p>
                  <p className="text-xs text-muted-foreground">
                    Access basic page details and follower count
                  </p>
                </div>
              </div>
              
              <div className="flex items-center space-x-3 p-3 border rounded-lg">
                <CheckCircle className="w-5 h-5 text-green-500" />
                <div>
                  <p className="text-sm font-medium">View advertising insights</p>
                  <p className="text-xs text-muted-foreground">
                    Access campaign performance and analytics data
                  </p>
                </div>
              </div>
              
              <div className="flex items-center space-x-3 p-3 border rounded-lg">
                <CheckCircle className="w-5 h-5 text-green-500" />
                <div>
                  <p className="text-sm font-medium">Manage ads (optional)</p>
                  <p className="text-xs text-muted-foreground">
                    Create and modify advertising campaigns
                  </p>
                </div>
              </div>
            </div>

            <div className="bg-muted p-4 rounded-lg">
              <div className="flex items-start space-x-2">
                <Shield className="w-5 h-5 text-blue-500 mt-0.5" />
                <div>
                  <p className="text-sm font-medium">Your data is secure</p>
                  <p className="text-xs text-muted-foreground">
                    We only access the data necessary for analytics and campaign management. 
                    Your personal information remains private.
                  </p>
                </div>
              </div>
            </div>
          </div>
        )

      case 2:
        return (
          <div className="space-y-4">
            <div>
              <h3 className="text-lg font-semibold">Select Pages to Connect</h3>
              <p className="text-sm text-muted-foreground">
                Choose which Facebook pages you want to manage through our platform
              </p>
            </div>

            <div className="space-y-3 max-h-96 overflow-y-auto">
              {mockPages.map((page) => (
                <Card 
                  key={page.id} 
                  className={`cursor-pointer transition-colors ${
                    selectedPages.includes(page.id) ? 'ring-2 ring-primary' : ''
                  } ${!page.isEligible ? 'opacity-50' : ''}`}
                  onClick={() => page.isEligible && handlePageToggle(page.id)}
                >
                  <CardContent className="p-4">
                    <div className="flex items-center space-x-4">
                      <Avatar className="w-12 h-12">
                        <AvatarImage src={page.picture} alt={page.name} />
                        <AvatarFallback>{page.name.charAt(0)}</AvatarFallback>
                      </Avatar>
                      
                      <div className="flex-1">
                        <div className="flex items-center space-x-2">
                          <h4 className="font-medium">{page.name}</h4>
                          {!page.isEligible && (
                            <Badge variant="destructive" className="text-xs">
                              Insufficient permissions
                            </Badge>
                          )}
                        </div>
                        <p className="text-sm text-muted-foreground">{page.category}</p>
                        <p className="text-xs text-muted-foreground">
                          {page.followerCount.toLocaleString()} followers
                        </p>
                      </div>
                      
                      {page.isEligible && (
                        <Checkbox
                          checked={selectedPages.includes(page.id)}
                          onCheckedChange={() => handlePageToggle(page.id)}
                        />
                      )}
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>

            {selectedPages.length > 0 && (
              <div className="bg-muted p-3 rounded-lg">
                <p className="text-sm font-medium">
                  {selectedPages.length} page(s) selected
                </p>
              </div>
            )}
          </div>
        )

      case 3:
        return (
          <div className="space-y-6">
            <div>
              <h3 className="text-lg font-semibold">Configure Settings</h3>
              <p className="text-sm text-muted-foreground">
                Set up preferences for your connected pages
              </p>
            </div>

            <Form {...form}>
              <div className="space-y-4">
                <FormField
                  control={form.control}
                  name="autoOptimization"
                  render={({ field }) => (
                    <FormItem className="flex flex-row items-start space-x-3 space-y-0 rounded-md border p-4">
                      <FormControl>
                        <Checkbox
                          checked={field.value}
                          onCheckedChange={field.onChange}
                        />
                      </FormControl>
                      <div className="space-y-1 leading-none">
                        <FormLabel className="flex items-center space-x-2">
                          <Zap className="w-4 h-4" />
                          <span>Enable AI Auto-Optimization</span>
                        </FormLabel>
                        <FormDescription>
                          Allow our AI to automatically optimize your campaigns for better performance
                        </FormDescription>
                      </div>
                    </FormItem>
                  )}
                />

                <FormField
                  control={form.control}
                  name="performanceAlerts"
                  render={({ field }) => (
                    <FormItem className="flex flex-row items-start space-x-3 space-y-0 rounded-md border p-4">
                      <FormControl>
                        <Checkbox
                          checked={field.value}
                          onCheckedChange={field.onChange}
                        />
                      </FormControl>
                      <div className="space-y-1 leading-none">
                        <FormLabel className="flex items-center space-x-2">
                          <Target className="w-4 h-4" />
                          <span>Performance Alerts</span>
                        </FormLabel>
                        <FormDescription>
                          Get notified when campaigns exceed budget or underperform
                        </FormDescription>
                      </div>
                    </FormItem>
                  )}
                />

                <FormField
                  control={form.control}
                  name="weeklyReports"
                  render={({ field }) => (
                    <FormItem className="flex flex-row items-start space-x-3 space-y-0 rounded-md border p-4">
                      <FormControl>
                        <Checkbox
                          checked={field.value}
                          onCheckedChange={field.onChange}
                        />
                      </FormControl>
                      <div className="space-y-1 leading-none">
                        <FormLabel className="flex items-center space-x-2">
                          <BarChart3 className="w-4 h-4" />
                          <span>Weekly Performance Reports</span>
                        </FormLabel>
                        <FormDescription>
                          Receive automated weekly reports via email
                        </FormDescription>
                      </div>
                    </FormItem>
                  )}
                />
              </div>
            </Form>
          </div>
        )

      case 4:
        return (
          <div className="space-y-6">
            <div className="text-center">
              <CheckCircle className="mx-auto w-16 h-16 text-green-500" />
              <h3 className="text-lg font-semibold mt-4">Ready to Connect!</h3>
              <p className="text-sm text-muted-foreground">
                Review your selections and confirm to complete the setup
              </p>
            </div>

            <div className="space-y-4">
              <div>
                <h4 className="font-medium mb-2">Selected Pages ({selectedPages.length})</h4>
                <div className="space-y-2">
                  {selectedPages.map(pageId => {
                    const page = mockPages.find(p => p.id === pageId)
                    return page ? (
                      <div key={pageId} className="flex items-center space-x-3 p-2 border rounded">
                        <Avatar className="w-8 h-8">
                          <AvatarImage src={page.picture} alt={page.name} />
                          <AvatarFallback>{page.name.charAt(0)}</AvatarFallback>
                        </Avatar>
                        <div>
                          <p className="text-sm font-medium">{page.name}</p>
                          <p className="text-xs text-muted-foreground">{page.category}</p>
                        </div>
                      </div>
                    ) : null
                  })}
                </div>
              </div>

              <div>
                <h4 className="font-medium mb-2">Configuration</h4>
                <div className="text-sm space-y-1">
                  <p>Auto-optimization: {form.getValues('autoOptimization') ? 'Enabled' : 'Disabled'}</p>
                  <p>Performance alerts: {form.getValues('performanceAlerts') ? 'Enabled' : 'Disabled'}</p>
                  <p>Weekly reports: {form.getValues('weeklyReports') ? 'Enabled' : 'Disabled'}</p>
                </div>
              </div>
            </div>
          </div>
        )

      default:
        return null
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-2xl max-h-[90vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle>Connect Facebook Pages</DialogTitle>
          <DialogDescription>
            Step {currentStep} of {steps.length}: {steps[currentStep - 1]?.description}
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-6">
          {/* Progress bar */}
          <div className="space-y-2">
            <Progress value={(currentStep / steps.length) * 100} />
            <div className="flex justify-between text-xs text-muted-foreground">
              {steps.map((step) => (
                <span
                  key={step.id}
                  className={currentStep >= step.id ? 'text-primary font-medium' : ''}
                >
                  {step.title}
                </span>
              ))}
            </div>
          </div>

          {/* Step content */}
          <div className="min-h-[400px]">
            {renderStepContent()}
          </div>

          {/* Navigation buttons */}
          <div className="flex justify-between">
            <Button
              variant="outline"
              onClick={handleBack}
              disabled={currentStep === 1}
              leftIcon={<ArrowLeft className="w-4 h-4" />}
            >
              Back
            </Button>

            {currentStep < steps.length ? (
              <Button
                onClick={handleNext}
                disabled={currentStep === 2 && selectedPages.length === 0}
                rightIcon={<ArrowRight className="w-4 h-4" />}
              >
                Next
              </Button>
            ) : (
              <Button
                onClick={form.handleSubmit(handleFinish)}
                disabled={isLoading || selectedPages.length === 0}
                loading={isLoading}
                leftIcon={!isLoading ? <CheckCircle className="w-4 h-4" /> : undefined}
              >
                {isLoading ? 'Connecting...' : 'Connect Pages'}
              </Button>
            )}
          </div>
        </div>
      </DialogContent>
    </Dialog>
  )
}