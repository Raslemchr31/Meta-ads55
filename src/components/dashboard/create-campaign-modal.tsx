'use client'

import { useState } from 'react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { RadioGroup, RadioGroupItem } from '@/components/ui/radio-group'
import { Badge } from '@/components/ui/badge'
import { Progress } from '@/components/ui/progress'
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from '@/components/ui/dialog'
import { ScrollArea } from '@/components/ui/scroll-area'
import {
  Target,
  Users,
  Globe,
  TrendingUp,
  MessageCircle,
  Video,
  CheckCircle2,
  Star,
  Zap,
  Eye,
  Play,
  ArrowRight,
  ArrowLeft
} from 'lucide-react'

const OBJECTIVES = [
  {
    id: 'traffic',
    title: 'Traffic',
    description: 'Drive traffic to your website',
    icon: Globe,
    recommended: true,
  },
  {
    id: 'conversions',
    title: 'Conversions',
    description: 'Drive valuable actions on your website',
    icon: Target,
    recommended: true,
  },
  {
    id: 'lead_generation',
    title: 'Lead Generation',
    description: 'Collect leads for your business',
    icon: Users,
    recommended: true,
  },
  {
    id: 'awareness',
    title: 'Brand Awareness',
    description: 'Increase awareness of your brand',
    icon: Eye,
    recommended: false,
  },
]

const STEPS = [
  'Campaign Details',
  'Audience',
  'Budget & Schedule'
]

interface CreateCampaignModalProps {
  children: React.ReactNode
}

export function CreateCampaignModal({ children }: CreateCampaignModalProps) {
  const [isOpen, setIsOpen] = useState(false)
  const [currentStep, setCurrentStep] = useState(0)
  const [formData, setFormData] = useState({
    campaignName: '',
    objective: 'traffic',
    budget: '50',
    budgetType: 'daily',
  })

  const progress = ((currentStep + 1) / STEPS.length) * 100

  const handleNext = () => {
    if (currentStep < STEPS.length - 1) {
      setCurrentStep(currentStep + 1)
    } else {
      // Handle campaign creation
      console.log('Creating campaign:', formData)
      setIsOpen(false)
      setCurrentStep(0)
    }
  }

  const handleBack = () => {
    if (currentStep > 0) {
      setCurrentStep(currentStep - 1)
    }
  }

  const renderStepContent = () => {
    switch (currentStep) {
      case 0:
        return (
          <div className="space-y-6">
            <div>
              <Label htmlFor="campaignName">Campaign Name *</Label>
              <Input
                id="campaignName"
                placeholder="e.g., Holiday Sale 2024"
                value={formData.campaignName}
                onChange={(e) => setFormData({ ...formData, campaignName: e.target.value })}
                className="mt-1"
              />
            </div>

            <div>
              <Label className="text-base font-medium">Campaign Objective *</Label>
              <RadioGroup
                value={formData.objective}
                onValueChange={(value) => setFormData({ ...formData, objective: value })}
                className="mt-3"
              >
                {OBJECTIVES.map((objective) => {
                  const Icon = objective.icon
                  return (
                    <div
                      key={objective.id}
                      className="flex items-center space-x-3 border rounded-lg p-3 hover:bg-muted/50"
                    >
                      <RadioGroupItem value={objective.id} id={objective.id} />
                      <div className="flex items-center space-x-3 flex-1">
                        <div className="p-2 bg-primary/10 rounded-lg">
                          <Icon className="h-4 w-4 text-primary" />
                        </div>
                        <div className="flex-1">
                          <div className="flex items-center space-x-2">
                            <Label htmlFor={objective.id} className="font-medium cursor-pointer">
                              {objective.title}
                            </Label>
                            {objective.recommended && (
                              <Badge variant="secondary" className="text-xs">
                                <Star className="h-3 w-3 mr-1" />
                                Recommended
                              </Badge>
                            )}
                          </div>
                          <p className="text-sm text-muted-foreground">
                            {objective.description}
                          </p>
                        </div>
                      </div>
                    </div>
                  )
                })}
              </RadioGroup>
            </div>
          </div>
        )

      case 1:
        return (
          <div className="space-y-6">
            <div className="grid grid-cols-2 gap-4">
              <div>
                <Label>Age Range</Label>
                <div className="grid grid-cols-2 gap-2 mt-1">
                  <Input placeholder="18" defaultValue="18" />
                  <Input placeholder="65" defaultValue="65" />
                </div>
              </div>
              <div>
                <Label>Gender</Label>
                <RadioGroup defaultValue="all" className="mt-1">
                  <div className="flex items-center space-x-2">
                    <RadioGroupItem value="all" id="all" />
                    <Label htmlFor="all">All</Label>
                  </div>
                  <div className="flex items-center space-x-2">
                    <RadioGroupItem value="male" id="male" />
                    <Label htmlFor="male">Male</Label>
                  </div>
                  <div className="flex items-center space-x-2">
                    <RadioGroupItem value="female" id="female" />
                    <Label htmlFor="female">Female</Label>
                  </div>
                </RadioGroup>
              </div>
            </div>

            <div>
              <Label>Location</Label>
              <Input placeholder="Enter country, city, or region" className="mt-1" />
            </div>

            <div>
              <Label>Interests</Label>
              <Input placeholder="Enter interests separated by commas" className="mt-1" />
            </div>

            <div className="bg-muted p-4 rounded-lg">
              <div className="flex items-center space-x-2 mb-2">
                <Zap className="h-4 w-4 text-primary" />
                <p className="text-sm font-medium">AI Recommendation</p>
              </div>
              <p className="text-sm text-muted-foreground mb-3">
                Based on similar successful campaigns, we recommend targeting ages 25-45 with interests in e-commerce and online shopping.
              </p>
              <Button size="sm" variant="outline">Apply Suggestion</Button>
            </div>
          </div>
        )

      case 2:
        return (
          <div className="space-y-6">
            <div>
              <Label className="text-base font-medium">Budget Type</Label>
              <RadioGroup
                value={formData.budgetType}
                onValueChange={(value) => setFormData({ ...formData, budgetType: value })}
                className="mt-2"
              >
                <div className="flex items-center space-x-2">
                  <RadioGroupItem value="daily" id="daily" />
                  <Label htmlFor="daily">Daily Budget</Label>
                </div>
                <div className="flex items-center space-x-2">
                  <RadioGroupItem value="lifetime" id="lifetime" />
                  <Label htmlFor="lifetime">Lifetime Budget</Label>
                </div>
              </RadioGroup>
            </div>

            <div>
              <Label>Amount ($)</Label>
              <Input
                type="number"
                placeholder="50"
                value={formData.budget}
                onChange={(e) => setFormData({ ...formData, budget: e.target.value })}
                className="mt-1"
              />
            </div>

            <div>
              <Label>Start Date</Label>
              <Input type="date" className="mt-1" />
            </div>

            <div className="bg-primary/10 border border-primary/20 rounded-lg p-4">
              <div className="flex items-center space-x-2 mb-2">
                <CheckCircle2 className="h-4 w-4 text-primary" />
                <p className="text-sm font-medium">Campaign Summary</p>
              </div>
              <div className="space-y-1 text-sm text-muted-foreground">
                <p><span className="font-medium">Name:</span> {formData.campaignName || 'Untitled Campaign'}</p>
                <p><span className="font-medium">Objective:</span> {OBJECTIVES.find(obj => obj.id === formData.objective)?.title}</p>
                <p><span className="font-medium">Budget:</span> ${formData.budget} {formData.budgetType}</p>
                <p><span className="font-medium">Estimated Reach:</span> 15,000 - 45,000 people</p>
              </div>
            </div>
          </div>
        )

      default:
        return null
    }
  }

  return (
    <Dialog open={isOpen} onOpenChange={setIsOpen}>
      <DialogTrigger asChild>
        {children}
      </DialogTrigger>
      <DialogContent className="max-w-2xl max-h-[90vh] p-0">
        <DialogHeader className="p-6 pb-0">
          <DialogTitle>Create New Campaign</DialogTitle>
          <div className="flex items-center justify-between mt-4">
            <div className="text-sm text-muted-foreground">
              Step {currentStep + 1} of {STEPS.length}: {STEPS[currentStep]}
            </div>
            <Badge variant="outline" className="text-xs">
              {Math.round(progress)}% Complete
            </Badge>
          </div>
          <Progress value={progress} className="mt-2" />
        </DialogHeader>

        <ScrollArea className="flex-1 px-6 max-h-[60vh]">
          <div className="py-4">
            {renderStepContent()}
          </div>
        </ScrollArea>

        <div className="flex items-center justify-between p-6 pt-0 border-t">
          <Button
            variant="outline"
            onClick={handleBack}
            disabled={currentStep === 0}
          >
            <ArrowLeft className="h-4 w-4 mr-2" />
            Back
          </Button>

          <Button onClick={handleNext}>
            {currentStep === STEPS.length - 1 ? (
              <>
                <Zap className="h-4 w-4 mr-2" />
                Launch Campaign
              </>
            ) : (
              <>
                Next
                <ArrowRight className="h-4 w-4 ml-2" />
              </>
            )}
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  )
}