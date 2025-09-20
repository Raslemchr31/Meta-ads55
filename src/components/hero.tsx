'use client'

import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import {
  ArrowRight,
  Award,
  Users,
  BookOpen,
  Stethoscope,
  Wrench,
  Monitor,
  GraduationCap,
  Star,
  CheckCircle,
  Play,
  Calendar,
  MapPin,
} from 'lucide-react'
import { cn } from '@/lib/utils'

interface HeroProps {
  rtl?: boolean
}

const highlights = [
  {
    icon: Award,
    label: 'International Accreditation',
    labelAr: 'اعتماد دولي',
    color: 'bg-yellow-500'
  },
  {
    icon: Users,
    label: '5000+ Graduates',
    labelAr: '+5000 خريج',
    color: 'bg-green-500'
  },
  {
    icon: BookOpen,
    label: '50+ Programs',
    labelAr: '+50 برنامج',
    color: 'bg-blue-500'
  },
  {
    icon: Star,
    label: '4.9/5 Rating',
    labelAr: 'تقييم 4.9/5',
    color: 'bg-purple-500'
  }
]

const features = [
  {
    text: 'Government-Certified Training Programs',
    textAr: 'برامج تدريب معتمدة حكومياً'
  },
  {
    text: 'Industry-Leading Instructors',
    textAr: 'مدربون رائدون في الصناعة'
  },
  {
    text: '100% Job Placement Assistance',
    textAr: 'مساعدة توظيف بنسبة 100%'
  },
  {
    text: 'Modern Facilities & Equipment',
    textAr: 'مرافق ومعدات حديثة'
  }
]

export function Hero({ rtl = false }: HeroProps) {
  const scrollToPrograms = () => {
    const programsSection = document.getElementById('programs')
    if (programsSection) {
      programsSection.scrollIntoView({ behavior: 'smooth' })
    }
  }

  const scrollToContact = () => {
    const contactSection = document.getElementById('contact')
    if (contactSection) {
      contactSection.scrollIntoView({ behavior: 'smooth' })
    }
  }

  return (
    <section className={cn("relative min-h-screen flex items-center overflow-hidden", rtl && "rtl")}>
      {/* Background */}
      <div className="absolute inset-0 bg-gradient-to-br from-blue-50 via-white to-green-50 dark:from-slate-900 dark:via-slate-800 dark:to-slate-900" />
      
      {/* Animated background elements */}
      <div className="absolute inset-0 overflow-hidden">
        <div className="absolute -top-40 -right-40 w-80 h-80 bg-blue-400/10 rounded-full blur-3xl animate-pulse" />
        <div className="absolute -bottom-40 -left-40 w-80 h-80 bg-green-400/10 rounded-full blur-3xl animate-pulse delay-1000" />
        <div className="absolute top-1/2 left-1/2 transform -translate-x-1/2 -translate-y-1/2 w-96 h-96 bg-purple-400/5 rounded-full blur-3xl animate-pulse delay-500" />
      </div>

      <div className="container mx-auto px-4 py-20 relative z-10">
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-12 items-center">
          
          {/* Left Content */}
          <div className="space-y-8">
            {/* Badge */}
            <Badge className="bg-blue-100 text-blue-800 border-blue-200 px-4 py-2 text-sm">
              <Award className="h-4 w-4 mr-2" />
              {rtl ? 'الرائدة في التدريب المهني' : 'Leading Professional Training Academy'}
            </Badge>

            {/* Main Heading */}
            <div className="space-y-4">
              <h1 className="text-4xl md:text-5xl lg:text-6xl font-bold leading-tight">
                <span className="gradient-text">
                  {rtl ? 'أكاديمية' : 'Skillence'}
                </span>
                <br />
                <span className="text-slate-800 dark:text-slate-200">
                  {rtl ? 'Skillence' : 'Academy'}
                </span>
              </h1>
              <p className="text-xl md:text-2xl text-slate-600 dark:text-slate-300 max-w-2xl">
                {rtl 
                  ? 'نحول الأحلام إلى مهارات حقيقية من خلال برامج تدريب متقدمة في الآلات الثقيلة والرعاية الصحية والتكنولوجيا'
                  : 'Transforming dreams into real skills through advanced training programs in Heavy Machinery, Healthcare, and Technology'
                }
              </p>
            </div>

            {/* Features List */}
            <div className="space-y-3">
              {features.map((feature, index) => (
                <div key={index} className="flex items-center gap-3">
                  <CheckCircle className="h-5 w-5 text-green-500 flex-shrink-0" />
                  <span className="text-slate-600 dark:text-slate-300">
                    {rtl ? feature.textAr : feature.text}
                  </span>
                </div>
              ))}
            </div>

            {/* CTA Buttons */}
            <div className="flex flex-col sm:flex-row gap-4">
              <Button 
                onClick={scrollToPrograms}
                variant="skillence" 
                size="lg" 
                className="group"
              >
                {rtl ? 'استكشف البرامج' : 'Explore Programs'}
                <ArrowRight className="h-5 w-5 ml-2 group-hover:translate-x-1 transition-transform" />
              </Button>
              <Button 
                onClick={scrollToContact}
                variant="outline" 
                size="lg" 
                className="group"
              >
                <Play className="h-5 w-5 mr-2" />
                {rtl ? 'احجز جولة' : 'Book a Tour'}
              </Button>
            </div>

            {/* Statistics */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              {highlights.map((highlight, index) => {
                const Icon = highlight.icon
                return (
                  <Card key={index} className="card-hover">
                    <CardContent className="p-4 text-center">
                      <div className={cn(
                        "w-10 h-10 rounded-full flex items-center justify-center mx-auto mb-2",
                        highlight.color
                      )}>
                        <Icon className="h-5 w-5 text-white" />
                      </div>
                      <p className="font-semibold text-sm">
                        {rtl ? highlight.labelAr : highlight.label}
                      </p>
                    </CardContent>
                  </Card>
                )
              })}
            </div>
          </div>

          {/* Right Content - Visual Elements */}
          <div className="relative">
            {/* Main Hero Card */}
            <Card className="relative overflow-hidden shadow-2xl">
              <div className="aspect-[4/3] bg-gradient-to-br from-blue-500/20 to-green-500/20 flex items-center justify-center">
                <div className="text-center space-y-4">
                  <GraduationCap className="h-16 w-16 text-blue-600 mx-auto" />
                  <div className="space-y-2">
                    <h3 className="text-2xl font-bold text-slate-800 dark:text-slate-200">
                      {rtl ? 'مركز التدريب الحديث' : 'Modern Training Center'}
                    </h3>
                    <p className="text-slate-600 dark:text-slate-300">
                      {rtl ? 'مرافق عالمية المستوى' : 'World-Class Facilities'}
                    </p>
                  </div>
                </div>
              </div>
              
              {/* Floating elements */}
              <div className="absolute top-4 right-4">
                <Badge className="bg-green-500 text-white border-0">
                  <Star className="h-3 w-3 mr-1" />
                  {rtl ? 'معتمد' : 'Certified'}
                </Badge>
              </div>
            </Card>

            {/* Floating Cards */}
            <Card className="absolute -top-6 -left-6 w-32 glass border-white/20 hidden lg:block">
              <CardContent className="p-4 text-center">
                <Stethoscope className="h-8 w-8 text-red-500 mx-auto mb-2" />
                <p className="text-xs font-medium text-white">
                  {rtl ? 'طبي' : 'Medical'}
                </p>
              </CardContent>
            </Card>

            <Card className="absolute -bottom-6 -right-6 w-32 glass border-white/20 hidden lg:block">
              <CardContent className="p-4 text-center">
                <Wrench className="h-8 w-8 text-orange-500 mx-auto mb-2" />
                <p className="text-xs font-medium text-white">
                  {rtl ? 'آلات ثقيلة' : 'Heavy Machinery'}
                </p>
              </CardContent>
            </Card>

            <Card className="absolute top-1/2 -right-12 w-32 glass border-white/20 hidden lg:block">
              <CardContent className="p-4 text-center">
                <Monitor className="h-8 w-8 text-blue-500 mx-auto mb-2" />
                <p className="text-xs font-medium text-white">
                  {rtl ? 'تكنولوجيا' : 'Technology'}
                </p>
              </CardContent>
            </Card>
          </div>
        </div>

        {/* Bottom Info Bar */}
        <div className="mt-16 bg-white/50 dark:bg-slate-800/50 backdrop-blur-sm rounded-2xl p-6 border border-white/20">
          <div className="flex flex-col md:flex-row items-center justify-between gap-4">
            <div className="flex items-center gap-6">
              <div className="flex items-center gap-2 text-sm text-slate-600 dark:text-slate-300">
                <Calendar className="h-4 w-4" />
                <span>{rtl ? 'التسجيل مفتوح' : 'Enrollment Open'}</span>
              </div>
              <div className="flex items-center gap-2 text-sm text-slate-600 dark:text-slate-300">
                <MapPin className="h-4 w-4" />
                <span>{rtl ? 'الجزائر، العاصمة' : 'Algiers, Algeria'}</span>
              </div>
            </div>
            <Button variant="skillenceSecondary" size="sm">
              {rtl ? 'ابدأ رحلتك اليوم' : 'Start Your Journey Today'}
            </Button>
          </div>
        </div>
      </div>
    </section>
  )
}