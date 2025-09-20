'use client'

import { useEffect, useState } from 'react'
import { Card, CardContent } from '@/components/ui/card'
import {
  TrendingUp,
  Users,
  Award,
  Building2,
  GraduationCap,
  Briefcase,
  Star,
  Globe,
  Clock,
  Target,
} from 'lucide-react'
import { cn } from '@/lib/utils'

interface Statistic {
  id: string
  value: number
  label: string
  labelAr: string
  suffix?: string
  prefix?: string
  icon: React.ComponentType<{ className?: string }>
  color: string
  bgColor: string
  description: string
  descriptionAr: string
}

interface StatisticsProps {
  rtl?: boolean
}

const statistics: Statistic[] = [
  {
    id: '1',
    value: 5000,
    label: 'Successful Graduates',
    labelAr: 'خريج ناجح',
    suffix: '+',
    icon: GraduationCap,
    color: 'text-blue-600',
    bgColor: 'bg-blue-100',
    description: 'Students who completed our programs and achieved certification',
    descriptionAr: 'الطلاب الذين أكملوا برامجنا وحققوا الشهادة'
  },
  {
    id: '2',
    value: 98,
    label: 'Job Placement Rate',
    labelAr: 'معدل التوظيف',
    suffix: '%',
    icon: Briefcase,
    color: 'text-green-600',
    bgColor: 'bg-green-100',
    description: 'Graduates who found employment within 6 months',
    descriptionAr: 'الخريجون الذين وجدوا عملاً في غضون 6 أشهر'
  },
  {
    id: '3',
    value: 50,
    label: 'Training Programs',
    labelAr: 'برنامج تدريبي',
    suffix: '+',
    icon: Award,
    color: 'text-purple-600',
    bgColor: 'bg-purple-100',
    description: 'Comprehensive training programs across multiple industries',
    descriptionAr: 'برامج تدريبية شاملة عبر صناعات متعددة'
  },
  {
    id: '4',
    value: 120,
    label: 'Industry Partners',
    labelAr: 'شريك صناعي',
    suffix: '+',
    icon: Building2,
    color: 'text-orange-600',
    bgColor: 'bg-orange-100',
    description: 'Companies partnered with us for recruitment and training',
    descriptionAr: 'الشركات التي تشاركنا في التوظيف والتدريب'
  },
  {
    id: '5',
    value: 15,
    label: 'Years of Excellence',
    labelAr: 'سنة من التميز',
    suffix: '+',
    icon: Star,
    color: 'text-yellow-600',
    bgColor: 'bg-yellow-100',
    description: 'Years of providing quality vocational education',
    descriptionAr: 'سنوات من تقديم التعليم المهني عالي الجودة'
  },
  {
    id: '6',
    value: 25,
    label: 'Provinces Served',
    labelAr: 'ولاية مخدومة',
    suffix: '+',
    icon: Globe,
    color: 'text-red-600',
    bgColor: 'bg-red-100',
    description: 'Students from across Algeria have benefited from our programs',
    descriptionAr: 'طلاب من جميع أنحاء الجزائر استفادوا من برامجنا'
  },
  {
    id: '7',
    value: 40000,
    label: 'Training Hours Delivered',
    labelAr: 'ساعة تدريب مقدمة',
    suffix: '+',
    icon: Clock,
    color: 'text-indigo-600',
    bgColor: 'bg-indigo-100',
    description: 'Total hours of practical and theoretical training provided',
    descriptionAr: 'إجمالي ساعات التدريب العملي والنظري المقدمة'
  },
  {
    id: '8',
    value: 95,
    label: 'Student Satisfaction',
    labelAr: 'رضا الطلاب',
    suffix: '%',
    icon: Target,
    color: 'text-teal-600',
    bgColor: 'bg-teal-100',
    description: 'Students who rate our programs as excellent or very good',
    descriptionAr: 'الطلاب الذين يقيمون برامجنا كممتازة أو جيدة جداً'
  }
]

// Custom hook for counting animation
function useCountUp(end: number, duration: number = 2000) {
  const [count, setCount] = useState(0)
  const [isVisible, setIsVisible] = useState(false)

  useEffect(() => {
    if (!isVisible) return

    let startTime: number
    let animationFrame: number

    const animate = (timestamp: number) => {
      if (!startTime) startTime = timestamp
      const progress = Math.min((timestamp - startTime) / duration, 1)
      
      setCount(Math.floor(end * progress))
      
      if (progress < 1) {
        animationFrame = requestAnimationFrame(animate)
      }
    }

    animationFrame = requestAnimationFrame(animate)

    return () => {
      if (animationFrame) {
        cancelAnimationFrame(animationFrame)
      }
    }
  }, [end, duration, isVisible])

  return { count, setIsVisible }
}

function StatisticCard({ statistic, rtl = false }: { statistic: Statistic; rtl?: boolean }) {
  const { count, setIsVisible } = useCountUp(statistic.value)
  const Icon = statistic.icon

  useEffect(() => {
    const observer = new IntersectionObserver(
      (entries) => {
        if (entries[0].isIntersecting) {
          setIsVisible(true)
          observer.disconnect()
        }
      },
      { threshold: 0.1 }
    )

    const element = document.getElementById(`stat-${statistic.id}`)
    if (element) {
      observer.observe(element)
    }

    return () => observer.disconnect()
  }, [statistic.id, setIsVisible])

  return (
    <Card 
      id={`stat-${statistic.id}`}
      className="card-hover group overflow-hidden relative"
    >
      {/* Background decoration */}
      <div className={cn(
        "absolute top-0 right-0 w-20 h-20 rounded-full opacity-10 transform translate-x-6 -translate-y-6",
        statistic.bgColor
      )} />
      
      <CardContent className="p-6 relative">
        <div className="flex items-center justify-between mb-4">
          <div className={cn(
            "p-3 rounded-lg group-hover:scale-110 transition-transform duration-300",
            statistic.bgColor
          )}>
            <Icon className={cn("h-6 w-6", statistic.color)} />
          </div>
          <TrendingUp className="h-4 w-4 text-green-500 opacity-60" />
        </div>

        <div className="space-y-2">
          <div className="text-3xl font-bold tracking-tight">
            {statistic.prefix}{count.toLocaleString()}{statistic.suffix}
          </div>
          <div className="font-semibold text-slate-700 dark:text-slate-300">
            {rtl ? statistic.labelAr : statistic.label}
          </div>
          <div className="text-sm text-muted-foreground line-clamp-2">
            {rtl ? statistic.descriptionAr : statistic.description}
          </div>
        </div>

        {/* Progress bar animation */}
        <div className="mt-4 h-1 bg-gray-200 dark:bg-gray-700 rounded-full overflow-hidden">
          <div 
            className={cn(
              "h-full transition-all duration-2000 ease-out",
              statistic.color.replace('text-', 'bg-')
            )}
            style={{ 
              width: `${Math.min((count / statistic.value) * 100, 100)}%`,
              transition: 'width 2s ease-out'
            }}
          />
        </div>
      </CardContent>
    </Card>
  )
}

export function Statistics({ rtl = false }: StatisticsProps) {
  return (
    <section className={cn("py-20 bg-gradient-to-br from-slate-50 to-blue-50 dark:from-slate-900 dark:to-slate-800", rtl && "rtl")}>
      <div className="container mx-auto px-4">
        {/* Header */}
        <div className="text-center mb-16">
          <div className="inline-flex items-center justify-center w-16 h-16 bg-primary/10 rounded-full mb-6">
            <TrendingUp className="h-8 w-8 text-primary" />
          </div>
          <h2 className="text-4xl font-bold mb-4 gradient-text">
            {rtl ? 'إنجازاتنا بالأرقام' : 'Our Achievements in Numbers'}
          </h2>
          <p className="text-xl text-muted-foreground max-w-3xl mx-auto">
            {rtl 
              ? 'نفخر بالإنجازات التي حققناها على مدار سنوات من التميز في التعليم والتدريب المهني'
              : 'We take pride in the achievements we have accomplished over years of excellence in vocational education and training'
            }
          </p>
        </div>

        {/* Statistics Grid */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6 mb-16">
          {statistics.map((statistic) => (
            <StatisticCard 
              key={statistic.id} 
              statistic={statistic} 
              rtl={rtl}
            />
          ))}
        </div>

        {/* Impact Statement */}
        <div className="bg-white dark:bg-slate-800 rounded-2xl p-8 shadow-lg border">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 items-center">
            <div>
              <h3 className="text-2xl font-bold mb-4">
                {rtl ? 'تأثيرنا على المجتمع' : 'Our Impact on Society'}
              </h3>
              <p className="text-muted-foreground mb-6">
                {rtl 
                  ? 'منذ تأسيسنا، ساهمنا في تطوير القوى العاملة الماهرة في الجزائر، وساعدنا في سد الفجوة بين التعليم وسوق العمل، وقدمنا فرص تدريبية عالية الجودة للشباب الجزائري.'
                  : 'Since our establishment, we have contributed to developing skilled workforce in Algeria, helped bridge the gap between education and the job market, and provided high-quality training opportunities for Algerian youth.'
                }
              </p>
              <div className="space-y-3">
                <div className="flex items-center gap-3">
                  <div className="w-3 h-3 bg-green-500 rounded-full" />
                  <span className="text-sm">
                    {rtl ? 'تدريب معتمد دولياً' : 'Internationally Certified Training'}
                  </span>
                </div>
                <div className="flex items-center gap-3">
                  <div className="w-3 h-3 bg-blue-500 rounded-full" />
                  <span className="text-sm">
                    {rtl ? 'شراكات مع أفضل الشركات' : 'Partnerships with Top Companies'}
                  </span>
                </div>
                <div className="flex items-center gap-3">
                  <div className="w-3 h-3 bg-purple-500 rounded-full" />
                  <span className="text-sm">
                    {rtl ? 'مرافق تدريب حديثة' : 'Modern Training Facilities'}
                  </span>
                </div>
              </div>
            </div>

            <div className="relative">
              {/* Achievement Highlights */}
              <div className="grid grid-cols-2 gap-4">
                <Card className="p-4 text-center bg-gradient-to-br from-blue-500 to-blue-600 text-white">
                  <Users className="h-8 w-8 mx-auto mb-2" />
                  <div className="text-2xl font-bold">15k+</div>
                  <div className="text-sm text-blue-100">
                    {rtl ? 'خريج متدرب' : 'Trained Graduates'}
                  </div>
                </Card>
                
                <Card className="p-4 text-center bg-gradient-to-br from-green-500 to-green-600 text-white">
                  <Award className="h-8 w-8 mx-auto mb-2" />
                  <div className="text-2xl font-bold">500+</div>
                  <div className="text-sm text-green-100">
                    {rtl ? 'شهادة ممنوحة' : 'Certificates Awarded'}
                  </div>
                </Card>
                
                <Card className="p-4 text-center bg-gradient-to-br from-purple-500 to-purple-600 text-white">
                  <Building2 className="h-8 w-8 mx-auto mb-2" />
                  <div className="text-2xl font-bold">200+</div>
                  <div className="text-sm text-purple-100">
                    {rtl ? 'شراكة فعالة' : 'Active Partnerships'}
                  </div>
                </Card>
                
                <Card className="p-4 text-center bg-gradient-to-br from-orange-500 to-orange-600 text-white">
                  <Star className="h-8 w-8 mx-auto mb-2" />
                  <div className="text-2xl font-bold">4.8</div>
                  <div className="text-sm text-orange-100">
                    {rtl ? 'تقييم الجودة' : 'Quality Rating'}
                  </div>
                </Card>
              </div>
            </div>
          </div>
        </div>

        {/* Call to Action */}
        <div className="text-center mt-16">
          <div className="bg-gradient-to-r from-blue-600 to-green-600 rounded-2xl p-8 text-white">
            <h3 className="text-2xl font-bold mb-4">
              {rtl ? 'كن جزءاً من قصة نجاحنا' : 'Be Part of Our Success Story'}
            </h3>
            <p className="text-blue-100 mb-6 max-w-2xl mx-auto">
              {rtl 
                ? 'انضم إلى آلاف الطلاب الذين حققوا أحلامهم المهنية من خلال برامجنا التدريبية المتميزة'
                : 'Join thousands of students who have achieved their professional dreams through our excellent training programs'
              }
            </p>
            <div className="flex flex-col sm:flex-row gap-4 justify-center">
              <button className="bg-white text-blue-600 px-6 py-3 rounded-lg font-semibold hover:bg-blue-50 transition-colors">
                {rtl ? 'ابدأ رحلتك اليوم' : 'Start Your Journey Today'}
              </button>
              <button className="border border-white text-white px-6 py-3 rounded-lg font-semibold hover:bg-white/10 transition-colors">
                {rtl ? 'تواصل معنا' : 'Contact Us'}
              </button>
            </div>
          </div>
        </div>
      </div>
    </section>
  )
}