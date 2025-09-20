'use client'

import { useState } from 'react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import {
  Stethoscope,
  Wrench,
  Monitor,
  Users,
  Clock,
  Calendar,
  Award,
  ArrowRight,
  BookOpen,
  CheckCircle,
  Star,
  MapPin,
  DollarSign,
  GraduationCap,
} from 'lucide-react'
import { cn } from '@/lib/utils'

interface Program {
  id: string
  title: string
  titleAr: string
  description: string
  descriptionAr: string
  category: 'medical' | 'machinery' | 'technology'
  duration: string
  durationAr: string
  price: string
  priceAr: string
  level: 'beginner' | 'intermediate' | 'advanced'
  levelAr: string
  features: string[]
  featuresAr: string[]
  certification: string
  certificationAr: string
  nextStartDate: string
  studentsEnrolled: number
  rating: number
  popular: boolean
  featured: boolean
}

interface ProgramsProps {
  rtl?: boolean
}

const programCategories = [
  {
    id: 'all',
    label: 'All Programs',
    labelAr: 'جميع البرامج',
    icon: BookOpen,
    color: 'bg-blue-500'
  },
  {
    id: 'medical',
    label: 'Medical Training',
    labelAr: 'التدريب الطبي',
    icon: Stethoscope,
    color: 'bg-red-500'
  },
  {
    id: 'machinery',
    label: 'Heavy Machinery',
    labelAr: 'الآلات الثقيلة',
    icon: Wrench,
    color: 'bg-orange-500'
  },
  {
    id: 'technology',
    label: 'Technology',
    labelAr: 'التكنولوجيا',
    icon: Monitor,
    color: 'bg-green-500'
  },
]

const programs: Program[] = [
  {
    id: '1',
    title: 'Emergency Medical Response Certification',
    titleAr: 'شهادة الاستجابة الطبية للطوارئ',
    description: 'Comprehensive training in emergency medical procedures, patient care, and life-saving techniques.',
    descriptionAr: 'تدريب شامل في الإجراءات الطبية الطارئة ورعاية المرضى وتقنيات إنقاذ الحياة.',
    category: 'medical',
    duration: '12 weeks',
    durationAr: '12 أسبوع',
    price: '2,500 DZD',
    priceAr: '2,500 دج',
    level: 'intermediate',
    levelAr: 'متوسط',
    features: [
      'CPR & First Aid Certification',
      'Emergency Response Protocols',
      'Medical Equipment Training',
      'Patient Assessment Skills',
      'Trauma Care Procedures'
    ],
    featuresAr: [
      'شهادة الإنعاش القلبي والإسعافات الأولية',
      'بروتوكولات الاستجابة للطوارئ',
      'تدريب المعدات الطبية',
      'مهارات تقييم المرضى',
      'إجراءات رعاية الصدمات'
    ],
    certification: 'International Emergency Medical Technician',
    certificationAr: 'فني طبي طوارئ دولي',
    nextStartDate: '2024-03-15',
    studentsEnrolled: 124,
    rating: 4.8,
    popular: true,
    featured: true
  },
  {
    id: '2',
    title: 'Heavy Equipment Operation Mastery',
    titleAr: 'إتقان تشغيل المعدات الثقيلة',
    description: 'Master the operation of excavators, bulldozers, cranes, and other heavy construction equipment.',
    descriptionAr: 'إتقان تشغيل الحفارات والجرافات والرافعات والمعدات الإنشائية الثقيلة الأخرى.',
    category: 'machinery',
    duration: '16 weeks',
    durationAr: '16 أسبوع',
    price: '3,200 DZD',
    priceAr: '3,200 دج',
    level: 'beginner',
    levelAr: 'مبتدئ',
    features: [
      'Excavator Operation',
      'Bulldozer & Grader Training',
      'Crane Safety Certification',
      'Equipment Maintenance',
      'Site Safety Protocols'
    ],
    featuresAr: [
      'تشغيل الحفارات',
      'تدريب الجرافات والمسويات',
      'شهادة سلامة الرافعات',
      'صيانة المعدات',
      'بروتوكولات السلامة في الموقع'
    ],
    certification: 'Certified Heavy Equipment Operator',
    certificationAr: 'مشغل معدات ثقيلة معتمد',
    nextStartDate: '2024-03-22',
    studentsEnrolled: 89,
    rating: 4.9,
    popular: true,
    featured: false
  },
  {
    id: '3',
    title: 'Healthcare Administration & Management',
    titleAr: 'إدارة وتسيير الرعاية الصحية',
    description: 'Learn healthcare management, patient records, medical coding, and healthcare facility administration.',
    descriptionAr: 'تعلم إدارة الرعاية الصحية وسجلات المرضى والترميز الطبي وإدارة المرافق الصحية.',
    category: 'medical',
    duration: '10 weeks',
    durationAr: '10 أسابيع',
    price: '2,800 DZD',
    priceAr: '2,800 دج',
    level: 'intermediate',
    levelAr: 'متوسط',
    features: [
      'Healthcare Systems Overview',
      'Medical Records Management',
      'Healthcare Quality Assurance',
      'Patient Communication',
      'Healthcare Technology'
    ],
    featuresAr: [
      'نظرة عامة على أنظمة الرعاية الصحية',
      'إدارة السجلات الطبية',
      'ضمان جودة الرعاية الصحية',
      'التواصل مع المرضى',
      'تكنولوجيا الرعاية الصحية'
    ],
    certification: 'Healthcare Administration Certificate',
    certificationAr: 'شهادة إدارة الرعاية الصحية',
    nextStartDate: '2024-04-01',
    studentsEnrolled: 67,
    rating: 4.7,
    popular: false,
    featured: true
  },
  {
    id: '4',
    title: 'Digital Technology & Computer Skills',
    titleAr: 'التكنولوجيا الرقمية ومهارات الحاسوب',
    description: 'Comprehensive computer training covering office applications, digital literacy, and basic programming.',
    descriptionAr: 'تدريب شامل على الحاسوب يغطي تطبيقات المكتب والثقافة الرقمية والبرمجة الأساسية.',
    category: 'technology',
    duration: '8 weeks',
    durationAr: '8 أسابيع',
    price: '1,800 DZD',
    priceAr: '1,800 دج',
    level: 'beginner',
    levelAr: 'مبتدئ',
    features: [
      'Microsoft Office Suite',
      'Internet & Email Skills',
      'Basic Web Development',
      'Digital Communication',
      'Data Management'
    ],
    featuresAr: [
      'حزمة مايكروسوفت أوفيس',
      'مهارات الإنترنت والبريد الإلكتروني',
      'تطوير الويب الأساسي',
      'التواصل الرقمي',
      'إدارة البيانات'
    ],
    certification: 'Digital Literacy Certificate',
    certificationAr: 'شهادة الثقافة الرقمية',
    nextStartDate: '2024-03-25',
    studentsEnrolled: 156,
    rating: 4.6,
    popular: true,
    featured: false
  },
  {
    id: '5',
    title: 'Construction Equipment Maintenance',
    titleAr: 'صيانة معدات البناء',
    description: 'Learn preventive maintenance, troubleshooting, and repair of heavy construction machinery.',
    descriptionAr: 'تعلم الصيانة الوقائية واستكشاف الأخطاء وإصلاح آلات البناء الثقيلة.',
    category: 'machinery',
    duration: '14 weeks',
    durationAr: '14 أسبوع',
    price: '3,500 DZD',
    priceAr: '3,500 دج',
    level: 'advanced',
    levelAr: 'متقدم',
    features: [
      'Engine Diagnostics',
      'Hydraulic Systems',
      'Electrical Troubleshooting',
      'Preventive Maintenance',
      'Parts Management'
    ],
    featuresAr: [
      'تشخيص المحركات',
      'الأنظمة الهيدروليكية',
      'استكشاف الأخطاء الكهربائية',
      'الصيانة الوقائية',
      'إدارة قطع الغيار'
    ],
    certification: 'Certified Equipment Maintenance Technician',
    certificationAr: 'فني صيانة معدات معتمد',
    nextStartDate: '2024-04-08',
    studentsEnrolled: 43,
    rating: 4.9,
    popular: false,
    featured: true
  },
  {
    id: '6',
    title: 'Web Development & Design',
    titleAr: 'تطوير وتصميم المواقع',
    description: 'Learn modern web development including HTML, CSS, JavaScript, and responsive design principles.',
    descriptionAr: 'تعلم تطوير الويب الحديث بما في ذلك HTML و CSS و JavaScript ومبادئ التصميم المتجاوب.',
    category: 'technology',
    duration: '12 weeks',
    durationAr: '12 أسبوع',
    price: '2,200 DZD',
    priceAr: '2,200 دج',
    level: 'intermediate',
    levelAr: 'متوسط',
    features: [
      'HTML5 & CSS3',
      'JavaScript Programming',
      'Responsive Web Design',
      'Version Control (Git)',
      'Portfolio Development'
    ],
    featuresAr: [
      'HTML5 و CSS3',
      'برمجة جافاسكريبت',
      'تصميم ويب متجاوب',
      'التحكم في الإصدارات (Git)',
      'تطوير المعرض'
    ],
    certification: 'Web Developer Certificate',
    certificationAr: 'شهادة مطور ويب',
    nextStartDate: '2024-04-15',
    studentsEnrolled: 92,
    rating: 4.8,
    popular: true,
    featured: false
  }
]

export function Programs({ rtl = false }: ProgramsProps) {
  const [selectedCategory, setSelectedCategory] = useState('all')

  const filteredPrograms = selectedCategory === 'all' 
    ? programs 
    : programs.filter(program => program.category === selectedCategory)

  const featuredPrograms = filteredPrograms.filter(program => program.featured)
  const regularPrograms = filteredPrograms.filter(program => !program.featured)

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleDateString(rtl ? 'ar-SA' : 'en-US', {
      year: 'numeric',
      month: 'long',
      day: 'numeric'
    })
  }

  const getLevelColor = (level: string) => {
    switch (level) {
      case 'beginner': return 'bg-green-100 text-green-800 border-green-200'
      case 'intermediate': return 'bg-yellow-100 text-yellow-800 border-yellow-200'
      case 'advanced': return 'bg-red-100 text-red-800 border-red-200'
      default: return 'bg-gray-100 text-gray-800 border-gray-200'
    }
  }

  const renderStars = (rating: number) => {
    return Array.from({ length: 5 }, (_, i) => (
      <Star
        key={i}
        className={cn(
          "h-4 w-4",
          i < Math.floor(rating) 
            ? "text-yellow-400 fill-current" 
            : "text-gray-300"
        )}
      />
    ))
  }

  return (
    <section id="programs" className={cn("py-20 bg-gradient-to-br from-gray-50 to-blue-50 dark:from-slate-900 dark:to-slate-800", rtl && "rtl")}>
      <div className="container mx-auto px-4">
        {/* Header */}
        <div className="text-center mb-16">
          <div className="inline-flex items-center justify-center w-16 h-16 bg-primary/10 rounded-full mb-6">
            <GraduationCap className="h-8 w-8 text-primary" />
          </div>
          <h2 className="text-4xl font-bold mb-4 gradient-text">
            {rtl ? 'برامجنا التدريبية' : 'Our Training Programs'}
          </h2>
          <p className="text-xl text-muted-foreground max-w-3xl mx-auto">
            {rtl 
              ? 'اختر من بين مجموعة واسعة من البرامج التدريبية المعتمدة والمصممة لتلبية احتياجات السوق الحديثة'
              : 'Choose from a wide range of certified training programs designed to meet modern market demands'
            }
          </p>
        </div>

        {/* Category Filter */}
        <div className="flex flex-wrap justify-center gap-3 mb-12">
          {programCategories.map((category) => {
            const Icon = category.icon
            const isActive = selectedCategory === category.id
            
            return (
              <Button
                key={category.id}
                variant={isActive ? "skillence" : "outline"}
                onClick={() => setSelectedCategory(category.id)}
                className={cn(
                  "flex items-center gap-2 transition-all duration-300",
                  isActive && "shadow-lg scale-105"
                )}
              >
                <div className={cn(
                  "w-2 h-2 rounded-full",
                  isActive ? "bg-white" : category.color
                )} />
                <Icon className="h-4 w-4" />
                <span>{rtl ? category.labelAr : category.label}</span>
              </Button>
            )
          })}
        </div>

        {/* Featured Programs */}
        {featuredPrograms.length > 0 && (
          <div className="mb-16">
            <h3 className="text-2xl font-bold mb-8 flex items-center gap-2">
              <Star className="h-6 w-6 text-yellow-500" />
              {rtl ? 'البرامج المميزة' : 'Featured Programs'}
            </h3>
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
              {featuredPrograms.map((program) => {
                const categoryInfo = programCategories.find(c => c.id === program.category)
                const CategoryIcon = categoryInfo?.icon || BookOpen

                return (
                  <Card key={program.id} className="group card-hover overflow-hidden border-2 border-yellow-200 relative">
                    {/* Featured Badge */}
                    <Badge className="absolute top-4 left-4 z-10 bg-yellow-500 text-white border-0">
                      <Star className="h-3 w-3 mr-1" />
                      {rtl ? 'مميز' : 'Featured'}
                    </Badge>

                    {/* Popular Badge */}
                    {program.popular && (
                      <Badge className="absolute top-4 right-4 z-10 bg-green-500 text-white border-0">
                        {rtl ? 'الأكثر شعبية' : 'Most Popular'}
                      </Badge>
                    )}

                    <CardHeader className="pb-4">
                      <div className="flex items-start justify-between mb-4">
                        <div className={cn(
                          "p-3 rounded-lg",
                          categoryInfo?.color || 'bg-blue-500'
                        )}>
                          <CategoryIcon className="h-6 w-6 text-white" />
                        </div>
                        <div className="text-right">
                          <div className="flex items-center gap-1 mb-1">
                            {renderStars(program.rating)}
                            <span className="text-sm text-muted-foreground ml-1">
                              ({program.rating})
                            </span>
                          </div>
                          <div className="flex items-center gap-1 text-sm text-muted-foreground">
                            <Users className="h-3 w-3" />
                            <span>{program.studentsEnrolled} {rtl ? 'طالب' : 'students'}</span>
                          </div>
                        </div>
                      </div>

                      <CardTitle className="text-xl leading-tight group-hover:text-primary transition-colors">
                        {rtl ? program.titleAr : program.title}
                      </CardTitle>
                    </CardHeader>

                    <CardContent>
                      <p className="text-muted-foreground mb-6 line-clamp-2">
                        {rtl ? program.descriptionAr : program.description}
                      </p>

                      {/* Program Details */}
                      <div className="grid grid-cols-2 gap-4 mb-6">
                        <div className="flex items-center gap-2 text-sm">
                          <Clock className="h-4 w-4 text-muted-foreground" />
                          <span>{rtl ? program.durationAr : program.duration}</span>
                        </div>
                        <div className="flex items-center gap-2 text-sm">
                          <DollarSign className="h-4 w-4 text-muted-foreground" />
                          <span>{rtl ? program.priceAr : program.price}</span>
                        </div>
                        <div className="flex items-center gap-2 text-sm">
                          <Calendar className="h-4 w-4 text-muted-foreground" />
                          <span>{formatDate(program.nextStartDate)}</span>
                        </div>
                        <div className="flex items-center gap-2 text-sm">
                          <Badge 
                            variant="outline" 
                            className={getLevelColor(program.level)}
                          >
                            {rtl ? program.levelAr : program.level}
                          </Badge>
                        </div>
                      </div>

                      {/* Key Features */}
                      <div className="mb-6">
                        <h4 className="font-semibold mb-3 text-sm">
                          {rtl ? 'المميزات الرئيسية:' : 'Key Features:'}
                        </h4>
                        <div className="space-y-2">
                          {(rtl ? program.featuresAr : program.features).slice(0, 3).map((feature, index) => (
                            <div key={index} className="flex items-center gap-2 text-sm text-muted-foreground">
                              <CheckCircle className="h-3 w-3 text-green-500 flex-shrink-0" />
                              <span>{feature}</span>
                            </div>
                          ))}
                        </div>
                      </div>

                      {/* Certification */}
                      <div className="bg-blue-50 dark:bg-blue-900/20 rounded-lg p-3 mb-6">
                        <div className="flex items-center gap-2 text-sm">
                          <Award className="h-4 w-4 text-blue-600" />
                          <span className="font-medium">
                            {rtl ? 'الشهادة:' : 'Certification:'}
                          </span>
                        </div>
                        <p className="text-sm text-blue-700 dark:text-blue-300 mt-1">
                          {rtl ? program.certificationAr : program.certification}
                        </p>
                      </div>

                      {/* CTA Buttons */}
                      <div className="flex gap-3">
                        <Button variant="skillence" className="flex-1 group">
                          {rtl ? 'التسجيل الآن' : 'Enroll Now'}
                          <ArrowRight className="h-4 w-4 ml-2 group-hover:translate-x-1 transition-transform" />
                        </Button>
                        <Button variant="outline" size="sm">
                          {rtl ? 'تفاصيل' : 'Details'}
                        </Button>
                      </div>
                    </CardContent>
                  </Card>
                )
              })}
            </div>
          </div>
        )}

        {/* Regular Programs */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">
          {regularPrograms.map((program) => {
            const categoryInfo = programCategories.find(c => c.id === program.category)
            const CategoryIcon = categoryInfo?.icon || BookOpen

            return (
              <Card key={program.id} className="group card-hover overflow-hidden">
                {/* Popular Badge */}
                {program.popular && (
                  <Badge className="absolute top-4 right-4 z-10 bg-green-500 text-white border-0">
                    {rtl ? 'شائع' : 'Popular'}
                  </Badge>
                )}

                <CardHeader className="pb-4">
                  <div className="flex items-start justify-between mb-4">
                    <div className={cn(
                      "p-2 rounded-lg",
                      categoryInfo?.color || 'bg-blue-500'
                    )}>
                      <CategoryIcon className="h-5 w-5 text-white" />
                    </div>
                    <div className="text-right">
                      <div className="flex items-center gap-1 mb-1">
                        {renderStars(program.rating)}
                        <span className="text-xs text-muted-foreground ml-1">
                          ({program.rating})
                        </span>
                      </div>
                      <div className="flex items-center gap-1 text-xs text-muted-foreground">
                        <Users className="h-3 w-3" />
                        <span>{program.studentsEnrolled}</span>
                      </div>
                    </div>
                  </div>

                  <CardTitle className="text-lg leading-tight group-hover:text-primary transition-colors line-clamp-2">
                    {rtl ? program.titleAr : program.title}
                  </CardTitle>
                </CardHeader>

                <CardContent>
                  <p className="text-muted-foreground text-sm mb-4 line-clamp-3">
                    {rtl ? program.descriptionAr : program.description}
                  </p>

                  {/* Quick Info */}
                  <div className="space-y-2 mb-4">
                    <div className="flex items-center justify-between text-sm">
                      <div className="flex items-center gap-1 text-muted-foreground">
                        <Clock className="h-3 w-3" />
                        <span>{rtl ? program.durationAr : program.duration}</span>
                      </div>
                      <Badge 
                        variant="outline" 
                        className={cn("text-xs", getLevelColor(program.level))}
                      >
                        {rtl ? program.levelAr : program.level}
                      </Badge>
                    </div>
                    <div className="flex items-center justify-between text-sm">
                      <div className="flex items-center gap-1 text-muted-foreground">
                        <Calendar className="h-3 w-3" />
                        <span>{formatDate(program.nextStartDate)}</span>
                      </div>
                      <span className="font-semibold text-primary">
                        {rtl ? program.priceAr : program.price}
                      </span>
                    </div>
                  </div>

                  {/* CTA */}
                  <Button variant="outline" className="w-full group">
                    {rtl ? 'عرض التفاصيل' : 'View Details'}
                    <ArrowRight className="h-4 w-4 ml-2 group-hover:translate-x-1 transition-transform" />
                  </Button>
                </CardContent>
              </Card>
            )
          })}
        </div>

        {/* Empty State */}
        {filteredPrograms.length === 0 && (
          <div className="text-center py-16">
            <GraduationCap className="h-16 w-16 text-muted-foreground mx-auto mb-4" />
            <h3 className="text-lg font-semibold mb-2">
              {rtl ? 'لا توجد برامج في هذه الفئة' : 'No programs in this category'}
            </h3>
            <p className="text-muted-foreground">
              {rtl ? 'جرب تحديد فئة أخرى لعرض البرامج المتاحة' : 'Try selecting another category to view available programs'}
            </p>
          </div>
        )}

        {/* Call to Action */}
        <div className="text-center mt-16">
          <div className="bg-gradient-to-r from-blue-600 to-green-600 rounded-2xl p-8 text-white">
            <h3 className="text-2xl font-bold mb-4">
              {rtl ? 'لا تجد البرنامج المناسب؟' : 'Can\'t find the right program?'}
            </h3>
            <p className="text-blue-100 mb-6 max-w-2xl mx-auto">
              {rtl 
                ? 'اتصل بنا للحصول على استشارة مجانية حول أفضل برنامج تدريبي يناسب أهدافك المهنية'
                : 'Contact us for a free consultation on the best training program that suits your career goals'
              }
            </p>
            <Button variant="outline" size="lg" className="bg-white text-blue-600 hover:bg-blue-50">
              {rtl ? 'احجز استشارة مجانية' : 'Book Free Consultation'}
            </Button>
          </div>
        </div>
      </div>
    </section>
  )
}