'use client'

import { useState, useEffect } from 'react'
import { Card, CardContent } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import {
  ChevronLeft,
  ChevronRight,
  Quote,
  Star,
  Users,
  Award,
  Building,
  MapPin,
  Calendar,
  Play,
  Pause,
} from 'lucide-react'
import { cn } from '@/lib/utils'

interface Testimonial {
  id: string
  name: string
  nameAr: string
  role: string
  roleAr: string
  company: string
  companyAr: string
  program: string
  programAr: string
  testimonial: string
  testimonialAr: string
  rating: number
  graduationYear: string
  location: string
  locationAr: string
  avatar: string
  featured: boolean
}

interface TestimonialsProps {
  rtl?: boolean
}

const testimonials: Testimonial[] = [
  {
    id: '1',
    name: 'Mohamed Ali Benali',
    nameAr: 'محمد علي بن علي',
    role: 'Senior Equipment Operator',
    roleAr: 'مشغل معدات أول',
    company: 'SONATRACH Construction',
    companyAr: 'سوناطراك للبناء',
    program: 'Heavy Equipment Operation Mastery',
    programAr: 'إتقان تشغيل المعدات الثقيلة',
    testimonial: 'Skillence Academy completely transformed my career. The hands-on training with real equipment and experienced instructors gave me the confidence to excel in my field. I went from unemployed to landing a senior position at SONATRACH in just 6 months after graduation.',
    testimonialAr: 'أكاديمية Skillence غيرت مسيرتي المهنية تماماً. التدريب العملي بالمعدات الحقيقية والمدربين ذوي الخبرة منحني الثقة للتفوق في مجالي. انتقلت من العاطل عن العمل إلى الحصول على منصب أول في سوناطراك في 6 أشهر فقط بعد التخرج.',
    rating: 5,
    graduationYear: '2023',
    location: 'Hassi Messaoud, Algeria',
    locationAr: 'حاسي مسعود، الجزائر',
    avatar: '/api/placeholder/80/80',
    featured: true
  },
  {
    id: '2',
    name: 'Amina Khelil',
    nameAr: 'أمينة خليل',
    role: 'Emergency Medical Technician',
    roleAr: 'فنية طوارئ طبية',
    company: 'Algiers Central Hospital',
    companyAr: 'مستشفى الجزائر المركزي',
    program: 'Emergency Medical Response Certification',
    programAr: 'شهادة الاستجابة الطبية للطوارئ',
    testimonial: 'The medical training program at Skillence Academy was incredibly comprehensive. The simulation exercises and real-world scenarios prepared me perfectly for emergency situations. I now feel confident handling any medical emergency that comes my way.',
    testimonialAr: 'برنامج التدريب الطبي في أكاديمية Skillence كان شاملاً بشكل لا يصدق. تمارين المحاكاة والسيناريوهات الواقعية أعدتني بشكل مثالي لحالات الطوارئ. أشعر الآن بالثقة في التعامل مع أي حالة طوارئ طبية.',
    rating: 5,
    graduationYear: '2023',
    location: 'Algiers, Algeria',
    locationAr: 'الجزائر، الجزائر',
    avatar: '/api/placeholder/80/80',
    featured: true
  },
  {
    id: '3',
    name: 'Yacine Boumediene',
    nameAr: 'ياسين بومدين',
    role: 'Web Developer',
    roleAr: 'مطور ويب',
    company: 'TechStart Algeria',
    companyAr: 'تك ستارت الجزائر',
    program: 'Web Development & Design',
    programAr: 'تطوير وتصميم المواقع',
    testimonial: 'From zero programming knowledge to building complete websites - Skillence Academy made it possible. The curriculum is modern and practical, focusing on real-world skills that employers actually need. I started freelancing before I even graduated!',
    testimonialAr: 'من صفر معرفة في البرمجة إلى بناء مواقع كاملة - أكاديمية Skillence جعلت ذلك ممكناً. المنهج حديث وعملي، يركز على المهارات الواقعية التي يحتاجها أصحاب العمل فعلاً. بدأت العمل الحر قبل أن أتخرج حتى!',
    rating: 5,
    graduationYear: '2024',
    location: 'Oran, Algeria',
    locationAr: 'وهران، الجزائر',
    avatar: '/api/placeholder/80/80',
    featured: true
  },
  {
    id: '4',
    name: 'Fatima Zahra Mekki',
    nameAr: 'فاطمة الزهراء مكي',
    role: 'Healthcare Administrator',
    roleAr: 'مسؤولة إدارة صحية',
    company: 'Private Medical Center',
    companyAr: 'مركز طبي خاص',
    program: 'Healthcare Administration & Management',
    programAr: 'إدارة وتسيير الرعاية الصحية',
    testimonial: 'The healthcare administration program gave me insights into the entire healthcare system. I learned patient management, medical coding, and quality assurance. The knowledge I gained helped me secure a management position immediately after graduation.',
    testimonialAr: 'برنامج إدارة الرعاية الصحية منحني نظرة شاملة على نظام الرعاية الصحية بأكمله. تعلمت إدارة المرضى والترميز الطبي وضمان الجودة. المعرفة التي اكتسبتها ساعدتني في الحصول على منصب إداري فور التخرج.',
    rating: 4,
    graduationYear: '2023',
    location: 'Constantine, Algeria',
    locationAr: 'قسنطينة، الجزائر',
    avatar: '/api/placeholder/80/80',
    featured: false
  },
  {
    id: '5',
    name: 'Karim Bensalem',
    nameAr: 'كريم بن سالم',
    role: 'Maintenance Supervisor',
    roleAr: 'مشرف صيانة',
    company: 'Algeria Mining Corporation',
    companyAr: 'شركة التعدين الجزائرية',
    program: 'Construction Equipment Maintenance',
    programAr: 'صيانة معدات البناء',
    testimonial: 'The maintenance program at Skillence Academy is top-notch. Learning hydraulic systems, engine diagnostics, and preventive maintenance has made me an expert in my field. My employers value my skills highly, and I\'ve been promoted twice since graduation.',
    testimonialAr: 'برنامج الصيانة في أكاديمية Skillence من الدرجة الأولى. تعلم الأنظمة الهيدروليكية وتشخيص المحركات والصيانة الوقائية جعلني خبيراً في مجالي. أصحاب العمل يقدرون مهاراتي عالياً، وتمت ترقيتي مرتين منذ التخرج.',
    rating: 5,
    graduationYear: '2023',
    location: 'Ouargla, Algeria',
    locationAr: 'ورقلة، الجزائر',
    avatar: '/api/placeholder/80/80',
    featured: false
  },
  {
    id: '6',
    name: 'Nadia Brahimi',
    nameAr: 'نادية براهيمي',
    role: 'IT Support Specialist',
    roleAr: 'أخصائية دعم تقني',
    company: 'Algeria Telecom',
    companyAr: 'اتصالات الجزائر',
    program: 'Digital Technology & Computer Skills',
    programAr: 'التكنولوجيا الرقمية ومهارات الحاسوب',
    testimonial: 'Starting with basic computer skills, I never imagined I would become an IT specialist. The instructors at Skillence Academy were patient and supportive, breaking down complex concepts into understandable lessons. Now I work for Algeria Telecom!',
    testimonialAr: 'بدءاً من مهارات الحاسوب الأساسية، لم أتخيل أبداً أنني سأصبح أخصائية تقنية معلومات. المدربون في أكاديمية Skillence كانوا صبورين وداعمين، يفككون المفاهيم المعقدة إلى دروس مفهومة. الآن أعمل في اتصالات الجزائر!',
    rating: 4,
    graduationYear: '2024',
    location: 'Setif, Algeria',
    locationAr: 'سطيف، الجزائر',
    avatar: '/api/placeholder/80/80',
    featured: false
  }
]

export function Testimonials({ rtl = false }: TestimonialsProps) {
  const [currentIndex, setCurrentIndex] = useState(0)
  const [isAutoPlay, setIsAutoPlay] = useState(true)

  const featuredTestimonials = testimonials.filter(t => t.featured)
  const allTestimonials = testimonials

  // Auto-play functionality
  useEffect(() => {
    if (!isAutoPlay) return

    const interval = setInterval(() => {
      setCurrentIndex((prevIndex) => 
        (prevIndex + 1) % featuredTestimonials.length
      )
    }, 5000)

    return () => clearInterval(interval)
  }, [isAutoPlay, featuredTestimonials.length])

  const goToSlide = (index: number) => {
    setCurrentIndex(index)
  }

  const nextSlide = () => {
    setCurrentIndex((prevIndex) => 
      (prevIndex + 1) % featuredTestimonials.length
    )
  }

  const prevSlide = () => {
    setCurrentIndex((prevIndex) => 
      prevIndex === 0 ? featuredTestimonials.length - 1 : prevIndex - 1
    )
  }

  const renderStars = (rating: number) => {
    return Array.from({ length: 5 }, (_, i) => (
      <Star
        key={i}
        className={cn(
          "h-4 w-4",
          i < rating 
            ? "text-yellow-400 fill-current" 
            : "text-gray-300"
        )}
      />
    ))
  }

  const currentTestimonial = featuredTestimonials[currentIndex]

  return (
    <section className={cn("py-20 bg-background", rtl && "rtl")}>
      <div className="container mx-auto px-4">
        {/* Header */}
        <div className="text-center mb-16">
          <div className="inline-flex items-center justify-center w-16 h-16 bg-primary/10 rounded-full mb-6">
            <Users className="h-8 w-8 text-primary" />
          </div>
          <h2 className="text-4xl font-bold mb-4 gradient-text">
            {rtl ? 'قصص نجاح طلابنا' : 'Student Success Stories'}
          </h2>
          <p className="text-xl text-muted-foreground max-w-3xl mx-auto">
            {rtl 
              ? 'اكتشف كيف غيرت أكاديمية Skillence حياة آلاف الطلاب وساعدتهم في تحقيق أهدافهم المهنية'
              : 'Discover how Skillence Academy has transformed the lives of thousands of students and helped them achieve their career goals'
            }
          </p>
        </div>

        {/* Featured Testimonials Carousel */}
        <div className="mb-16">
          <div className="relative max-w-4xl mx-auto">
            {/* Main Testimonial Card */}
            <Card className="relative overflow-hidden shadow-xl border-2">
              <div className="absolute top-6 left-6 text-primary/20">
                <Quote className="h-12 w-12" />
              </div>
              
              <CardContent className="p-8 md:p-12">
                <div className="grid grid-cols-1 lg:grid-cols-3 gap-8 items-center">
                  
                  {/* Testimonial Content */}
                  <div className="lg:col-span-2 order-2 lg:order-1">
                    {/* Rating */}
                    <div className="flex items-center gap-1 mb-4">
                      {renderStars(currentTestimonial?.rating || 5)}
                      <span className="ml-2 text-sm text-muted-foreground">
                        ({currentTestimonial?.rating}/5)
                      </span>
                    </div>

                    {/* Testimonial Text */}
                    <blockquote className="text-lg md:text-xl leading-relaxed text-slate-700 dark:text-slate-300 mb-6">
                      "{rtl ? currentTestimonial?.testimonialAr : currentTestimonial?.testimonial}"
                    </blockquote>

                    {/* Author Info */}
                    <div className="space-y-2">
                      <div className="font-semibold text-lg">
                        {rtl ? currentTestimonial?.nameAr : currentTestimonial?.name}
                      </div>
                      <div className="text-primary font-medium">
                        {rtl ? currentTestimonial?.roleAr : currentTestimonial?.role}
                      </div>
                      <div className="text-muted-foreground">
                        {rtl ? currentTestimonial?.companyAr : currentTestimonial?.company}
                      </div>
                      <div className="flex items-center gap-4 text-sm text-muted-foreground">
                        <div className="flex items-center gap-1">
                          <Calendar className="h-3 w-3" />
                          <span>{rtl ? 'تخرج' : 'Graduated'} {currentTestimonial?.graduationYear}</span>
                        </div>
                        <div className="flex items-center gap-1">
                          <MapPin className="h-3 w-3" />
                          <span>{rtl ? currentTestimonial?.locationAr : currentTestimonial?.location}</span>
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* Author Avatar & Program */}
                  <div className="order-1 lg:order-2 text-center">
                    {/* Avatar */}
                    <div className="w-24 h-24 md:w-32 md:h-32 mx-auto mb-4 rounded-full bg-gradient-to-br from-primary/20 to-primary/5 flex items-center justify-center">
                      <Users className="h-12 w-12 md:h-16 md:w-16 text-primary/40" />
                    </div>
                    
                    {/* Program Badge */}
                    <Badge variant="outline" className="mb-4">
                      <Award className="h-3 w-3 mr-1" />
                      {rtl ? currentTestimonial?.programAr : currentTestimonial?.program}
                    </Badge>
                  </div>
                </div>
              </CardContent>
            </Card>

            {/* Navigation Buttons */}
            <Button
              variant="outline"
              size="icon"
              className="absolute left-4 top-1/2 -translate-y-1/2 bg-white/80 backdrop-blur-sm shadow-lg"
              onClick={prevSlide}
            >
              <ChevronLeft className="h-4 w-4" />
            </Button>
            
            <Button
              variant="outline"
              size="icon"
              className="absolute right-4 top-1/2 -translate-y-1/2 bg-white/80 backdrop-blur-sm shadow-lg"
              onClick={nextSlide}
            >
              <ChevronRight className="h-4 w-4" />
            </Button>

            {/* Auto-play Control */}
            <Button
              variant="outline"
              size="icon"
              className="absolute bottom-4 right-4 bg-white/80 backdrop-blur-sm shadow-lg"
              onClick={() => setIsAutoPlay(!isAutoPlay)}
            >
              {isAutoPlay ? <Pause className="h-4 w-4" /> : <Play className="h-4 w-4" />}
            </Button>
          </div>

          {/* Carousel Indicators */}
          <div className="flex justify-center gap-2 mt-6">
            {featuredTestimonials.map((_, index) => (
              <button
                key={index}
                onClick={() => goToSlide(index)}
                className={cn(
                  "w-3 h-3 rounded-full transition-all duration-300",
                  index === currentIndex 
                    ? "bg-primary scale-125" 
                    : "bg-primary/30 hover:bg-primary/50"
                )}
              />
            ))}
          </div>
        </div>

        {/* All Testimonials Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">
          {allTestimonials.map((testimonial) => (
            <Card key={testimonial.id} className="card-hover">
              <CardContent className="p-6">
                {/* Rating */}
                <div className="flex items-center gap-1 mb-4">
                  {renderStars(testimonial.rating)}
                  <span className="ml-2 text-sm text-muted-foreground">
                    ({testimonial.rating}/5)
                  </span>
                </div>

                {/* Testimonial Preview */}
                <blockquote className="text-muted-foreground mb-4 line-clamp-4">
                  "{rtl ? testimonial.testimonialAr : testimonial.testimonial}"
                </blockquote>

                {/* Author */}
                <div className="flex items-center gap-3">
                  <div className="w-12 h-12 rounded-full bg-gradient-to-br from-primary/20 to-primary/5 flex items-center justify-center flex-shrink-0">
                    <Users className="h-6 w-6 text-primary/40" />
                  </div>
                  <div className="min-w-0 flex-1">
                    <div className="font-semibold truncate">
                      {rtl ? testimonial.nameAr : testimonial.name}
                    </div>
                    <div className="text-sm text-primary truncate">
                      {rtl ? testimonial.roleAr : testimonial.role}
                    </div>
                    <div className="text-xs text-muted-foreground truncate">
                      {rtl ? testimonial.companyAr : testimonial.company}
                    </div>
                  </div>
                </div>

                {/* Program Badge */}
                <Badge variant="outline" className="mt-4 w-full justify-center">
                  <Award className="h-3 w-3 mr-1" />
                  <span className="truncate">
                    {rtl ? testimonial.programAr : testimonial.program}
                  </span>
                </Badge>
              </CardContent>
            </Card>
          ))}
        </div>

        {/* Statistics */}
        <div className="mt-16 bg-gradient-to-r from-blue-600 to-green-600 rounded-2xl p-8 text-white">
          <div className="grid grid-cols-1 md:grid-cols-4 gap-8 text-center">
            <div>
              <div className="text-3xl font-bold mb-2">5000+</div>
              <div className="text-blue-100">
                {rtl ? 'خريج ناجح' : 'Successful Graduates'}
              </div>
            </div>
            <div>
              <div className="text-3xl font-bold mb-2">98%</div>
              <div className="text-blue-100">
                {rtl ? 'معدل التوظيف' : 'Job Placement Rate'}
              </div>
            </div>
            <div>
              <div className="text-3xl font-bold mb-2">4.8/5</div>
              <div className="text-blue-100">
                {rtl ? 'تقييم الطلاب' : 'Student Rating'}
              </div>
            </div>
            <div>
              <div className="text-3xl font-bold mb-2">50+</div>
              <div className="text-blue-100">
                {rtl ? 'شركة شريكة' : 'Partner Companies'}
              </div>
            </div>
          </div>
        </div>

        {/* Call to Action */}
        <div className="text-center mt-16">
          <h3 className="text-2xl font-bold mb-4">
            {rtl ? 'كن قصة النجاح القادمة' : 'Be the Next Success Story'}
          </h3>
          <p className="text-muted-foreground mb-6 max-w-2xl mx-auto">
            {rtl 
              ? 'انضم إلى آلاف الخريجين الناجحين واحصل على المهارات اللازمة لبناء مستقبل مهني مشرق'
              : 'Join thousands of successful graduates and gain the skills needed to build a bright professional future'
            }
          </p>
          <Button variant="skillence" size="lg">
            {rtl ? 'ابدأ رحلتك اليوم' : 'Start Your Journey Today'}
          </Button>
        </div>
      </div>
    </section>
  )
}