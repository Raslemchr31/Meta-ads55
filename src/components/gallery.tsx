'use client'

import { useState } from 'react'
import { Card, CardContent } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from '@/components/ui/dialog'
import {
  Building2,
  Users,
  GraduationCap,
  Stethoscope,
  Wrench,
  Monitor,
  ChevronLeft,
  ChevronRight,
  Eye,
  Calendar,
  MapPin,
} from 'lucide-react'
import { cn } from '@/lib/utils'

interface GalleryItem {
  id: string
  title: string
  titleAr: string
  description: string
  descriptionAr: string
  category: 'facilities' | 'training' | 'medical' | 'student-life'
  imageUrl: string
  date: string
  location: string
  locationAr: string
}

interface GalleryProps {
  rtl?: boolean
}

const galleryCategories = [
  { 
    id: 'all', 
    label: 'All Photos', 
    labelAr: 'جميع الصور',
    icon: Eye,
    color: 'bg-blue-500'
  },
  { 
    id: 'facilities', 
    label: 'Facilities', 
    labelAr: 'المرافق',
    icon: Building2,
    color: 'bg-green-500'
  },
  { 
    id: 'training', 
    label: 'Heavy Machinery Training', 
    labelAr: 'تدريب الآلات الثقيلة',
    icon: Wrench,
    color: 'bg-orange-500'
  },
  { 
    id: 'medical', 
    label: 'Medical Training', 
    labelAr: 'التدريب الطبي',
    icon: Stethoscope,
    color: 'bg-red-500'
  },
  { 
    id: 'student-life', 
    label: 'Student Life', 
    labelAr: 'الحياة الطلابية',
    icon: Users,
    color: 'bg-purple-500'
  },
]

const galleryItems: GalleryItem[] = [
  {
    id: '1',
    title: 'Modern Training Facility',
    titleAr: 'مرفق التدريب الحديث',
    description: 'State-of-the-art training facility equipped with the latest technology and safety standards for professional development.',
    descriptionAr: 'مرفق تدريب حديث مجهز بأحدث التقنيات ومعايير السلامة للتطوير المهني.',
    category: 'facilities',
    imageUrl: '/api/placeholder/600/400',
    date: '2024-01-15',
    location: 'Main Campus, Building A',
    locationAr: 'الحرم الرئيسي، المبنى أ'
  },
  {
    id: '2',
    title: 'Heavy Machinery Workshop',
    titleAr: 'ورشة الآلات الثقيلة',
    description: 'Comprehensive workshop for hands-on training with excavators, bulldozers, and construction equipment.',
    descriptionAr: 'ورشة شاملة للتدريب العملي على الحفارات والجرافات ومعدات البناء.',
    category: 'training',
    imageUrl: '/api/placeholder/600/400',
    date: '2024-01-20',
    location: 'Workshop Complex',
    locationAr: 'مجمع الورش'
  },
  {
    id: '3',
    title: 'Medical Simulation Lab',
    titleAr: 'مختبر المحاكاة الطبية',
    description: 'Advanced medical training laboratory with simulation equipment for healthcare professional development.',
    descriptionAr: 'مختبر تدريب طبي متقدم مع معدات المحاكاة لتطوير المهنيين الصحيين.',
    category: 'medical',
    imageUrl: '/api/placeholder/600/400',
    date: '2024-01-25',
    location: 'Medical Training Center',
    locationAr: 'مركز التدريب الطبي'
  },
  {
    id: '4',
    title: 'Student Accommodation',
    titleAr: 'سكن الطلاب',
    description: 'Comfortable and secure student housing facilities providing a supportive living environment.',
    descriptionAr: 'مرافق سكن طلابي مريحة وآمنة توفر بيئة معيشية داعمة.',
    category: 'student-life',
    imageUrl: '/api/placeholder/600/400',
    date: '2024-02-01',
    location: 'Residential Campus',
    locationAr: 'الحرم السكني'
  },
  {
    id: '5',
    title: 'Computer Training Lab',
    titleAr: 'مختبر التدريب على الحاسوب',
    description: 'Modern computer laboratory with latest software and hardware for digital skills development.',
    descriptionAr: 'مختبر كمبيوتر حديث مع أحدث البرامج والأجهزة لتطوير المهارات الرقمية.',
    category: 'facilities',
    imageUrl: '/api/placeholder/600/400',
    date: '2024-02-05',
    location: 'Technology Building',
    locationAr: 'مبنى التكنولوجيا'
  },
  {
    id: '6',
    title: 'Practical Training Session',
    titleAr: 'جلسة التدريب العملي',
    description: 'Students engaged in hands-on learning with professional instructors and industry-standard equipment.',
    descriptionAr: 'الطلاب منخرطون في التعلم العملي مع المدربين المحترفين والمعدات المطابقة لمعايير الصناعة.',
    category: 'training',
    imageUrl: '/api/placeholder/600/400',
    date: '2024-02-10',
    location: 'Training Ground',
    locationAr: 'ساحة التدريب'
  },
  {
    id: '7',
    title: 'Emergency Response Training',
    titleAr: 'تدريب الاستجابة للطوارئ',
    description: 'Specialized emergency response and first aid training for healthcare and safety professionals.',
    descriptionAr: 'تدريب متخصص في الاستجابة للطوارئ والإسعافات الأولية للمهنيين الصحيين وأخصائيي السلامة.',
    category: 'medical',
    imageUrl: '/api/placeholder/600/400',
    date: '2024-02-15',
    location: 'Emergency Training Center',
    locationAr: 'مركز تدريب الطوارئ'
  },
  {
    id: '8',
    title: 'Student Recreation Area',
    titleAr: 'منطقة ترفيه الطلاب',
    description: 'Dedicated recreation and relaxation area for students to unwind and socialize between training sessions.',
    descriptionAr: 'منطقة ترفيه واسترخاء مخصصة للطلاب للاستراحة والتواصل الاجتماعي بين جلسات التدريب.',
    category: 'student-life',
    imageUrl: '/api/placeholder/600/400',
    date: '2024-02-20',
    location: 'Student Center',
    locationAr: 'مركز الطلاب'
  },
  {
    id: '9',
    title: 'Library and Study Hall',
    titleAr: 'المكتبة وقاعة الدراسة',
    description: 'Quiet study environment with extensive resources and modern learning facilities for academic research.',
    descriptionAr: 'بيئة دراسة هادئة مع موارد واسعة ومرافق تعلم حديثة للبحث الأكاديمي.',
    category: 'facilities',
    imageUrl: '/api/placeholder/600/400',
    date: '2024-02-25',
    location: 'Academic Building',
    locationAr: 'المبنى الأكاديمي'
  }
]

export function Gallery({ rtl = false }: GalleryProps) {
  const [selectedCategory, setSelectedCategory] = useState('all')
  const [selectedImage, setSelectedImage] = useState<GalleryItem | null>(null)
  const [currentImageIndex, setCurrentImageIndex] = useState(0)

  const filteredItems = selectedCategory === 'all' 
    ? galleryItems 
    : galleryItems.filter(item => item.category === selectedCategory)

  const handleImageSelect = (item: GalleryItem) => {
    setSelectedImage(item)
    setCurrentImageIndex(filteredItems.findIndex(i => i.id === item.id))
  }

  const navigateImage = (direction: 'prev' | 'next') => {
    const newIndex = direction === 'prev' 
      ? (currentImageIndex - 1 + filteredItems.length) % filteredItems.length
      : (currentImageIndex + 1) % filteredItems.length
    
    setCurrentImageIndex(newIndex)
    setSelectedImage(filteredItems[newIndex])
  }

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleDateString(rtl ? 'ar-SA' : 'en-US', {
      year: 'numeric',
      month: 'long',
      day: 'numeric'
    })
  }

  return (
    <section className={cn("py-20 bg-gradient-to-br from-slate-50 to-blue-50 dark:from-slate-900 dark:to-slate-800", rtl && "rtl")}>
      <div className="container mx-auto px-4">
        {/* Header */}
        <div className="text-center mb-16">
          <div className="inline-flex items-center justify-center w-16 h-16 bg-primary/10 rounded-full mb-6">
            <Eye className="h-8 w-8 text-primary" />
          </div>
          <h2 className="text-4xl font-bold mb-4 gradient-text">
            {rtl ? 'معرض الصور' : 'Photo Gallery'}
          </h2>
          <p className="text-xl text-muted-foreground max-w-3xl mx-auto">
            {rtl 
              ? 'استكشف مرافقنا الحديثة وبرامج التدريب المتقدمة والحياة الطلابية النابضة بالحياة في أكاديمية Skillence'
              : 'Explore our modern facilities, advanced training programs, and vibrant student life at Skillence Academy'
            }
          </p>
        </div>

        {/* Category Filter */}
        <div className="flex flex-wrap justify-center gap-3 mb-12">
          {galleryCategories.map((category) => {
            const Icon = category.icon
            const isActive = selectedCategory === category.id
            
            return (
              <Button
                key={category.id}
                variant={isActive ? "default" : "outline"}
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

        {/* Gallery Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">
          {filteredItems.map((item) => (
            <Dialog key={item.id}>
              <DialogTrigger asChild>
                <Card 
                  className="group cursor-pointer card-hover overflow-hidden"
                  onClick={() => handleImageSelect(item)}
                >
                  <div className="relative aspect-[4/3] overflow-hidden">
                    {/* Placeholder Image */}
                    <div className="w-full h-full bg-gradient-to-br from-primary/20 to-primary/5 flex items-center justify-center">
                      <div className="text-center">
                        <GraduationCap className="h-12 w-12 text-primary/40 mx-auto mb-2" />
                        <p className="text-sm text-muted-foreground">
                          {rtl ? 'صورة تمثيلية' : 'Placeholder Image'}
                        </p>
                      </div>
                    </div>
                    
                    {/* Overlay */}
                    <div className="absolute inset-0 bg-black/60 opacity-0 group-hover:opacity-100 transition-opacity duration-300 flex items-center justify-center">
                      <div className="bg-white/20 backdrop-blur-sm rounded-full p-3">
                        <Eye className="h-6 w-6 text-white" />
                      </div>
                    </div>

                    {/* Category Badge */}
                    <Badge 
                      className="absolute top-3 left-3 bg-black/50 text-white border-0"
                      variant="secondary"
                    >
                      {rtl 
                        ? galleryCategories.find(c => c.id === item.category)?.labelAr 
                        : galleryCategories.find(c => c.id === item.category)?.label
                      }
                    </Badge>
                  </div>

                  <CardContent className="p-6">
                    <h3 className="font-semibold text-lg mb-2 line-clamp-2">
                      {rtl ? item.titleAr : item.title}
                    </h3>
                    <p className="text-muted-foreground text-sm mb-4 line-clamp-2">
                      {rtl ? item.descriptionAr : item.description}
                    </p>
                    
                    <div className="flex items-center justify-between text-xs text-muted-foreground">
                      <div className="flex items-center gap-1">
                        <Calendar className="h-3 w-3" />
                        <span>{formatDate(item.date)}</span>
                      </div>
                      <div className="flex items-center gap-1">
                        <MapPin className="h-3 w-3" />
                        <span>{rtl ? item.locationAr : item.location}</span>
                      </div>
                    </div>
                  </CardContent>
                </Card>
              </DialogTrigger>

              <DialogContent className="max-w-4xl">
                <DialogHeader>
                  <DialogTitle className="text-xl">
                    {rtl ? selectedImage?.titleAr : selectedImage?.title}
                  </DialogTitle>
                  <DialogDescription>
                    {rtl ? selectedImage?.descriptionAr : selectedImage?.description}
                  </DialogDescription>
                </DialogHeader>
                
                <div className="relative">
                  {/* Main Image */}
                  <div className="relative aspect-[16/10] bg-gradient-to-br from-primary/20 to-primary/5 rounded-lg overflow-hidden">
                    <div className="w-full h-full flex items-center justify-center">
                      <div className="text-center">
                        <Monitor className="h-16 w-16 text-primary/40 mx-auto mb-4" />
                        <h3 className="text-lg font-semibold text-muted-foreground mb-2">
                          {rtl ? selectedImage?.titleAr : selectedImage?.title}
                        </h3>
                        <p className="text-sm text-muted-foreground">
                          {rtl ? 'صورة عالية الجودة ستكون متاحة قريباً' : 'High-quality image coming soon'}
                        </p>
                      </div>
                    </div>
                  </div>

                  {/* Navigation Buttons */}
                  {filteredItems.length > 1 && (
                    <>
                      <Button
                        variant="outline"
                        size="icon"
                        className="absolute left-4 top-1/2 -translate-y-1/2 bg-white/80 backdrop-blur-sm"
                        onClick={() => navigateImage('prev')}
                      >
                        <ChevronLeft className="h-4 w-4" />
                      </Button>
                      <Button
                        variant="outline"
                        size="icon"
                        className="absolute right-4 top-1/2 -translate-y-1/2 bg-white/80 backdrop-blur-sm"
                        onClick={() => navigateImage('next')}
                      >
                        <ChevronRight className="h-4 w-4" />
                      </Button>
                    </>
                  )}
                </div>

                {/* Image Info */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-4 border-t">
                  <div className="space-y-2">
                    <div className="flex items-center gap-2 text-sm">
                      <Calendar className="h-4 w-4 text-muted-foreground" />
                      <span className="text-muted-foreground">
                        {rtl ? 'التاريخ:' : 'Date:'}
                      </span>
                      <span>{formatDate(selectedImage?.date || '')}</span>
                    </div>
                    <div className="flex items-center gap-2 text-sm">
                      <MapPin className="h-4 w-4 text-muted-foreground" />
                      <span className="text-muted-foreground">
                        {rtl ? 'الموقع:' : 'Location:'}
                      </span>
                      <span>{rtl ? selectedImage?.locationAr : selectedImage?.location}</span>
                    </div>
                  </div>
                  <div className="text-right">
                    <span className="text-sm text-muted-foreground">
                      {currentImageIndex + 1} / {filteredItems.length}
                    </span>
                  </div>
                </div>
              </DialogContent>
            </Dialog>
          ))}
        </div>

        {/* Empty State */}
        {filteredItems.length === 0 && (
          <div className="text-center py-16">
            <GraduationCap className="h-16 w-16 text-muted-foreground mx-auto mb-4" />
            <h3 className="text-lg font-semibold mb-2">
              {rtl ? 'لا توجد صور في هذه الفئة' : 'No images in this category'}
            </h3>
            <p className="text-muted-foreground">
              {rtl ? 'جرب تحديد فئة أخرى لعرض الصور المتاحة' : 'Try selecting another category to view available images'}
            </p>
          </div>
        )}
      </div>
    </section>
  )
}