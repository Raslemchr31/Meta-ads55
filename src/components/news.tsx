'use client'

import { useState } from 'react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import {
  Newspaper,
  Calendar,
  User,
  Clock,
  Search,
  Filter,
  Award,
  Users,
  BookOpen,
  Briefcase,
  Building,
  ChevronRight,
  Star,
  TrendingUp,
} from 'lucide-react'
import { cn } from '@/lib/utils'

interface NewsItem {
  id: string
  title: string
  titleAr: string
  summary: string
  summaryAr: string
  content: string
  contentAr: string
  category: 'academy-news' | 'student-success' | 'training-schedule' | 'certification' | 'partnerships'
  author: string
  authorAr: string
  publishDate: string
  readTime: number
  featured: boolean
  imageUrl: string
  tags: string[]
  tagsAr: string[]
}

interface NewsProps {
  rtl?: boolean
}

const newsCategories = [
  { 
    id: 'all', 
    label: 'All News', 
    labelAr: 'جميع الأخبار',
    icon: Newspaper,
    color: 'bg-blue-500'
  },
  { 
    id: 'academy-news', 
    label: 'Academy News', 
    labelAr: 'أخبار الأكاديمية',
    icon: Building,
    color: 'bg-green-500'
  },
  { 
    id: 'student-success', 
    label: 'Student Success', 
    labelAr: 'نجاح الطلاب',
    icon: Award,
    color: 'bg-yellow-500'
  },
  { 
    id: 'training-schedule', 
    label: 'Training Schedule', 
    labelAr: 'جدول التدريب',
    icon: BookOpen,
    color: 'bg-purple-500'
  },
  { 
    id: 'certification', 
    label: 'Certifications', 
    labelAr: 'الشهادات',
    icon: Star,
    color: 'bg-orange-500'
  },
  { 
    id: 'partnerships', 
    label: 'Industry Partnerships', 
    labelAr: 'الشراكات الصناعية',
    icon: Briefcase,
    color: 'bg-red-500'
  },
]

const newsItems: NewsItem[] = [
  {
    id: '1',
    title: 'Skillence Academy Achieves International Accreditation',
    titleAr: 'أكاديمية Skillence تحصل على الاعتماد الدولي',
    summary: 'We are proud to announce that Skillence Academy has received international accreditation for our training programs.',
    summaryAr: 'يسعدنا أن نعلن أن أكاديمية Skillence قد حصلت على الاعتماد الدولي لبرامجنا التدريبية.',
    content: 'This milestone represents years of dedication to excellence in vocational education and training. The accreditation validates our commitment to providing world-class education that meets international standards.',
    contentAr: 'هذا الإنجاز يمثل سنوات من التفاني في التميز في التعليم والتدريب المهني. يؤكد الاعتماد التزامنا بتوفير تعليم عالمي المستوى يلبي المعايير الدولية.',
    category: 'academy-news',
    author: 'Dr. Ahmed Hassan',
    authorAr: 'د. أحمد حسن',
    publishDate: '2024-02-20',
    readTime: 5,
    featured: true,
    imageUrl: '/api/placeholder/800/400',
    tags: ['Accreditation', 'International', 'Excellence'],
    tagsAr: ['الاعتماد', 'دولي', 'التميز']
  },
  {
    id: '2',
    title: 'Top Graduate Lands Management Position at Leading Construction Company',
    titleAr: 'خريج متفوق يحصل على منصب إداري في شركة إنشاءات رائدة',
    summary: 'Former student Mohamed Ali secures senior management role just six months after completing our Heavy Machinery Training program.',
    summaryAr: 'الطالب السابق محمد علي يحصل على دور إداري عالي بعد ستة أشهر فقط من إكمال برنامج تدريب الآلات الثقيلة.',
    content: 'Mohamed\'s journey from student to senior manager exemplifies the career advancement opportunities available through our comprehensive training programs.',
    contentAr: 'رحلة محمد من طالب إلى مدير عام تجسد فرص التقدم الوظيفي المتاحة من خلال برامجنا التدريبية الشاملة.',
    category: 'student-success',
    author: 'Sarah Johnson',
    authorAr: 'سارة جونسون',
    publishDate: '2024-02-18',
    readTime: 3,
    featured: true,
    imageUrl: '/api/placeholder/800/400',
    tags: ['Success Story', 'Career Growth', 'Heavy Machinery'],
    tagsAr: ['قصة نجاح', 'نمو مهني', 'آلات ثقيلة']
  },
  {
    id: '3',
    title: 'New Medical Training Program Launches Next Month',
    titleAr: 'برنامج التدريب الطبي الجديد ينطلق الشهر القادم',
    summary: 'Advanced Emergency Response and Healthcare Management program set to begin March 15th with limited enrollment.',
    summaryAr: 'برنامج متقدم للاستجابة للطوارئ وإدارة الرعاية الصحية سيبدأ في 15 مارس مع تسجيل محدود.',
    content: 'This 12-week intensive program covers emergency medical procedures, healthcare administration, and patient care management.',
    contentAr: 'هذا البرنامج المكثف لمدة 12 أسبوعاً يغطي الإجراءات الطبية الطارئة وإدارة الرعاية الصحية وإدارة رعاية المرضى.',
    category: 'training-schedule',
    author: 'Dr. Fatima Al-Zahra',
    authorAr: 'د. فاطمة الزهراء',
    publishDate: '2024-02-15',
    readTime: 4,
    featured: false,
    imageUrl: '/api/placeholder/800/400',
    tags: ['Medical Training', 'Emergency Response', 'Healthcare'],
    tagsAr: ['تدريب طبي', 'استجابة للطوارئ', 'رعاية صحية']
  },
  {
    id: '4',
    title: 'Government Partnership Brings New Certification Standards',
    titleAr: 'الشراكة الحكومية تجلب معايير شهادات جديدة',
    summary: 'Ministry of Education endorses our certification programs, adding government recognition to our credentials.',
    summaryAr: 'وزارة التعليم تدعم برامج الشهادات لدينا، مما يضيف اعترافاً حكومياً لأوراق اعتمادنا.',
    content: 'Students graduating from our programs will now receive dual certification - from Skillence Academy and the Ministry of Education.',
    contentAr: 'الطلاب الذين يتخرجون من برامجنا سيحصلون الآن على شهادة مزدوجة - من أكاديمية Skillence ووزارة التعليم.',
    category: 'certification',
    author: 'Admin Team',
    authorAr: 'فريق الإدارة',
    publishDate: '2024-02-12',
    readTime: 2,
    featured: false,
    imageUrl: '/api/placeholder/800/400',
    tags: ['Government', 'Certification', 'Recognition'],
    tagsAr: ['حكومة', 'شهادة', 'اعتراف']
  },
  {
    id: '5',
    title: 'Industry Leaders Join Advisory Board',
    titleAr: 'قادة الصناعة ينضمون إلى المجلس الاستشاري',
    summary: 'Five major companies commit to providing internships and job placement opportunities for our graduates.',
    summaryAr: 'خمس شركات كبرى تلتزم بتوفير فرص التدريب والتوظيف لخريجينا.',
    content: 'This partnership ensures our curriculum stays current with industry needs and provides direct pathways to employment.',
    contentAr: 'هذه الشراكة تضمن أن منهجنا يبقى محدثاً مع احتياجات الصناعة ويوفر مسارات مباشرة للتوظيف.',
    category: 'partnerships',
    author: 'Business Development',
    authorAr: 'تطوير الأعمال',
    publishDate: '2024-02-10',
    readTime: 3,
    featured: false,
    imageUrl: '/api/placeholder/800/400',
    tags: ['Partnerships', 'Industry', 'Employment'],
    tagsAr: ['شراكات', 'صناعة', 'توظيف']
  },
  {
    id: '6',
    title: 'Student Achieves Perfect Score in National Skills Competition',
    titleAr: 'طالب يحقق النتيجة الكاملة في مسابقة المهارات الوطنية',
    summary: 'Amina Khelil represents Skillence Academy at national level, winning gold medal in Healthcare Skills category.',
    summaryAr: 'أمينة خليل تمثل أكاديمية Skillence على المستوى الوطني، وتفوز بالميدالية الذهبية في فئة المهارات الصحية.',
    content: 'Amina\'s achievement highlights the quality of training and dedication of our students and instructors.',
    contentAr: 'إنجاز أمينة يسلط الضوء على جودة التدريب وتفاني طلابنا ومدربينا.',
    category: 'student-success',
    author: 'Competition Team',
    authorAr: 'فريق المسابقات',
    publishDate: '2024-02-08',
    readTime: 2,
    featured: true,
    imageUrl: '/api/placeholder/800/400',
    tags: ['Competition', 'Gold Medal', 'Healthcare'],
    tagsAr: ['مسابقة', 'ميدالية ذهبية', 'رعاية صحية']
  }
]

export function News({ rtl = false }: NewsProps) {
  const [selectedCategory, setSelectedCategory] = useState('all')
  const [searchTerm, setSearchTerm] = useState('')
  const [sortBy, setSortBy] = useState('date')

  const filteredNews = newsItems
    .filter(item => selectedCategory === 'all' || item.category === selectedCategory)
    .filter(item => {
      const searchContent = rtl 
        ? `${item.titleAr} ${item.summaryAr} ${item.tagsAr.join(' ')}`
        : `${item.title} ${item.summary} ${item.tags.join(' ')}`
      return searchContent.toLowerCase().includes(searchTerm.toLowerCase())
    })
    .sort((a, b) => {
      if (sortBy === 'date') {
        return new Date(b.publishDate).getTime() - new Date(a.publishDate).getTime()
      }
      return 0
    })

  const featuredNews = filteredNews.filter(item => item.featured)
  const regularNews = filteredNews.filter(item => !item.featured)

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleDateString(rtl ? 'ar-SA' : 'en-US', {
      year: 'numeric',
      month: 'long',
      day: 'numeric'
    })
  }

  const formatReadTime = (minutes: number) => {
    return rtl ? `${minutes} دقائق قراءة` : `${minutes} min read`
  }

  return (
    <section className={cn("py-20 bg-background", rtl && "rtl")}>
      <div className="container mx-auto px-4">
        {/* Header */}
        <div className="text-center mb-16">
          <div className="inline-flex items-center justify-center w-16 h-16 bg-primary/10 rounded-full mb-6">
            <Newspaper className="h-8 w-8 text-primary" />
          </div>
          <h2 className="text-4xl font-bold mb-4 gradient-text">
            {rtl ? 'الأخبار والتحديثات' : 'News & Updates'}
          </h2>
          <p className="text-xl text-muted-foreground max-w-3xl mx-auto">
            {rtl 
              ? 'ابق على اطلاع بآخر أخبار الأكاديمية، قصص نجاح الطلاب، والتطورات في برامجنا التدريبية'
              : 'Stay informed with the latest academy news, student success stories, and developments in our training programs'
            }
          </p>
        </div>

        {/* Search and Filter Bar */}
        <div className="flex flex-col lg:flex-row gap-4 mb-12">
          <div className="relative flex-1">
            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-muted-foreground" />
            <Input
              placeholder={rtl ? 'البحث في الأخبار...' : 'Search news...'}
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="pl-10"
            />
          </div>
          <div className="flex gap-4">
            <Select value={selectedCategory} onValueChange={setSelectedCategory}>
              <SelectTrigger className="w-48">
                <Filter className="h-4 w-4 mr-2" />
                <SelectValue placeholder={rtl ? 'تصفية حسب الفئة' : 'Filter by category'} />
              </SelectTrigger>
              <SelectContent>
                {newsCategories.map((category) => (
                  <SelectItem key={category.id} value={category.id}>
                    {rtl ? category.labelAr : category.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <Select value={sortBy} onValueChange={setSortBy}>
              <SelectTrigger className="w-40">
                <SelectValue placeholder={rtl ? 'ترتيب حسب' : 'Sort by'} />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="date">
                  {rtl ? 'التاريخ' : 'Date'}
                </SelectItem>
              </SelectContent>
            </Select>
          </div>
        </div>

        {/* Featured News */}
        {featuredNews.length > 0 && (
          <div className="mb-16">
            <h3 className="text-2xl font-bold mb-8 flex items-center gap-2">
              <TrendingUp className="h-6 w-6 text-primary" />
              {rtl ? 'الأخبار المميزة' : 'Featured News'}
            </h3>
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
              {featuredNews.map((item) => (
                <Card key={item.id} className="group card-hover overflow-hidden">
                  <div className="relative aspect-[16/9] overflow-hidden">
                    {/* Placeholder Image */}
                    <div className="w-full h-full bg-gradient-to-br from-primary/20 to-primary/5 flex items-center justify-center">
                      <div className="text-center">
                        <Newspaper className="h-12 w-12 text-primary/40 mx-auto mb-2" />
                        <p className="text-sm text-muted-foreground">
                          {rtl ? 'صورة إخبارية' : 'News Image'}
                        </p>
                      </div>
                    </div>
                    
                    {/* Featured Badge */}
                    <Badge className="absolute top-4 left-4 bg-yellow-500 text-white border-0">
                      <Star className="h-3 w-3 mr-1" />
                      {rtl ? 'مميز' : 'Featured'}
                    </Badge>

                    {/* Category Badge */}
                    <Badge 
                      className="absolute top-4 right-4 bg-black/50 text-white border-0"
                      variant="secondary"
                    >
                      {rtl 
                        ? newsCategories.find(c => c.id === item.category)?.labelAr 
                        : newsCategories.find(c => c.id === item.category)?.label
                      }
                    </Badge>
                  </div>

                  <CardHeader className="pb-4">
                    <CardTitle className="text-xl leading-tight group-hover:text-primary transition-colors">
                      {rtl ? item.titleAr : item.title}
                    </CardTitle>
                  </CardHeader>

                  <CardContent className="pt-0">
                    <p className="text-muted-foreground mb-4 line-clamp-2">
                      {rtl ? item.summaryAr : item.summary}
                    </p>

                    <div className="flex items-center justify-between text-sm text-muted-foreground mb-4">
                      <div className="flex items-center gap-4">
                        <div className="flex items-center gap-1">
                          <User className="h-3 w-3" />
                          <span>{rtl ? item.authorAr : item.author}</span>
                        </div>
                        <div className="flex items-center gap-1">
                          <Calendar className="h-3 w-3" />
                          <span>{formatDate(item.publishDate)}</span>
                        </div>
                        <div className="flex items-center gap-1">
                          <Clock className="h-3 w-3" />
                          <span>{formatReadTime(item.readTime)}</span>
                        </div>
                      </div>
                    </div>

                    <div className="flex flex-wrap gap-2 mb-4">
                      {(rtl ? item.tagsAr : item.tags).slice(0, 3).map((tag, index) => (
                        <Badge key={index} variant="outline" className="text-xs">
                          {tag}
                        </Badge>
                      ))}
                    </div>

                    <Button variant="outline" className="w-full group">
                      {rtl ? 'اقرأ المزيد' : 'Read More'}
                      <ChevronRight className="h-4 w-4 ml-2 group-hover:translate-x-1 transition-transform" />
                    </Button>
                  </CardContent>
                </Card>
              ))}
            </div>
          </div>
        )}

        {/* Regular News */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">
          {regularNews.map((item) => {
            const categoryInfo = newsCategories.find(c => c.id === item.category)
            const CategoryIcon = categoryInfo?.icon || Newspaper

            return (
              <Card key={item.id} className="group card-hover overflow-hidden">
                <div className="relative aspect-[16/9] overflow-hidden">
                  {/* Placeholder Image */}
                  <div className="w-full h-full bg-gradient-to-br from-muted/50 to-muted/20 flex items-center justify-center">
                    <div className="text-center">
                      <CategoryIcon className="h-10 w-10 text-muted-foreground/40 mx-auto mb-2" />
                      <p className="text-xs text-muted-foreground">
                        {rtl ? categoryInfo?.labelAr : categoryInfo?.label}
                      </p>
                    </div>
                  </div>
                  
                  {/* Category Badge */}
                  <Badge 
                    className="absolute top-3 right-3 bg-black/50 text-white border-0 text-xs"
                    variant="secondary"
                  >
                    {rtl ? categoryInfo?.labelAr : categoryInfo?.label}
                  </Badge>
                </div>

                <CardHeader className="pb-3">
                  <CardTitle className="text-lg leading-tight group-hover:text-primary transition-colors line-clamp-2">
                    {rtl ? item.titleAr : item.title}
                  </CardTitle>
                </CardHeader>

                <CardContent className="pt-0">
                  <p className="text-muted-foreground text-sm mb-4 line-clamp-3">
                    {rtl ? item.summaryAr : item.summary}
                  </p>

                  <div className="flex items-center justify-between text-xs text-muted-foreground mb-4">
                    <div className="flex items-center gap-1">
                      <Calendar className="h-3 w-3" />
                      <span>{formatDate(item.publishDate)}</span>
                    </div>
                    <div className="flex items-center gap-1">
                      <Clock className="h-3 w-3" />
                      <span>{formatReadTime(item.readTime)}</span>
                    </div>
                  </div>

                  <Button variant="ghost" className="w-full justify-between group p-0 h-auto">
                    <span className="text-sm font-medium">
                      {rtl ? 'اقرأ المزيد' : 'Read More'}
                    </span>
                    <ChevronRight className="h-4 w-4 group-hover:translate-x-1 transition-transform" />
                  </Button>
                </CardContent>
              </Card>
            )
          })}
        </div>

        {/* Empty State */}
        {filteredNews.length === 0 && (
          <div className="text-center py-16">
            <Newspaper className="h-16 w-16 text-muted-foreground mx-auto mb-4" />
            <h3 className="text-lg font-semibold mb-2">
              {rtl ? 'لا توجد أخبار متاحة' : 'No news available'}
            </h3>
            <p className="text-muted-foreground">
              {rtl 
                ? 'جرب تغيير فلاتر البحث أو تحقق مرة أخرى لاحقاً'
                : 'Try adjusting your search filters or check back later'
              }
            </p>
          </div>
        )}

        {/* Load More Button */}
        {filteredNews.length > 0 && (
          <div className="text-center mt-12">
            <Button variant="outline" size="lg">
              {rtl ? 'تحميل المزيد من الأخبار' : 'Load More News'}
            </Button>
          </div>
        )}
      </div>
    </section>
  )
}