'use client'

import { useState } from 'react'
import { Card, CardContent } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import {
  ChevronDown,
  ChevronUp,
  HelpCircle,
  Search,
  MessageCircle,
  Phone,
  Mail,
  Clock,
  FileQuestion,
  Users,
  GraduationCap,
  DollarSign,
} from 'lucide-react'
import { cn } from '@/lib/utils'

interface FAQ {
  id: string
  question: string
  questionAr: string
  answer: string
  answerAr: string
  category: 'general' | 'programs' | 'admission' | 'fees' | 'support'
  popular: boolean
}

interface FAQProps {
  rtl?: boolean
}

const faqCategories = [
  {
    id: 'all',
    label: 'All Questions',
    labelAr: 'جميع الأسئلة',
    icon: HelpCircle,
    color: 'bg-blue-500'
  },
  {
    id: 'general',
    label: 'General',
    labelAr: 'عام',
    icon: FileQuestion,
    color: 'bg-green-500'
  },
  {
    id: 'programs',
    label: 'Training Programs',
    labelAr: 'البرامج التدريبية',
    icon: GraduationCap,
    color: 'bg-purple-500'
  },
  {
    id: 'admission',
    label: 'Admission',
    labelAr: 'القبول',
    icon: Users,
    color: 'bg-orange-500'
  },
  {
    id: 'fees',
    label: 'Fees & Payment',
    labelAr: 'الرسوم والدفع',
    icon: DollarSign,
    color: 'bg-red-500'
  },
  {
    id: 'support',
    label: 'Student Support',
    labelAr: 'دعم الطلاب',
    icon: MessageCircle,
    color: 'bg-teal-500'
  }
]

const faqs: FAQ[] = [
  {
    id: '1',
    question: 'What programs does Skillence Academy offer?',
    questionAr: 'ما هي البرامج التي تقدمها أكاديمية Skillence؟',
    answer: 'We offer over 50 training programs in three main categories: Heavy Machinery Operation and Maintenance, Medical and Healthcare Training, and Digital Technology and Computer Skills. Each program is designed to meet industry standards and provide practical, hands-on experience.',
    answerAr: 'نقدم أكثر من 50 برنامج تدريبي في ثلاث فئات رئيسية: تشغيل وصيانة الآلات الثقيلة، والتدريب الطبي والرعاية الصحية، والتكنولوجيا الرقمية ومهارات الحاسوب. كل برنامج مصمم لتلبية معايير الصناعة وتوفير خبرة عملية ومباشرة.',
    category: 'programs',
    popular: true
  },
  {
    id: '2',
    question: 'Are your certifications internationally recognized?',
    questionAr: 'هل شهاداتكم معترف بها دولياً؟',
    answer: 'Yes, all our programs are internationally accredited and our certifications are recognized by industry leaders globally. We maintain partnerships with international certification bodies to ensure our graduates meet global standards.',
    answerAr: 'نعم، جميع برامجنا معتمدة دولياً وشهاداتنا معترف بها من قبل قادة الصناعة عالمياً. نحافظ على شراكات مع هيئات الاعتماد الدولية لضمان أن خريجينا يلبون المعايير العالمية.',
    category: 'programs',
    popular: true
  },
  {
    id: '3',
    question: 'What are the admission requirements?',
    questionAr: 'ما هي متطلبات القبول؟',
    answer: 'Admission requirements vary by program. Generally, you need to be at least 18 years old, have completed secondary education, and pass our assessment test. Some specialized programs may have additional prerequisites. We also consider your motivation and career goals during the selection process.',
    answerAr: 'متطلبات القبول تختلف حسب البرنامج. بشكل عام، تحتاج أن تكون بعمر 18 سنة على الأقل، وأن تكون قد أكملت التعليم الثانوي، وتجتاز اختبار التقييم الخاص بنا. بعض البرامج المتخصصة قد تحتاج متطلبات إضافية. نحن أيضاً نعتبر دافعيتك وأهدافك المهنية أثناء عملية الاختيار.',
    category: 'admission',
    popular: true
  },
  {
    id: '4',
    question: 'How much do the training programs cost?',
    questionAr: 'كم تكلف البرامج التدريبية؟',
    answer: 'Program fees range from 1,800 DZD to 3,500 DZD depending on the program duration and complexity. We offer flexible payment plans and scholarship opportunities for qualified students. Contact our admissions team for detailed pricing and available financial assistance.',
    answerAr: 'رسوم البرامج تتراوح من 1,800 دج إلى 3,500 دج حسب مدة البرنامج وتعقيده. نقدم خطط دفع مرنة وفرص منح دراسية للطلاب المؤهلين. اتصل بفريق القبول للحصول على تفاصيل الأسعار والمساعدة المالية المتاحة.',
    category: 'fees',
    popular: true
  },
  {
    id: '5',
    question: 'Do you provide job placement assistance?',
    questionAr: 'هل تقدمون مساعدة في التوظيف؟',
    answer: 'Yes, we have a 98% job placement rate! We maintain strong relationships with over 120 industry partners who actively recruit our graduates. Our career services team provides resume writing, interview preparation, and job matching services to all graduates.',
    answerAr: 'نعم، لدينا معدل توظيف 98%! نحافظ على علاقات قوية مع أكثر من 120 شريك صناعي يقومون بتوظيف خريجينا بنشاط. فريق الخدمات المهنية لدينا يقدم كتابة السيرة الذاتية وإعداد المقابلات وخدمات مطابقة الوظائف لجميع الخريجين.',
    category: 'support',
    popular: true
  },
  {
    id: '6',
    question: 'How long are the training programs?',
    questionAr: 'كم تستغرق البرامج التدريبية؟',
    answer: 'Program duration varies from 8 to 16 weeks, depending on the complexity and depth of the training. Most programs include both theoretical learning and extensive hands-on practice. We also offer part-time and evening schedules for working professionals.',
    answerAr: 'مدة البرامج تتراوح من 8 إلى 16 أسبوع، حسب تعقيد وعمق التدريب. معظم البرامج تشمل التعلم النظري والممارسة العملية الواسعة. نقدم أيضاً جداول بدوام جزئي ومسائية للمهنيين العاملين.',
    category: 'programs',
    popular: false
  },
  {
    id: '7',
    question: 'What facilities and equipment do you have?',
    questionAr: 'ما هي المرافق والمعدات التي تملكونها؟',
    answer: 'Our academy features state-of-the-art training facilities including fully equipped workshops for heavy machinery, modern medical simulation labs, computer labs with latest software, and comfortable student accommodation. All equipment meets international safety and quality standards.',
    answerAr: 'أكاديميتنا تضم مرافق تدريبية حديثة تشمل ورش مجهزة بالكامل للآلات الثقيلة، ومختبرات محاكاة طبية حديثة، ومختبرات كمبيوتر بأحدث البرامج، وسكن طلابي مريح. جميع المعدات تلبي معايير السلامة والجودة الدولية.',
    category: 'general',
    popular: false
  },
  {
    id: '8',
    question: 'Can I visit the academy before enrolling?',
    questionAr: 'هل يمكنني زيارة الأكاديمية قبل التسجيل؟',
    answer: 'Absolutely! We encourage prospective students to visit our campus. We offer guided tours every weekday from 9 AM to 4 PM, and special open house events monthly. You can see our facilities, meet instructors, and talk to current students.',
    answerAr: 'بالطبع! نشجع الطلاب المحتملين على زيارة حرمنا الجامعي. نقدم جولات مرشدة كل يوم من أيام الأسبوع من 9 صباحاً إلى 4 مساءً، وفعاليات الباب المفتوح الشهرية الخاصة. يمكنك رؤية مرافقنا ومقابلة المدربين والتحدث مع الطلاب الحاليين.',
    category: 'general',
    popular: false
  },
  {
    id: '9',
    question: 'Do you offer online or remote training options?',
    questionAr: 'هل تقدمون خيارات تدريب عبر الإنترنت أو عن بُعد؟',
    answer: 'For theoretical components, we offer hybrid learning options that combine in-person practical training with online lectures and resources. However, hands-on training with equipment requires in-person attendance for safety and effectiveness.',
    answerAr: 'للمكونات النظرية، نقدم خيارات تعلم مختلط تجمع بين التدريب العملي الحضوري والمحاضرات والموارد عبر الإنترنت. ومع ذلك، التدريب العملي بالمعدات يتطلب الحضور الشخصي للسلامة والفعالية.',
    category: 'programs',
    popular: false
  },
  {
    id: '10',
    question: 'What support services do you provide to students?',
    questionAr: 'ما هي خدمات الدعم التي تقدمونها للطلاب؟',
    answer: 'We provide comprehensive student support including academic counseling, career guidance, accommodation assistance, health services, library access, and 24/7 student helpline. We also have student clubs and recreational activities to ensure a well-rounded experience.',
    answerAr: 'نقدم دعم طلابي شامل يشمل الإرشاد الأكاديمي، التوجيه المهني، مساعدة السكن، الخدمات الصحية، الوصول للمكتبة، وخط مساعدة الطلاب على مدار 24/7. لدينا أيضاً نوادي طلابية وأنشطة ترفيهية لضمان تجربة متكاملة.',
    category: 'support',
    popular: false
  },
  {
    id: '11',
    question: 'Are there age restrictions for enrollment?',
    questionAr: 'هل هناك قيود عمرية للتسجيل؟',
    answer: 'The minimum age for enrollment is 18 years. There is no upper age limit - we welcome students of all ages who are motivated to learn and develop new skills. We have successfully trained students ranging from recent graduates to career changers in their 50s.',
    answerAr: 'الحد الأدنى للعمر للتسجيل هو 18 سنة. لا يوجد حد أقصى للعمر - نرحب بالطلاب من جميع الأعمار المتحمسين للتعلم وتطوير مهارات جديدة. لقد دربنا بنجاح طلاب يتراوحون من الخريجين الجدد إلى الذين يغيرون مهنهم في الخمسينات.',
    category: 'admission',
    popular: false
  },
  {
    id: '12',
    question: 'How can I apply for financial assistance or scholarships?',
    questionAr: 'كيف يمكنني التقدم للحصول على مساعدة مالية أو منح دراسية؟',
    answer: 'We offer merit-based scholarships and need-based financial assistance. Applications are available on our website and must be submitted with your enrollment application. Required documents include academic transcripts, financial statements, and a personal statement explaining your goals.',
    answerAr: 'نقدم منح دراسية على أساس الجدارة ومساعدة مالية على أساس الحاجة. الطلبات متاحة على موقعنا الإلكتروني ويجب تقديمها مع طلب التسجيل. الوثائق المطلوبة تشمل النصوص الأكاديمية، البيانات المالية، وبيان شخصي يوضح أهدافك.',
    category: 'fees',
    popular: false
  }
]

export function FAQ({ rtl = false }: FAQProps) {
  const [selectedCategory, setSelectedCategory] = useState('all')
  const [searchTerm, setSearchTerm] = useState('')
  const [expandedItems, setExpandedItems] = useState<Set<string>>(new Set())

  const filteredFAQs = faqs
    .filter(faq => selectedCategory === 'all' || faq.category === selectedCategory)
    .filter(faq => {
      const searchContent = rtl 
        ? `${faq.questionAr} ${faq.answerAr}`
        : `${faq.question} ${faq.answer}`
      return searchContent.toLowerCase().includes(searchTerm.toLowerCase())
    })

  const popularFAQs = filteredFAQs.filter(faq => faq.popular)
  const regularFAQs = filteredFAQs.filter(faq => !faq.popular)

  const toggleExpanded = (id: string) => {
    const newExpanded = new Set(expandedItems)
    if (newExpanded.has(id)) {
      newExpanded.delete(id)
    } else {
      newExpanded.add(id)
    }
    setExpandedItems(newExpanded)
  }

  const expandAll = () => {
    setExpandedItems(new Set(filteredFAQs.map(faq => faq.id)))
  }

  const collapseAll = () => {
    setExpandedItems(new Set())
  }

  return (
    <section id="faq" className={cn("py-20 bg-background", rtl && "rtl")}>
      <div className="container mx-auto px-4">
        {/* Header */}
        <div className="text-center mb-16">
          <div className="inline-flex items-center justify-center w-16 h-16 bg-primary/10 rounded-full mb-6">
            <HelpCircle className="h-8 w-8 text-primary" />
          </div>
          <h2 className="text-4xl font-bold mb-4 gradient-text">
            {rtl ? 'الأسئلة الشائعة' : 'Frequently Asked Questions'}
          </h2>
          <p className="text-xl text-muted-foreground max-w-3xl mx-auto">
            {rtl 
              ? 'نحن هنا للإجابة على جميع أسئلتك حول برامجنا التدريبية وخدماتنا التعليمية'
              : 'We are here to answer all your questions about our training programs and educational services'
            }
          </p>
        </div>

        {/* Search and Controls */}
        <div className="flex flex-col lg:flex-row gap-4 mb-12">
          <div className="relative flex-1">
            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-muted-foreground" />
            <Input
              placeholder={rtl ? 'ابحث في الأسئلة الشائعة...' : 'Search FAQ...'}
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="pl-10"
            />
          </div>
          <div className="flex gap-2">
            <Button onClick={expandAll} variant="outline" size="sm">
              {rtl ? 'توسيع الكل' : 'Expand All'}
            </Button>
            <Button onClick={collapseAll} variant="outline" size="sm">
              {rtl ? 'طي الكل' : 'Collapse All'}
            </Button>
          </div>
        </div>

        {/* Category Filter */}
        <div className="flex flex-wrap justify-center gap-3 mb-12">
          {faqCategories.map((category) => {
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

        {/* Popular FAQs */}
        {popularFAQs.length > 0 && (
          <div className="mb-16">
            <h3 className="text-2xl font-bold mb-8 flex items-center gap-2">
              <MessageCircle className="h-6 w-6 text-primary" />
              {rtl ? 'الأسئلة الأكثر شيوعاً' : 'Most Popular Questions'}
            </h3>
            <div className="space-y-4">
              {popularFAQs.map((faq) => {
                const isExpanded = expandedItems.has(faq.id)
                
                return (
                  <Card key={faq.id} className="overflow-hidden border-2 border-yellow-200 bg-yellow-50/50 dark:bg-yellow-900/10">
                    <CardContent className="p-0">
                      <button
                        onClick={() => toggleExpanded(faq.id)}
                        className="w-full p-6 text-left hover:bg-yellow-100/50 dark:hover:bg-yellow-900/20 transition-colors"
                      >
                        <div className="flex items-center justify-between gap-4">
                          <div className="flex items-start gap-3 flex-1">
                            <div className="bg-yellow-500 text-white p-2 rounded-lg flex-shrink-0 mt-1">
                              <HelpCircle className="h-4 w-4" />
                            </div>
                            <div className="flex-1">
                              <h4 className="font-semibold text-lg mb-1">
                                {rtl ? faq.questionAr : faq.question}
                              </h4>
                              {!isExpanded && (
                                <p className="text-muted-foreground text-sm line-clamp-2">
                                  {rtl ? faq.answerAr : faq.answer}
                                </p>
                              )}
                            </div>
                          </div>
                          <div className="flex-shrink-0">
                            {isExpanded ? (
                              <ChevronUp className="h-5 w-5 text-muted-foreground" />
                            ) : (
                              <ChevronDown className="h-5 w-5 text-muted-foreground" />
                            )}
                          </div>
                        </div>
                      </button>
                      
                      {isExpanded && (
                        <div className="px-6 pb-6">
                          <div className="pl-14">
                            <p className="text-muted-foreground leading-relaxed">
                              {rtl ? faq.answerAr : faq.answer}
                            </p>
                          </div>
                        </div>
                      )}
                    </CardContent>
                  </Card>
                )
              })}
            </div>
          </div>
        )}

        {/* Regular FAQs */}
        <div className="space-y-4">
          {regularFAQs.map((faq) => {
            const isExpanded = expandedItems.has(faq.id)
            const categoryInfo = faqCategories.find(c => c.id === faq.category)
            const CategoryIcon = categoryInfo?.icon || HelpCircle
            
            return (
              <Card key={faq.id} className="card-hover overflow-hidden">
                <CardContent className="p-0">
                  <button
                    onClick={() => toggleExpanded(faq.id)}
                    className="w-full p-6 text-left hover:bg-muted/50 transition-colors"
                  >
                    <div className="flex items-center justify-between gap-4">
                      <div className="flex items-start gap-3 flex-1">
                        <div className={cn(
                          "p-2 rounded-lg flex-shrink-0 mt-1",
                          categoryInfo?.color || 'bg-blue-500'
                        )}>
                          <CategoryIcon className="h-4 w-4 text-white" />
                        </div>
                        <div className="flex-1">
                          <h4 className="font-semibold text-lg mb-1">
                            {rtl ? faq.questionAr : faq.question}
                          </h4>
                          {!isExpanded && (
                            <p className="text-muted-foreground text-sm line-clamp-2">
                              {rtl ? faq.answerAr : faq.answer}
                            </p>
                          )}
                        </div>
                      </div>
                      <div className="flex-shrink-0">
                        {isExpanded ? (
                          <ChevronUp className="h-5 w-5 text-muted-foreground" />
                        ) : (
                          <ChevronDown className="h-5 w-5 text-muted-foreground" />
                        )}
                      </div>
                    </div>
                  </button>
                  
                  {isExpanded && (
                    <div className="px-6 pb-6">
                      <div className="pl-14">
                        <p className="text-muted-foreground leading-relaxed">
                          {rtl ? faq.answerAr : faq.answer}
                        </p>
                      </div>
                    </div>
                  )}
                </CardContent>
              </Card>
            )
          })}
        </div>

        {/* Empty State */}
        {filteredFAQs.length === 0 && (
          <div className="text-center py-16">
            <HelpCircle className="h-16 w-16 text-muted-foreground mx-auto mb-4" />
            <h3 className="text-lg font-semibold mb-2">
              {rtl ? 'لم نجد أسئلة تطابق بحثك' : 'No questions found matching your search'}
            </h3>
            <p className="text-muted-foreground mb-6">
              {rtl 
                ? 'جرب تغيير مصطلحات البحث أو اختيار فئة مختلفة'
                : 'Try changing your search terms or selecting a different category'
              }
            </p>
            <Button variant="outline" onClick={() => { setSearchTerm(''); setSelectedCategory('all'); }}>
              {rtl ? 'إعادة تعيين البحث' : 'Reset Search'}
            </Button>
          </div>
        )}

        {/* Contact Support */}
        <div className="mt-16 bg-gradient-to-r from-blue-600 to-green-600 rounded-2xl p-8 text-white">
          <div className="text-center mb-8">
            <h3 className="text-2xl font-bold mb-4">
              {rtl ? 'لم تجد إجابة لسؤالك؟' : 'Didn\'t find the answer to your question?'}
            </h3>
            <p className="text-blue-100 max-w-2xl mx-auto">
              {rtl 
                ? 'فريق الدعم لدينا متاح لمساعدتك. تواصل معنا وسنكون سعداء للإجابة على أي أسئلة إضافية'
                : 'Our support team is available to help you. Contact us and we\'ll be happy to answer any additional questions'
              }
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            <Card className="bg-white/10 border-white/20 text-white">
              <CardContent className="p-6 text-center">
                <Phone className="h-8 w-8 mx-auto mb-4 text-blue-200" />
                <h4 className="font-semibold mb-2">
                  {rtl ? 'اتصل بنا' : 'Call Us'}
                </h4>
                <p className="text-blue-100 text-sm mb-3">
                  {rtl ? 'متاح من 8 ص إلى 6 م' : 'Available 8 AM - 6 PM'}
                </p>
                <p className="font-medium">+213 123 456 789</p>
              </CardContent>
            </Card>

            <Card className="bg-white/10 border-white/20 text-white">
              <CardContent className="p-6 text-center">
                <Mail className="h-8 w-8 mx-auto mb-4 text-blue-200" />
                <h4 className="font-semibold mb-2">
                  {rtl ? 'راسلنا' : 'Email Us'}
                </h4>
                <p className="text-blue-100 text-sm mb-3">
                  {rtl ? 'رد خلال 24 ساعة' : 'Response within 24 hours'}
                </p>
                <p className="font-medium">info@skillence.dz</p>
              </CardContent>
            </Card>

            <Card className="bg-white/10 border-white/20 text-white">
              <CardContent className="p-6 text-center">
                <Clock className="h-8 w-8 mx-auto mb-4 text-blue-200" />
                <h4 className="font-semibold mb-2">
                  {rtl ? 'ساعات العمل' : 'Office Hours'}
                </h4>
                <p className="text-blue-100 text-sm mb-3">
                  {rtl ? 'السبت - الخميس' : 'Saturday - Thursday'}
                </p>
                <p className="font-medium">8:00 AM - 6:00 PM</p>
              </CardContent>
            </Card>
          </div>

          <div className="text-center mt-8">
            <Button variant="outline" size="lg" className="bg-white text-blue-600 hover:bg-blue-50">
              {rtl ? 'تواصل معنا الآن' : 'Contact Us Now'}
            </Button>
          </div>
        </div>
      </div>
    </section>
  )
}