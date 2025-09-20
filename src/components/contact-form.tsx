'use client'

import { useState } from 'react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import {
  Mail,
  Phone,
  MapPin,
  Clock,
  Send,
  CheckCircle,
  User,
  MessageSquare,
  Calendar,
  Building,
  Globe,
  Facebook,
  Instagram,
  Linkedin,
  Youtube,
} from 'lucide-react'
import { cn } from '@/lib/utils'

interface ContactFormProps {
  rtl?: boolean
}

interface FormData {
  name: string
  email: string
  phone: string
  program: string
  message: string
  preferredContact: string
  inquiryType: string
}

const programs = [
  { id: 'emergency-medical', label: 'Emergency Medical Response', labelAr: 'الاستجابة الطبية للطوارئ' },
  { id: 'heavy-equipment', label: 'Heavy Equipment Operation', labelAr: 'تشغيل المعدات الثقيلة' },
  { id: 'healthcare-admin', label: 'Healthcare Administration', labelAr: 'إدارة الرعاية الصحية' },
  { id: 'digital-tech', label: 'Digital Technology', labelAr: 'التكنولوجيا الرقمية' },
  { id: 'equipment-maintenance', label: 'Equipment Maintenance', labelAr: 'صيانة المعدات' },
  { id: 'web-development', label: 'Web Development', labelAr: 'تطوير الويب' },
  { id: 'other', label: 'Other / General Inquiry', labelAr: 'أخرى / استفسار عام' }
]

const inquiryTypes = [
  { id: 'enrollment', label: 'Program Enrollment', labelAr: 'التسجيل في البرنامج' },
  { id: 'information', label: 'Program Information', labelAr: 'معلومات البرنامج' },
  { id: 'schedule', label: 'Schedule & Timing', labelAr: 'الجدول والتوقيت' },
  { id: 'fees', label: 'Fees & Payment', labelAr: 'الرسوم والدفع' },
  { id: 'campus-tour', label: 'Campus Tour', labelAr: 'جولة في الحرم الجامعي' },
  { id: 'partnership', label: 'Business Partnership', labelAr: 'شراكة تجارية' },
  { id: 'other', label: 'Other', labelAr: 'أخرى' }
]

const contactMethods = [
  { id: 'email', label: 'Email', labelAr: 'البريد الإلكتروني' },
  { id: 'phone', label: 'Phone Call', labelAr: 'مكالمة هاتفية' },
  { id: 'whatsapp', label: 'WhatsApp', labelAr: 'واتساب' },
  { id: 'no-preference', label: 'No Preference', labelAr: 'لا أفضلية' }
]

export function ContactForm({ rtl = false }: ContactFormProps) {
  const [formData, setFormData] = useState<FormData>({
    name: '',
    email: '',
    phone: '',
    program: '',
    message: '',
    preferredContact: '',
    inquiryType: ''
  })
  
  const [isSubmitting, setIsSubmitting] = useState(false)
  const [isSubmitted, setIsSubmitted] = useState(false)
  const [errors, setErrors] = useState<Partial<FormData>>({})

  const validateForm = (): boolean => {
    const newErrors: Partial<FormData> = {}

    if (!formData.name.trim()) {
      newErrors.name = rtl ? 'الاسم مطلوب' : 'Name is required'
    }

    if (!formData.email.trim()) {
      newErrors.email = rtl ? 'البريد الإلكتروني مطلوب' : 'Email is required'
    } else if (!/\S+@\S+\.\S+/.test(formData.email)) {
      newErrors.email = rtl ? 'صيغة البريد الإلكتروني غير صحيحة' : 'Invalid email format'
    }

    if (!formData.phone.trim()) {
      newErrors.phone = rtl ? 'رقم الهاتف مطلوب' : 'Phone number is required'
    }

    if (!formData.inquiryType) {
      newErrors.inquiryType = rtl ? 'نوع الاستفسار مطلوب' : 'Inquiry type is required'
    }

    if (!formData.message.trim()) {
      newErrors.message = rtl ? 'الرسالة مطلوبة' : 'Message is required'
    } else if (formData.message.trim().length < 10) {
      newErrors.message = rtl ? 'الرسالة قصيرة جداً' : 'Message is too short'
    }

    setErrors(newErrors)
    return Object.keys(newErrors).length === 0
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    
    if (!validateForm()) {
      return
    }

    setIsSubmitting(true)
    
    // Simulate API call
    await new Promise(resolve => setTimeout(resolve, 2000))
    
    setIsSubmitting(false)
    setIsSubmitted(true)
    
    // Reset form after success
    setTimeout(() => {
      setIsSubmitted(false)
      setFormData({
        name: '',
        email: '',
        phone: '',
        program: '',
        message: '',
        preferredContact: '',
        inquiryType: ''
      })
    }, 3000)
  }

  const handleInputChange = (field: keyof FormData, value: string) => {
    setFormData(prev => ({ ...prev, [field]: value }))
    // Clear error when user starts typing
    if (errors[field]) {
      setErrors(prev => ({ ...prev, [field]: undefined }))
    }
  }

  if (isSubmitted) {
    return (
      <section id="contact" className={cn("py-20 bg-gradient-to-br from-green-50 to-blue-50 dark:from-slate-900 dark:to-slate-800", rtl && "rtl")}>
        <div className="container mx-auto px-4">
          <div className="max-w-2xl mx-auto text-center">
            <Card className="border-green-200 bg-green-50 dark:bg-green-900/20">
              <CardContent className="p-12">
                <div className="inline-flex items-center justify-center w-16 h-16 bg-green-100 dark:bg-green-900 rounded-full mb-6">
                  <CheckCircle className="h-8 w-8 text-green-600" />
                </div>
                <h3 className="text-2xl font-bold text-green-800 dark:text-green-300 mb-4">
                  {rtl ? 'تم إرسال رسالتك بنجاح!' : 'Message Sent Successfully!'}
                </h3>
                <p className="text-green-700 dark:text-green-400 mb-6">
                  {rtl 
                    ? 'شكراً لتواصلك معنا. سيقوم فريقنا بالرد عليك خلال 24 ساعة.'
                    : 'Thank you for contacting us. Our team will respond to you within 24 hours.'
                  }
                </p>
                <div className="space-y-2 text-sm text-green-600 dark:text-green-400">
                  <p>{rtl ? 'رقم المرجع:' : 'Reference Number:'} #SKL-{Date.now().toString().slice(-6)}</p>
                  <p>{rtl ? 'تاريخ الإرسال:' : 'Submitted:'} {new Date().toLocaleDateString(rtl ? 'ar-SA' : 'en-US')}</p>
                </div>
              </CardContent>
            </Card>
          </div>
        </div>
      </section>
    )
  }

  return (
    <section id="contact" className={cn("py-20 bg-gradient-to-br from-gray-50 to-blue-50 dark:from-slate-900 dark:to-slate-800", rtl && "rtl")}>
      <div className="container mx-auto px-4">
        {/* Header */}
        <div className="text-center mb-16">
          <div className="inline-flex items-center justify-center w-16 h-16 bg-primary/10 rounded-full mb-6">
            <Mail className="h-8 w-8 text-primary" />
          </div>
          <h2 className="text-4xl font-bold mb-4 gradient-text">
            {rtl ? 'تواصل معنا' : 'Contact Us'}
          </h2>
          <p className="text-xl text-muted-foreground max-w-3xl mx-auto">
            {rtl 
              ? 'نحن هنا لمساعدتك في رحلتك التعليمية. تواصل معنا للحصول على معلومات حول برامجنا أو لحجز جولة في الحرم الجامعي'
              : 'We are here to help you in your educational journey. Contact us for information about our programs or to book a campus tour'
            }
          </p>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-12">
          {/* Contact Information */}
          <div className="space-y-8">
            <div>
              <h3 className="text-2xl font-bold mb-6">
                {rtl ? 'معلومات الاتصال' : 'Contact Information'}
              </h3>
              <div className="space-y-6">
                <Card className="card-hover">
                  <CardContent className="p-6">
                    <div className="flex items-start gap-4">
                      <div className="bg-blue-100 dark:bg-blue-900 p-3 rounded-lg">
                        <MapPin className="h-6 w-6 text-blue-600" />
                      </div>
                      <div>
                        <h4 className="font-semibold mb-2">
                          {rtl ? 'العنوان' : 'Address'}
                        </h4>
                        <p className="text-muted-foreground">
                          {rtl 
                            ? 'شارع الاستقلال، حي السلام\nالجزائر العاصمة، الجزائر 16000'
                            : '123 Independence Street, Peace District\nAlgiers, Algeria 16000'
                          }
                        </p>
                      </div>
                    </div>
                  </CardContent>
                </Card>

                <Card className="card-hover">
                  <CardContent className="p-6">
                    <div className="flex items-start gap-4">
                      <div className="bg-green-100 dark:bg-green-900 p-3 rounded-lg">
                        <Phone className="h-6 w-6 text-green-600" />
                      </div>
                      <div>
                        <h4 className="font-semibold mb-2">
                          {rtl ? 'الهاتف' : 'Phone'}
                        </h4>
                        <p className="text-muted-foreground">
                          +213 123 456 789<br />
                          +213 987 654 321
                        </p>
                      </div>
                    </div>
                  </CardContent>
                </Card>

                <Card className="card-hover">
                  <CardContent className="p-6">
                    <div className="flex items-start gap-4">
                      <div className="bg-purple-100 dark:bg-purple-900 p-3 rounded-lg">
                        <Mail className="h-6 w-6 text-purple-600" />
                      </div>
                      <div>
                        <h4 className="font-semibold mb-2">
                          {rtl ? 'البريد الإلكتروني' : 'Email'}
                        </h4>
                        <p className="text-muted-foreground">
                          info@skillence.dz<br />
                          admissions@skillence.dz
                        </p>
                      </div>
                    </div>
                  </CardContent>
                </Card>

                <Card className="card-hover">
                  <CardContent className="p-6">
                    <div className="flex items-start gap-4">
                      <div className="bg-orange-100 dark:bg-orange-900 p-3 rounded-lg">
                        <Clock className="h-6 w-6 text-orange-600" />
                      </div>
                      <div>
                        <h4 className="font-semibold mb-2">
                          {rtl ? 'ساعات العمل' : 'Office Hours'}
                        </h4>
                        <p className="text-muted-foreground">
                          {rtl 
                            ? 'السبت - الخميس: 8:00 ص - 6:00 م\nالجمعة: مغلق'
                            : 'Saturday - Thursday: 8:00 AM - 6:00 PM\nFriday: Closed'
                          }
                        </p>
                      </div>
                    </div>
                  </CardContent>
                </Card>
              </div>
            </div>

            {/* Social Media */}
            <div>
              <h4 className="font-semibold mb-4">
                {rtl ? 'تابعنا على' : 'Follow Us'}
              </h4>
              <div className="flex gap-3">
                <Button variant="outline" size="icon" className="hover:bg-blue-50 hover:border-blue-200">
                  <Facebook className="h-4 w-4" />
                </Button>
                <Button variant="outline" size="icon" className="hover:bg-pink-50 hover:border-pink-200">
                  <Instagram className="h-4 w-4" />
                </Button>
                <Button variant="outline" size="icon" className="hover:bg-blue-50 hover:border-blue-200">
                  <Linkedin className="h-4 w-4" />
                </Button>
                <Button variant="outline" size="icon" className="hover:bg-red-50 hover:border-red-200">
                  <Youtube className="h-4 w-4" />
                </Button>
              </div>
            </div>
          </div>

          {/* Contact Form */}
          <div className="lg:col-span-2">
            <Card className="shadow-xl">
              <CardHeader>
                <CardTitle className="text-2xl">
                  {rtl ? 'أرسل لنا رسالة' : 'Send us a Message'}
                </CardTitle>
              </CardHeader>
              <CardContent>
                <form onSubmit={handleSubmit} className="space-y-6">
                  {/* Personal Information */}
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                    <div className="space-y-2">
                      <Label htmlFor="name">
                        {rtl ? 'الاسم الكامل' : 'Full Name'} *
                      </Label>
                      <div className="relative">
                        <User className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                        <Input
                          id="name"
                          placeholder={rtl ? 'أدخل اسمك الكامل' : 'Enter your full name'}
                          value={formData.name}
                          onChange={(e) => handleInputChange('name', e.target.value)}
                          className={cn("pl-10", errors.name && "border-red-500")}
                        />
                      </div>
                      {errors.name && (
                        <p className="text-sm text-red-500">{errors.name}</p>
                      )}
                    </div>

                    <div className="space-y-2">
                      <Label htmlFor="email">
                        {rtl ? 'البريد الإلكتروني' : 'Email Address'} *
                      </Label>
                      <div className="relative">
                        <Mail className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                        <Input
                          id="email"
                          type="email"
                          placeholder={rtl ? 'أدخل بريدك الإلكتروني' : 'Enter your email address'}
                          value={formData.email}
                          onChange={(e) => handleInputChange('email', e.target.value)}
                          className={cn("pl-10", errors.email && "border-red-500")}
                        />
                      </div>
                      {errors.email && (
                        <p className="text-sm text-red-500">{errors.email}</p>
                      )}
                    </div>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                    <div className="space-y-2">
                      <Label htmlFor="phone">
                        {rtl ? 'رقم الهاتف' : 'Phone Number'} *
                      </Label>
                      <div className="relative">
                        <Phone className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                        <Input
                          id="phone"
                          placeholder={rtl ? 'أدخل رقم هاتفك' : 'Enter your phone number'}
                          value={formData.phone}
                          onChange={(e) => handleInputChange('phone', e.target.value)}
                          className={cn("pl-10", errors.phone && "border-red-500")}
                        />
                      </div>
                      {errors.phone && (
                        <p className="text-sm text-red-500">{errors.phone}</p>
                      )}
                    </div>

                    <div className="space-y-2">
                      <Label>
                        {rtl ? 'طريقة التواصل المفضلة' : 'Preferred Contact Method'}
                      </Label>
                      <Select value={formData.preferredContact} onValueChange={(value) => handleInputChange('preferredContact', value)}>
                        <SelectTrigger>
                          <SelectValue placeholder={rtl ? 'اختر طريقة التواصل' : 'Select contact method'} />
                        </SelectTrigger>
                        <SelectContent>
                          {contactMethods.map((method) => (
                            <SelectItem key={method.id} value={method.id}>
                              {rtl ? method.labelAr : method.label}
                            </SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                    </div>
                  </div>

                  {/* Inquiry Details */}
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                    <div className="space-y-2">
                      <Label>
                        {rtl ? 'نوع الاستفسار' : 'Inquiry Type'} *
                      </Label>
                      <Select value={formData.inquiryType} onValueChange={(value) => handleInputChange('inquiryType', value)}>
                        <SelectTrigger className={cn(errors.inquiryType && "border-red-500")}>
                          <SelectValue placeholder={rtl ? 'اختر نوع الاستفسار' : 'Select inquiry type'} />
                        </SelectTrigger>
                        <SelectContent>
                          {inquiryTypes.map((type) => (
                            <SelectItem key={type.id} value={type.id}>
                              {rtl ? type.labelAr : type.label}
                            </SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                      {errors.inquiryType && (
                        <p className="text-sm text-red-500">{errors.inquiryType}</p>
                      )}
                    </div>

                    <div className="space-y-2">
                      <Label>
                        {rtl ? 'البرنامج المهتم به' : 'Program of Interest'}
                      </Label>
                      <Select value={formData.program} onValueChange={(value) => handleInputChange('program', value)}>
                        <SelectTrigger>
                          <SelectValue placeholder={rtl ? 'اختر البرنامج' : 'Select program'} />
                        </SelectTrigger>
                        <SelectContent>
                          {programs.map((program) => (
                            <SelectItem key={program.id} value={program.id}>
                              {rtl ? program.labelAr : program.label}
                            </SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                    </div>
                  </div>

                  {/* Message */}
                  <div className="space-y-2">
                    <Label htmlFor="message">
                      {rtl ? 'رسالتك' : 'Your Message'} *
                    </Label>
                    <div className="relative">
                      <MessageSquare className="absolute left-3 top-3 h-4 w-4 text-muted-foreground" />
                      <textarea
                        id="message"
                        rows={5}
                        placeholder={rtl 
                          ? 'اكتب رسالتك هنا... أخبرنا كيف يمكننا مساعدتك'
                          : 'Write your message here... Tell us how we can help you'
                        }
                        value={formData.message}
                        onChange={(e) => handleInputChange('message', e.target.value)}
                        className={cn(
                          "w-full pl-10 pt-3 pr-3 pb-3 border rounded-md resize-none",
                          "focus:outline-none focus:ring-2 focus:ring-primary focus:border-transparent",
                          "dark:bg-background dark:border-input",
                          errors.message && "border-red-500"
                        )}
                      />
                    </div>
                    <div className="flex justify-between text-sm text-muted-foreground">
                      {errors.message && (
                        <p className="text-red-500">{errors.message}</p>
                      )}
                      <div className="ml-auto">
                        {formData.message.length}/500
                      </div>
                    </div>
                  </div>

                  {/* Submit Button */}
                  <Button 
                    type="submit" 
                    variant="skillence" 
                    size="lg" 
                    className="w-full" 
                    disabled={isSubmitting}
                  >
                    {isSubmitting ? (
                      <>
                        <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white mr-2" />
                        {rtl ? 'جاري الإرسال...' : 'Sending...'}
                      </>
                    ) : (
                      <>
                        <Send className="h-4 w-4 mr-2" />
                        {rtl ? 'إرسال الرسالة' : 'Send Message'}
                      </>
                    )}
                  </Button>
                </form>
              </CardContent>
            </Card>
          </div>
        </div>

        {/* Map Placeholder */}
        <div className="mt-16">
          <Card className="overflow-hidden">
            <div className="aspect-[21/9] bg-gradient-to-br from-blue-100 to-green-100 dark:from-blue-900/20 dark:to-green-900/20 flex items-center justify-center">
              <div className="text-center">
                <MapPin className="h-12 w-12 text-primary mx-auto mb-4" />
                <h3 className="text-xl font-semibold mb-2">
                  {rtl ? 'موقعنا على الخريطة' : 'Our Location'}
                </h3>
                <p className="text-muted-foreground">
                  {rtl 
                    ? 'نحن في قلب العاصمة، سهل الوصول بوسائل النقل العام'
                    : 'Located in the heart of the capital, easily accessible by public transport'
                  }
                </p>
              </div>
            </div>
          </Card>
        </div>
      </div>
    </section>
  )
}