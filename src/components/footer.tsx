'use client'

import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import {
  Mail,
  Phone,
  MapPin,
  Facebook,
  Instagram,
  Linkedin,
  Youtube,
  Twitter,
  ArrowRight,
  GraduationCap,
  Award,
  Users,
  Building,
  BookOpen,
  Heart,
  ExternalLink,
} from 'lucide-react'
import { cn } from '@/lib/utils'

interface FooterProps {
  rtl?: boolean
}

const quickLinks = [
  { label: 'About Us', labelAr: 'من نحن', href: '#about' },
  { label: 'Our Programs', labelAr: 'برامجنا', href: '#programs' },
  { label: 'Admission', labelAr: 'القبول', href: '#admission' },
  { label: 'Campus Tour', labelAr: 'جولة في الحرم', href: '#tour' },
  { label: 'Student Life', labelAr: 'الحياة الطلابية', href: '#student-life' },
  { label: 'Career Services', labelAr: 'الخدمات المهنية', href: '#career' }
]

const programs = [
  { label: 'Heavy Machinery', labelAr: 'الآلات الثقيلة', href: '#heavy-machinery' },
  { label: 'Medical Training', labelAr: 'التدريب الطبي', href: '#medical' },
  { label: 'Digital Technology', labelAr: 'التكنولوجيا الرقمية', href: '#technology' },
  { label: 'Equipment Maintenance', labelAr: 'صيانة المعدات', href: '#maintenance' },
  { label: 'Web Development', labelAr: 'تطوير الويب', href: '#web-dev' },
  { label: 'View All Programs', labelAr: 'عرض جميع البرامج', href: '#programs' }
]

const supportLinks = [
  { label: 'Contact Us', labelAr: 'اتصل بنا', href: '#contact' },
  { label: 'FAQ', labelAr: 'الأسئلة الشائعة', href: '#faq' },
  { label: 'Student Portal', labelAr: 'بوابة الطلاب', href: '#portal' },
  { label: 'Online Learning', labelAr: 'التعلم الإلكتروني', href: '#online' },
  { label: 'Technical Support', labelAr: 'الدعم التقني', href: '#support' },
  { label: 'Feedback', labelAr: 'التعليقات', href: '#feedback' }
]

const legalLinks = [
  { label: 'Privacy Policy', labelAr: 'سياسة الخصوصية', href: '#privacy' },
  { label: 'Terms of Service', labelAr: 'شروط الخدمة', href: '#terms' },
  { label: 'Refund Policy', labelAr: 'سياسة الاسترداد', href: '#refund' },
  { label: 'Accessibility', labelAr: 'إمكانية الوصول', href: '#accessibility' }
]

const socialLinks = [
  { icon: Facebook, label: 'Facebook', href: '#', color: 'hover:text-blue-600' },
  { icon: Instagram, label: 'Instagram', href: '#', color: 'hover:text-pink-600' },
  { icon: Linkedin, label: 'LinkedIn', href: '#', color: 'hover:text-blue-700' },
  { icon: Youtube, label: 'YouTube', href: '#', color: 'hover:text-red-600' },
  { icon: Twitter, label: 'Twitter', href: '#', color: 'hover:text-blue-400' }
]

const achievements = [
  { icon: GraduationCap, value: '5000+', label: 'Graduates', labelAr: 'خريج' },
  { icon: Award, value: '50+', label: 'Programs', labelAr: 'برنامج' },
  { icon: Users, value: '98%', label: 'Job Placement', labelAr: 'توظيف' },
  { icon: Building, value: '120+', label: 'Partners', labelAr: 'شريك' }
]

export function Footer({ rtl = false }: FooterProps) {
  const handleNewsletterSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    // Handle newsletter subscription
  }

  const scrollToTop = () => {
    window.scrollTo({ top: 0, behavior: 'smooth' })
  }

  return (
    <footer className={cn("bg-slate-900 text-white", rtl && "rtl")}>
      {/* Main Footer Content */}
      <div className="container mx-auto px-4 py-16">
        <div className="grid grid-cols-1 lg:grid-cols-4 gap-12">
          
          {/* Company Info */}
          <div className="lg:col-span-1 space-y-6">
            <div>
              <div className="flex items-center gap-3 mb-4">
                <div className="bg-gradient-to-br from-blue-500 to-green-500 p-2 rounded-lg">
                  <GraduationCap className="h-6 w-6 text-white" />
                </div>
                <div>
                  <h3 className="text-2xl font-bold gradient-text">
                    Skillence Academy
                  </h3>
                  <p className="text-sm text-slate-400">
                    {rtl ? 'أكاديمية التميز المهني' : 'Professional Excellence Academy'}
                  </p>
                </div>
              </div>
              
              <p className="text-slate-300 leading-relaxed mb-6">
                {rtl 
                  ? 'نحن نقدم برامج تدريبية عالمية المستوى في الآلات الثقيلة والرعاية الصحية والتكنولوجيا، مما يمكن الطلاب من تحقيق أهدافهم المهنية بثقة.'
                  : 'We provide world-class training programs in heavy machinery, healthcare, and technology, empowering students to achieve their career goals with confidence.'
                }
              </p>

              {/* Contact Info */}
              <div className="space-y-3">
                <div className="flex items-center gap-3 text-sm">
                  <MapPin className="h-4 w-4 text-blue-400 flex-shrink-0" />
                  <span className="text-slate-300">
                    {rtl 
                      ? 'شارع الاستقلال، الجزائر العاصمة'
                      : '123 Independence St, Algiers'
                    }
                  </span>
                </div>
                <div className="flex items-center gap-3 text-sm">
                  <Phone className="h-4 w-4 text-green-400 flex-shrink-0" />
                  <span className="text-slate-300">+213 123 456 789</span>
                </div>
                <div className="flex items-center gap-3 text-sm">
                  <Mail className="h-4 w-4 text-purple-400 flex-shrink-0" />
                  <span className="text-slate-300">info@skillence.dz</span>
                </div>
              </div>
            </div>

            {/* Social Media */}
            <div>
              <h4 className="font-semibold mb-3">
                {rtl ? 'تابعنا على' : 'Follow Us'}
              </h4>
              <div className="flex gap-3">
                {socialLinks.map((social, index) => {
                  const Icon = social.icon
                  return (
                    <a
                      key={index}
                      href={social.href}
                      className={cn(
                        "p-2 bg-slate-800 rounded-lg transition-all duration-300 hover:scale-110",
                        social.color
                      )}
                      aria-label={social.label}
                    >
                      <Icon className="h-4 w-4" />
                    </a>
                  )
                })}
              </div>
            </div>
          </div>

          {/* Quick Links */}
          <div className="space-y-6">
            <h4 className="text-xl font-semibold">
              {rtl ? 'روابط سريعة' : 'Quick Links'}
            </h4>
            <ul className="space-y-3">
              {quickLinks.map((link, index) => (
                <li key={index}>
                  <a
                    href={link.href}
                    className="text-slate-300 hover:text-white transition-colors duration-300 flex items-center gap-2 group"
                  >
                    <ArrowRight className="h-3 w-3 group-hover:translate-x-1 transition-transform" />
                    {rtl ? link.labelAr : link.label}
                  </a>
                </li>
              ))}
            </ul>
          </div>

          {/* Programs */}
          <div className="space-y-6">
            <h4 className="text-xl font-semibold">
              {rtl ? 'برامجنا التدريبية' : 'Training Programs'}
            </h4>
            <ul className="space-y-3">
              {programs.map((program, index) => (
                <li key={index}>
                  <a
                    href={program.href}
                    className="text-slate-300 hover:text-white transition-colors duration-300 flex items-center gap-2 group"
                  >
                    <BookOpen className="h-3 w-3 group-hover:scale-110 transition-transform" />
                    {rtl ? program.labelAr : program.label}
                  </a>
                </li>
              ))}
            </ul>
          </div>

          {/* Support & Newsletter */}
          <div className="space-y-6">
            <div>
              <h4 className="text-xl font-semibold mb-4">
                {rtl ? 'الدعم والمساعدة' : 'Support & Help'}
              </h4>
              <ul className="space-y-3">
                {supportLinks.map((link, index) => (
                  <li key={index}>
                    <a
                      href={link.href}
                      className="text-slate-300 hover:text-white transition-colors duration-300 flex items-center gap-2 group"
                    >
                      <ExternalLink className="h-3 w-3 group-hover:rotate-45 transition-transform" />
                      {rtl ? link.labelAr : link.label}
                    </a>
                  </li>
                ))}
              </ul>
            </div>

            {/* Newsletter Subscription */}
            <div>
              <h4 className="text-xl font-semibold mb-4">
                {rtl ? 'النشرة الإخبارية' : 'Newsletter'}
              </h4>
              <p className="text-slate-300 text-sm mb-4">
                {rtl 
                  ? 'اشترك للحصول على آخر الأخبار والتحديثات'
                  : 'Subscribe for latest news and updates'
                }
              </p>
              <form onSubmit={handleNewsletterSubmit} className="space-y-3">
                <div className="relative">
                  <Input
                    type="email"
                    placeholder={rtl ? 'بريدك الإلكتروني' : 'Your email address'}
                    className="bg-slate-800 border-slate-700 text-white placeholder:text-slate-400 pr-12"
                  />
                  <Mail className="absolute right-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-slate-400" />
                </div>
                <Button 
                  type="submit" 
                  variant="skillence" 
                  className="w-full"
                >
                  {rtl ? 'اشتراك' : 'Subscribe'}
                </Button>
              </form>
            </div>
          </div>
        </div>

        {/* Achievements Section */}
        <div className="mt-16 pt-8 border-t border-slate-800">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-6">
            {achievements.map((achievement, index) => {
              const Icon = achievement.icon
              return (
                <div key={index} className="text-center">
                  <div className="inline-flex items-center justify-center w-12 h-12 bg-gradient-to-br from-blue-500 to-green-500 rounded-lg mb-3">
                    <Icon className="h-6 w-6 text-white" />
                  </div>
                  <div className="text-2xl font-bold text-white mb-1">
                    {achievement.value}
                  </div>
                  <div className="text-sm text-slate-400">
                    {rtl ? achievement.labelAr : achievement.label}
                  </div>
                </div>
              )
            })}
          </div>
        </div>
      </div>

      {/* Bottom Footer */}
      <div className="border-t border-slate-800 bg-slate-950">
        <div className="container mx-auto px-4 py-6">
          <div className="flex flex-col md:flex-row items-center justify-between gap-4">
            
            {/* Copyright */}
            <div className="text-center md:text-left">
              <p className="text-slate-400 text-sm">
                © 2024 Skillence Academy. {rtl ? 'جميع الحقوق محفوظة.' : 'All rights reserved.'}
              </p>
              <p className="text-slate-500 text-xs mt-1">
                {rtl 
                  ? 'مصنوع بـ ❤️ في الجزائر'
                  : 'Made with ❤️ in Algeria'
                }
              </p>
            </div>

            {/* Legal Links */}
            <div className="flex flex-wrap items-center gap-4 text-sm">
              {legalLinks.map((link, index) => (
                <a
                  key={index}
                  href={link.href}
                  className="text-slate-400 hover:text-white transition-colors duration-300"
                >
                  {rtl ? link.labelAr : link.label}
                </a>
              ))}
            </div>

            {/* Back to Top */}
            <Button
              onClick={scrollToTop}
              variant="outline"
              size="sm"
              className="border-slate-700 text-slate-400 hover:text-white hover:border-slate-600"
            >
              {rtl ? 'العودة للأعلى' : 'Back to Top'}
            </Button>
          </div>
        </div>
      </div>
    </footer>
  )
}