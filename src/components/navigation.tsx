'use client'

import { useState, useEffect } from 'react'
import { Button } from '@/components/ui/button'
import {
  GraduationCap,
  Menu,
  X,
  Phone,
  Mail,
  MapPin,
  ChevronRight,
} from 'lucide-react'
import { cn } from '@/lib/utils'

interface NavigationProps {
  rtl?: boolean
}

const navigationItems = [
  { label: 'Home', labelAr: 'الرئيسية', href: '#home' },
  { label: 'Programs', labelAr: 'البرامج', href: '#programs' },
  { label: 'Gallery', labelAr: 'المرافق', href: '#gallery' },
  { label: 'News', labelAr: 'الأخبار', href: '#news' },
  { label: 'FAQ', labelAr: 'الأسئلة الشائعة', href: '#faq' },
  { label: 'Contact', labelAr: 'اتصل بنا', href: '#contact' },
]

export function Navigation({ rtl = false }: NavigationProps) {
  const [isOpen, setIsOpen] = useState(false)
  const [isScrolled, setIsScrolled] = useState(false)
  const [activeSection, setActiveSection] = useState('home')

  // Handle scroll effect
  useEffect(() => {
    const handleScroll = () => {
      setIsScrolled(window.scrollY > 50)
    }

    window.addEventListener('scroll', handleScroll)
    return () => window.removeEventListener('scroll', handleScroll)
  }, [])

  // Handle active section detection
  useEffect(() => {
    const handleScroll = () => {
      const sections = navigationItems.map(item => item.href.slice(1))
      const scrollPosition = window.scrollY + 100

      for (let i = sections.length - 1; i >= 0; i--) {
        const section = document.getElementById(sections[i])
        if (section && section.offsetTop <= scrollPosition) {
          setActiveSection(sections[i])
          break
        }
      }
    }

    window.addEventListener('scroll', handleScroll)
    return () => window.removeEventListener('scroll', handleScroll)
  }, [])

  const scrollToSection = (href: string) => {
    const sectionId = href.slice(1)
    const section = document.getElementById(sectionId)
    
    if (section) {
      const offsetTop = section.offsetTop - 80 // Account for fixed header
      window.scrollTo({
        top: offsetTop,
        behavior: 'smooth'
      })
    }
    
    setIsOpen(false)
  }

  return (
    <>
      {/* Top Contact Bar */}
      <div className="bg-slate-800 text-white py-2 hidden lg:block">
        <div className="container mx-auto px-4">
          <div className="flex items-center justify-between text-sm">
            <div className="flex items-center gap-6">
              <div className="flex items-center gap-2">
                <Phone className="h-3 w-3" />
                <span>+213 123 456 789</span>
              </div>
              <div className="flex items-center gap-2">
                <Mail className="h-3 w-3" />
                <span>info@skillence.dz</span>
              </div>
              <div className="flex items-center gap-2">
                <MapPin className="h-3 w-3" />
                <span>{rtl ? 'الجزائر العاصمة' : 'Algiers, Algeria'}</span>
              </div>
            </div>
            <div className="flex items-center gap-4">
              <span className="text-green-400">
                {rtl ? 'التسجيل مفتوح الآن!' : 'Enrollment Open Now!'}
              </span>
              <Button variant="skillence" size="sm">
                {rtl ? 'سجل الآن' : 'Apply Now'}
              </Button>
            </div>
          </div>
        </div>
      </div>

      {/* Main Navigation */}
      <nav className={cn(
        "fixed top-0 left-0 right-0 z-50 transition-all duration-300",
        isScrolled 
          ? "bg-white/95 backdrop-blur-md border-b border-gray-200 shadow-lg dark:bg-slate-900/95 dark:border-slate-700" 
          : "bg-transparent",
        rtl && "rtl"
      )}>
        <div className="container mx-auto px-4">
          <div className="flex items-center justify-between h-16 lg:h-20">
            
            {/* Logo */}
            <div className="flex items-center gap-3">
              <div className="bg-gradient-to-br from-blue-500 to-green-500 p-2 rounded-lg">
                <GraduationCap className="h-6 w-6 text-white" />
              </div>
              <div>
                <h1 className="text-xl font-bold gradient-text">
                  Skillence Academy
                </h1>
                <p className="text-xs text-muted-foreground hidden sm:block">
                  {rtl ? 'أكاديمية التميز المهني' : 'Professional Excellence Academy'}
                </p>
              </div>
            </div>

            {/* Desktop Navigation */}
            <div className="hidden lg:flex items-center gap-1">
              {navigationItems.map((item) => (
                <button
                  key={item.href}
                  onClick={() => scrollToSection(item.href)}
                  className={cn(
                    "px-4 py-2 rounded-lg text-sm font-medium transition-all duration-300 relative group",
                    activeSection === item.href.slice(1)
                      ? "text-primary bg-primary/10" 
                      : "text-slate-700 dark:text-slate-300 hover:text-primary hover:bg-primary/5"
                  )}
                >
                  {rtl ? item.labelAr : item.label}
                  {activeSection === item.href.slice(1) && (
                    <div className="absolute bottom-0 left-1/2 transform -translate-x-1/2 w-1 h-1 bg-primary rounded-full" />
                  )}
                </button>
              ))}
            </div>

            {/* CTA Button & Mobile Menu */}
            <div className="flex items-center gap-4">
              <Button variant="skillence" className="hidden sm:flex">
                {rtl ? 'احجز جولة' : 'Book Tour'}
              </Button>
              
              {/* Mobile Menu Button */}
              <Button
                variant="ghost"
                size="icon"
                onClick={() => setIsOpen(!isOpen)}
                className="lg:hidden"
              >
                {isOpen ? <X className="h-5 w-5" /> : <Menu className="h-5 w-5" />}
              </Button>
            </div>
          </div>
        </div>

        {/* Mobile Navigation Menu */}
        {isOpen && (
          <div className="lg:hidden bg-white dark:bg-slate-900 border-t border-gray-200 dark:border-slate-700 shadow-lg">
            <div className="container mx-auto px-4 py-4">
              <div className="space-y-2">
                {navigationItems.map((item) => (
                  <button
                    key={item.href}
                    onClick={() => scrollToSection(item.href)}
                    className={cn(
                      "w-full flex items-center justify-between px-4 py-3 rounded-lg text-left transition-all duration-300 group",
                      activeSection === item.href.slice(1)
                        ? "text-primary bg-primary/10 font-medium" 
                        : "text-slate-700 dark:text-slate-300 hover:text-primary hover:bg-primary/5"
                    )}
                  >
                    <span>{rtl ? item.labelAr : item.label}</span>
                    <ChevronRight className="h-4 w-4 group-hover:translate-x-1 transition-transform" />
                  </button>
                ))}
                
                {/* Mobile CTA */}
                <div className="pt-4 border-t border-gray-200 dark:border-slate-700">
                  <Button variant="skillence" className="w-full">
                    {rtl ? 'احجز جولة مجانية' : 'Book Free Tour'}
                  </Button>
                </div>

                {/* Mobile Contact Info */}
                <div className="pt-4 space-y-2 text-sm text-muted-foreground">
                  <div className="flex items-center gap-2">
                    <Phone className="h-3 w-3" />
                    <span>+213 123 456 789</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <Mail className="h-3 w-3" />
                    <span>info@skillence.dz</span>
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}
      </nav>

      {/* Spacer to prevent content from hiding behind fixed nav */}
      <div className="h-16 lg:h-20" />
    </>
  )
}