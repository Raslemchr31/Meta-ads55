'use client'

import { useEffect } from 'react'
import { useRouter } from 'next/navigation'
import { useSession } from 'next-auth/react'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import Link from 'next/link'
import {
  BarChart3,
  Target,
  Users,
  TrendingUp,
  Zap,
  ArrowRight,
  Facebook,
  Shield,
  Sparkles,
  Rocket
} from 'lucide-react'

export default function HomePage() {
  const { data: session, status } = useSession()
  const router = useRouter()

  // Auto-redirect authenticated users to dashboard
  useEffect(() => {
    if (status === 'authenticated') {
      router.push('/dashboard')
    }
  }, [status, router])

  const features = [
    {
      icon: Target,
      title: 'Campaign Wizard',
      description: 'Create high-converting campaigns with our intelligent wizard'
    },
    {
      icon: Users,
      title: 'Team Collaboration',
      description: 'Real-time collaboration tools for marketing teams'
    },
    {
      icon: BarChart3,
      title: 'Advanced Analytics',
      description: 'Deep insights into campaign performance and ROI'
    },
    {
      icon: Zap,
      title: 'AI Optimization',
      description: 'AI-powered recommendations to boost campaign performance'
    }
  ]

  if (status === 'loading') {
    return (
      <div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100 flex items-center justify-center">
        <div className="animate-spin rounded-full h-32 w-32 border-b-2 border-blue-600"></div>
      </div>
    )
  }

  return (
    <main className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100">
      {/* Navigation */}
      <nav className="border-b bg-white/80 backdrop-blur-sm sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between h-16 items-center">
            <div className="flex items-center space-x-2">
              <Facebook className="h-8 w-8 text-blue-600" />
              <span className="text-xl font-bold text-gray-900">Meta Ads Intelligence</span>
            </div>
            <div className="flex items-center space-x-4">
              {session ? (
                <Button asChild>
                  <Link href="/dashboard">
                    Dashboard <ArrowRight className="ml-2 h-4 w-4" />
                  </Link>
                </Button>
              ) : (
                <Button asChild>
                  <Link href="/auth/login">
                    Sign In <ArrowRight className="ml-2 h-4 w-4" />
                  </Link>
                </Button>
              )}
            </div>
          </div>
        </div>
      </nav>

      {/* Hero Section */}
      <section className="py-20 px-4 sm:px-6 lg:px-8">
        <div className="max-w-7xl mx-auto text-center">
          <div className="flex justify-center mb-6">
            <div className="flex items-center space-x-2 bg-blue-100 px-4 py-2 rounded-full">
              <Sparkles className="h-5 w-5 text-blue-600" />
              <span className="text-blue-800 font-medium">v2.0 with Real-time Features</span>
            </div>
          </div>

          <h1 className="text-4xl md:text-6xl font-bold text-gray-900 mb-6">
            Meta Ads Intelligence
            <span className="bg-gradient-to-r from-blue-600 to-purple-600 bg-clip-text text-transparent block">
              Platform
            </span>
          </h1>

          <p className="text-xl text-gray-600 mb-8 max-w-3xl mx-auto">
            Comprehensive, real-time Meta/Facebook advertising intelligence platform for campaign analysis,
            competitor research, and automated reporting.
          </p>

          <div className="flex flex-col sm:flex-row gap-4 justify-center">
            {session ? (
              <Button size="lg" asChild className="bg-blue-600 hover:bg-blue-700">
                <Link href="/dashboard">
                  <Rocket className="mr-2 h-5 w-5" />
                  Go to Dashboard
                </Link>
              </Button>
            ) : (
              <>
                <Button size="lg" asChild className="bg-blue-600 hover:bg-blue-700">
                  <Link href="/auth/login">
                    <Facebook className="mr-2 h-5 w-5" />
                    Sign in with Meta
                  </Link>
                </Button>
                <Button size="lg" variant="outline" asChild>
                  <Link href="#features">
                    Learn More
                  </Link>
                </Button>
              </>
            )}
          </div>
        </div>
      </section>

      {/* Features Section */}
      <section id="features" className="py-20 px-4 sm:px-6 lg:px-8">
        <div className="max-w-7xl mx-auto">
          <div className="text-center mb-16">
            <h2 className="text-3xl md:text-4xl font-bold text-gray-900 mb-4">
              Powerful Features for Modern Marketers
            </h2>
            <p className="text-xl text-gray-600 max-w-2xl mx-auto">
              Everything you need to optimize your Meta advertising campaigns and drive better results.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-8">
            {features.map((feature, index) => {
              const Icon = feature.icon
              return (
                <Card key={index} className="text-center hover:shadow-lg transition-shadow">
                  <CardHeader>
                    <div className="mx-auto bg-blue-100 w-16 h-16 rounded-full flex items-center justify-center mb-4">
                      <Icon className="h-8 w-8 text-blue-600" />
                    </div>
                    <CardTitle className="text-xl">{feature.title}</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <CardDescription className="text-gray-600">
                      {feature.description}
                    </CardDescription>
                  </CardContent>
                </Card>
              )
            })}
          </div>
        </div>
      </section>

      {/* CTA Section */}
      <section className="py-20 px-4 sm:px-6 lg:px-8">
        <div className="max-w-4xl mx-auto">
          <Card className="bg-gradient-to-r from-blue-600 to-purple-600 text-white">
            <CardContent className="p-12 text-center">
              <Shield className="h-16 w-16 mx-auto mb-6 opacity-90" />
              <h2 className="text-3xl font-bold mb-4">
                Ready to Transform Your Meta Advertising?
              </h2>
              <p className="text-xl mb-8 opacity-90">
                Join thousands of marketers using our platform to optimize their campaigns and drive better ROI.
              </p>
              {session ? (
                <Button size="lg" variant="secondary" asChild>
                  <Link href="/dashboard">
                    <TrendingUp className="mr-2 h-5 w-5" />
                    View Dashboard
                  </Link>
                </Button>
              ) : (
                <Button size="lg" variant="secondary" asChild>
                  <Link href="/auth/login">
                    <Facebook className="mr-2 h-5 w-5" />
                    Get Started Now
                  </Link>
                </Button>
              )}
            </CardContent>
          </Card>
        </div>
      </section>

      {/* Footer */}
      <footer className="border-t bg-white py-12 px-4 sm:px-6 lg:px-8">
        <div className="max-w-7xl mx-auto text-center">
          <div className="flex justify-center items-center space-x-2 mb-4">
            <Facebook className="h-6 w-6 text-blue-600" />
            <span className="text-lg font-semibold text-gray-900">Meta Ads Intelligence Platform</span>
          </div>
          <p className="text-gray-600">
            Built with Claude Code • Real-time advertising intelligence for modern marketers
          </p>
        </div>
      </footer>
    </main>
  )
}