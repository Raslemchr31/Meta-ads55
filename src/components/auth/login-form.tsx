'use client'

import { useState } from 'react'
import { signIn, getSession } from 'next-auth/react'
import { useRouter, useSearchParams } from 'next/navigation'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Loader2, Facebook, AlertCircle, CheckCircle } from 'lucide-react'
import { toast } from 'sonner'

export function LoginForm() {
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const router = useRouter()
  const searchParams = useSearchParams()
  const callbackUrl = searchParams.get('callbackUrl') || '/dashboard'

  const handleFacebookLogin = async () => {
    try {
      setIsLoading(true)
      setError(null)
      
      const result = await signIn('facebook', {
        callbackUrl,
        redirect: false,
      })
      
      if (result?.error) {
        setError('Failed to sign in with Facebook. Please try again.')
        toast.error('Login failed', {
          description: 'Please check your Facebook credentials and try again.',
        })
      } else if (result?.ok) {
        toast.success('Login successful!', {
          description: 'Welcome to Meta Ads Intelligence Platform.',
        })
        
        // Wait for session to be established
        const session = await getSession()
        if (session) {
          router.push(callbackUrl)
        }
      }
    } catch (err) {
      console.error('Login error:', err)
      setError('An unexpected error occurred. Please try again.')
      toast.error('Login error', {
        description: 'An unexpected error occurred. Please try again.',
      })
    } finally {
      setIsLoading(false)
    }
  }

  // Handle OAuth errors from URL params
  const oauthError = searchParams.get('error')
  
  return (
    <Card className="w-full max-w-md mx-auto shadow-lg">
      <CardHeader className="space-y-1 text-center">
        <CardTitle className="text-2xl font-bold">Welcome back</CardTitle>
        <CardDescription>
          Sign in with your Facebook account to continue
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {(error || oauthError) && (
          <Alert variant="destructive">
            <AlertCircle className="h-4 w-4" />
            <AlertDescription>
              {error || 'Authentication failed. Please try again.'}
            </AlertDescription>
          </Alert>
        )}
        
        <Button
          variant="facebook"
          className="w-full"
          size="lg"
          onClick={handleFacebookLogin}
          disabled={isLoading}
          loading={isLoading}
          leftIcon={!isLoading ? <Facebook className="w-5 h-5" /> : <Loader2 className="w-5 h-5 animate-spin" />}
        >
          {isLoading ? 'Signing in...' : 'Continue with Facebook'}
        </Button>
        
        <Button
          variant="outline"
          className="w-full"
          size="lg"
          onClick={() => router.push('/dashboard')}
          type="button"
        >
          Demo Mode (Skip Login)
        </Button>
        
        <div className="relative">
          <div className="absolute inset-0 flex items-center">
            <span className="w-full border-t" />
          </div>
          <div className="relative flex justify-center text-xs uppercase">
            <span className="bg-background px-2 text-muted-foreground">
              Secure login with OAuth 2.0
            </span>
          </div>
        </div>
        
        <div className="text-center space-y-2">
          <div className="flex items-center justify-center space-x-2 text-sm text-muted-foreground">
            <CheckCircle className="w-4 h-4 text-green-500" />
            <span>Access to your Facebook Pages</span>
          </div>
          <div className="flex items-center justify-center space-x-2 text-sm text-muted-foreground">
            <CheckCircle className="w-4 h-4 text-green-500" />
            <span>Advanced campaign analytics</span>
          </div>
          <div className="flex items-center justify-center space-x-2 text-sm text-muted-foreground">
            <CheckCircle className="w-4 h-4 text-green-500" />
            <span>AI-powered insights</span>
          </div>
        </div>
        
        <div className="text-xs text-muted-foreground text-center space-y-1">
          <p>
            We'll never post to your Facebook account or access your personal data.
          </p>
          <p>
            Your data is encrypted and stored securely.
          </p>
        </div>
      </CardContent>
    </Card>
  )
}