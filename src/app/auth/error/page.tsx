import { Metadata } from 'next'
import Link from 'next/link'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { AlertTriangle, ArrowLeft, Home } from 'lucide-react'

export const metadata: Metadata = {
  title: 'Authentication Error | Meta Ads Intelligence Platform',
  description: 'An error occurred during authentication',
}

interface AuthErrorPageProps {
  searchParams: {
    error?: string
  }
}

const errorMessages: Record<string, string> = {
  Configuration: 'There is a problem with the server configuration.',
  AccessDenied: 'You do not have permission to sign in.',
  Verification: 'The verification token has expired or has already been used.',
  Default: 'An error occurred during authentication.',
  OAuthSignin: 'Error in constructing an authorization URL.',
  OAuthCallback: 'Error in handling the response from an OAuth provider.',
  OAuthCreateAccount: 'Could not create OAuth account.',
  EmailCreateAccount: 'Could not create email account.',
  Callback: 'Error in the OAuth callback handler route.',
  OAuthAccountNotLinked: 'Another account already exists with the same e-mail address.',
  EmailSignin: 'Sending the e-mail with the verification token failed.',
  CredentialsSignin: 'The authorize callback returned null in the Credentials provider.',
  SessionRequired: 'The content of this page requires you to be signed in at all times.',
}

export default function AuthErrorPage({ searchParams }: AuthErrorPageProps) {
  const error = searchParams.error || 'Default'
  const errorMessage = errorMessages[error] || errorMessages.Default

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-red-50 via-white to-orange-50 dark:from-gray-900 dark:via-gray-800 dark:to-red-900">
      <div className="max-w-md w-full space-y-8 p-8">
        <Card className="w-full shadow-lg border-destructive/20">
          <CardHeader className="text-center space-y-4">
            <div className="mx-auto h-20 w-20 flex items-center justify-center rounded-full bg-destructive/10">
              <AlertTriangle className="w-10 h-10 text-destructive" />
            </div>
            <div>
              <CardTitle className="text-2xl font-bold text-destructive">
                Authentication Error
              </CardTitle>
              <CardDescription className="mt-2">
                {errorMessage}
              </CardDescription>
            </div>
          </CardHeader>
          
          <CardContent className="space-y-4">
            <div className="text-center space-y-4">
              <p className="text-sm text-muted-foreground">
                Don't worry, this happens sometimes. You can try the following:
              </p>
              
              <ul className="text-sm text-left space-y-2 bg-muted/50 p-4 rounded-lg">
                <li className="flex items-start space-x-2">
                  <span className="text-primary">•</span>
                  <span>Make sure you have a stable internet connection</span>
                </li>
                <li className="flex items-start space-x-2">
                  <span className="text-primary">•</span>
                  <span>Clear your browser cache and cookies</span>
                </li>
                <li className="flex items-start space-x-2">
                  <span className="text-primary">•</span>
                  <span>Try using a different browser or incognito mode</span>
                </li>
                <li className="flex items-start space-x-2">
                  <span className="text-primary">•</span>
                  <span>Contact support if the problem persists</span>
                </li>
              </ul>
            </div>
            
            <div className="flex flex-col space-y-2">
              <Button asChild className="w-full">
                <Link href="/auth/login">
                  <ArrowLeft className="w-4 h-4 mr-2" />
                  Try Again
                </Link>
              </Button>
              
              <Button variant="outline" asChild className="w-full">
                <Link href="/">
                  <Home className="w-4 h-4 mr-2" />
                  Go Home
                </Link>
              </Button>
            </div>
            
            <div className="text-center">
              <p className="text-xs text-muted-foreground">
                Need help?{' '}
                <a 
                  href="mailto:support@metaadsintelligence.com" 
                  className="underline hover:text-primary"
                >
                  Contact our support team
                </a>
              </p>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  )
}