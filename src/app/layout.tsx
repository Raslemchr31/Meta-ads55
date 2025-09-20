import type { Metadata, Viewport } from 'next'
import { Space_Grotesk } from 'next/font/google'
import './globals.css'
import { Providers } from '@/components/providers'
import { Toaster } from '@/components/ui/sonner'

const spaceGrotesk = Space_Grotesk({
  subsets: ['latin'],
  variable: '--font-space-grotesk',
})

export const metadata: Metadata = {
  title: 'Meta Ads Intelligence Platform',
  description: 'Advanced AI-powered Facebook advertising intelligence and campaign management platform',
  keywords: ['Facebook Ads', 'Meta Ads', 'Digital Marketing', 'AI', 'Campaign Management', 'Analytics'],
  authors: [{ name: 'Meta Ads Intelligence Team' }],
  creator: 'Meta Ads Intelligence Platform',
  publisher: 'Meta Ads Intelligence Platform',
  robots: 'index, follow',
  openGraph: {
    title: 'Meta Ads Intelligence Platform',
    description: 'Advanced AI-powered Facebook advertising intelligence and campaign management platform',
    type: 'website',
    locale: 'en_US',
    url: process.env.NEXT_PUBLIC_APP_URL,
    siteName: 'Meta Ads Intelligence Platform',
  },
  twitter: {
    card: 'summary_large_image',
    title: 'Meta Ads Intelligence Platform',
    description: 'Advanced AI-powered Facebook advertising intelligence and campaign management platform',
  },
}

export const viewport: Viewport = {
  width: 'device-width',
  initialScale: 1,
  themeColor: [
    { media: '(prefers-color-scheme: light)', color: '#8013ec' },
    { media: '(prefers-color-scheme: dark)', color: '#8013ec' },
  ],
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="en" suppressHydrationWarning>
      <head>
        <link rel="icon" href="/favicon.ico" />
        <link rel="apple-touch-icon" href="/apple-touch-icon.png" />
        <link rel="manifest" href="/manifest.json" />
      </head>
      <body className={`${spaceGrotesk.variable} font-sans antialiased`}>
        <Providers>
          {children}
          <Toaster 
            position="top-right"
            richColors
            closeButton
            duration={4000}
          />
        </Providers>
      </body>
    </html>
  )
}