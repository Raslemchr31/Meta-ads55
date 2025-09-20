'use client'

import { SessionProvider } from 'next-auth/react'
import { ThemeProvider } from './theme-provider'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { ReactQueryDevtools } from '@tanstack/react-query-devtools'
import { useState, useEffect } from 'react'
import { ErrorBoundary } from './error-boundary'
import { Toaster } from 'sonner'
// import RealTimeProvider from './real-time-provider' // Temporarily disabled

interface ProvidersProps {
  children: React.ReactNode
  session?: any
}

// Create a stable query client to prevent hydration issues
let clientQueryClientSingleton: QueryClient | undefined = undefined

const getQueryClient = () => {
  if (typeof window === 'undefined') {
    // Server: always make a new query client
    return makeQueryClient()
  } else {
    // Browser: use singleton pattern to keep the same query client
    return (clientQueryClientSingleton ??= makeQueryClient())
  }
}

function makeQueryClient() {
  return new QueryClient({
    defaultOptions: {
      queries: {
        staleTime: 5 * 60 * 1000, // 5 minutes
        gcTime: 10 * 60 * 1000, // 10 minutes
        refetchOnWindowFocus: false,
        retry: (failureCount, error: any) => {
          // Don't retry on 4xx errors except 408, 429
          if (error?.status >= 400 && error?.status < 500 && ![408, 429].includes(error.status)) {
            return false
          }
          // Retry up to 3 times for other errors
          return failureCount < 3
        },
        retryDelay: (attemptIndex) => Math.min(1000 * 2 ** attemptIndex, 30000),
      },
      mutations: {
        retry: 1,
        onError: (error) => {
          console.error('Mutation error:', error)
        },
      },
    },
  })
}

export function Providers({ children, session }: ProvidersProps) {
  const queryClient = getQueryClient()

  return (
    <SessionProvider session={session}>
      <QueryClientProvider client={queryClient}>
        <ErrorBoundary>
          <ThemeProvider
            attribute="class"
            defaultTheme="light"
            enableSystem
            disableTransitionOnChange
          >
            {children}
            <Toaster position="top-right" richColors closeButton />
            {process.env.NODE_ENV === 'development' && (
              <ReactQueryDevtools initialIsOpen={false} />
            )}
          </ThemeProvider>
        </ErrorBoundary>
      </QueryClientProvider>
    </SessionProvider>
  )
}