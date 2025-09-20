import { NextResponse } from 'next/server'
import type { NextRequest } from 'next/server'

// Simple middleware without Redis dependencies for basic functionality
export function middleware(request: NextRequest) {
  // Allow all requests to pass through for now
  // This removes the Redis dependency that was causing the compilation errors
  return NextResponse.next()
}

export const config = {
  matcher: [
    /*
     * Match all request paths except for the ones starting with:
     * - api (API routes)
     * - _next/static (static files)
     * - _next/image (image optimization files)
     * - favicon.ico (favicon file)
     */
    '/((?!api|_next/static|_next/image|favicon.ico).*)',
  ],
}