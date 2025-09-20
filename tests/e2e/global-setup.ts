import { chromium, FullConfig } from '@playwright/test'

/**
 * Global setup for E2E security testing
 * Prepares test environment and creates authenticated sessions
 */

async function globalSetup(config: FullConfig) {
  console.log('🔐 Setting up security E2E test environment...')
  
  // Launch browser for setup
  const browser = await chromium.launch()
  const page = await browser.newPage()
  
  try {
    // Setup environment variables for testing
    ;(process.env as any).NODE_ENV = 'test'
    ;(process.env as any).NEXTAUTH_URL = 'http://localhost:3000'
    
    // Navigate to the application
    await page.goto('http://localhost:3000')
    
    // Wait for the application to load
    await page.waitForLoadState('networkidle')
    
    // Create authenticated session for tests that require it
    await setupAuthenticatedSession(page)
    
    // Verify security headers are present
    await verifySecurityHeaders(page)
    
    console.log('✅ Security E2E test environment setup complete')
    
  } catch (error) {
    console.error('❌ Failed to setup security E2E test environment:', error)
    throw error
  } finally {
    await browser.close()
  }
}

async function setupAuthenticatedSession(page: any) {
  // Mock authenticated session
  await page.addInitScript(() => {
    // Mock NextAuth session
    window.localStorage.setItem('test-auth-token', 'authenticated-user-token')
    
    // Set secure session data (without sensitive tokens)
    window.localStorage.setItem('user-session', JSON.stringify({
      user: {
        id: 'test-user-id',
        name: 'Test User',
        email: 'test@example.com'
      },
      expires: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString()
    }))
  })
}

async function verifySecurityHeaders(page: any) {
  const response = await page.goto('http://localhost:3000')
  const headers = response?.headers() || {}
  
  // Check for essential security headers
  const requiredHeaders = [
    'x-frame-options',
    'x-content-type-options',
    'referrer-policy'
  ]
  
  const missingHeaders = requiredHeaders.filter(header => !headers[header])
  
  if (missingHeaders.length > 0) {
    console.warn('⚠️ Missing security headers:', missingHeaders)
  }
  
  // Check CSP header
  if (!headers['content-security-policy']) {
    console.warn('⚠️ Missing Content-Security-Policy header')
  }
}

export default globalSetup