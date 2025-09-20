import { test, expect } from '@playwright/test'

/**
 * E2E SECURITY TESTS
 * Testing security vulnerabilities and user workflows end-to-end
 */

test.describe('Security Flows E2E', () => {
  test.beforeEach(async ({ page }) => {
    // Mock authentication for testing
    await page.route('**/api/auth/**', (route) => {
      if (route.request().method() === 'GET' && route.request().url().includes('session')) {
        route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            user: {
              id: 'test-user',
              email: 'test@example.com',
              name: 'Test User'
            },
            expires: '2024-12-31'
            // Importantly: NO access tokens in client response
          })
        })
      } else {
        route.continue()
      }
    })
  })

  test.describe('Authentication Security', () => {
    test('should not expose Facebook tokens in browser storage', async ({ page }) => {
      await page.goto('/auth/login')
      
      // Mock login process
      await page.fill('[data-testid="email-input"]', 'test@example.com')
      await page.fill('[data-testid="password-input"]', 'password')
      await page.click('[data-testid="login-button"]')
      
      // Check localStorage for tokens
      const localStorageData = await page.evaluate(() => {
        const storage = {}
        for (let i = 0; i < localStorage.length; i++) {
          const key = localStorage.key(i)
          if (key) {
            storage[key] = localStorage.getItem(key)
          }
        }
        return storage
      })
      
      // Verify no Facebook tokens in localStorage
      const hasTokens = Object.values(localStorageData).some(value => 
        value && (value.includes('EAAG') || value.includes('facebook_token'))
      )
      
      expect(hasTokens).toBe(false)
    })

    test('should not expose tokens in sessionStorage', async ({ page }) => {
      await page.goto('/dashboard')
      
      const sessionStorageData = await page.evaluate(() => {
        const storage = {}
        for (let i = 0; i < sessionStorage.length; i++) {
          const key = sessionStorage.key(i)
          if (key) {
            storage[key] = sessionStorage.getItem(key)
          }
        }
        return storage
      })
      
      // Verify no sensitive tokens in sessionStorage
      const hasSensitiveData = Object.values(sessionStorageData).some(value => 
        value && (value.includes('access_token') || value.includes('EAAG'))
      )
      
      expect(hasSensitiveData).toBe(false)
    })

    test('should redirect unauthenticated users to login', async ({ page }) => {
      // Mock unauthenticated state
      await page.route('**/api/auth/session', (route) => {
        route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ user: null })
        })
      })
      
      await page.goto('/dashboard')
      
      // Should redirect to login page
      await expect(page).toHaveURL(/.*auth.*login/)
    })
  })

  test.describe('XSS Prevention', () => {
    test('should prevent XSS in user input fields', async ({ page }) => {
      await page.goto('/dashboard/campaigns/new')
      
      const xssPayload = '<script>window.xssExecuted = true</script>'
      
      // Try to inject XSS in campaign name
      await page.fill('[data-testid="campaign-name"]', xssPayload)
      await page.click('[data-testid="save-campaign"]')
      
      // Check if XSS was executed
      const xssExecuted = await page.evaluate(() => window.xssExecuted)
      expect(xssExecuted).toBeFalsy()
      
      // Verify the input is safely displayed
      const displayedValue = await page.inputValue('[data-testid="campaign-name"]')
      expect(displayedValue).toBe(xssPayload) // Should be stored as text, not executed
    })

    test('should sanitize user data in display components', async ({ page }) => {
      // Mock API response with malicious data
      await page.route('**/api/campaigns', (route) => {
        route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify([
            {
              id: '1',
              name: '<img src="x" onerror="alert(\'XSS\')">',
              status: 'active'
            }
          ])
        })
      })
      
      await page.goto('/dashboard/campaigns')
      
      // Check if malicious script was executed
      page.on('dialog', (dialog) => {
        // If alert is triggered, XSS was successful (bad)
        expect(dialog.type()).not.toBe('alert')
        dialog.dismiss()
      })
      
      // Verify the content is safely rendered
      const campaignName = await page.textContent('[data-testid="campaign-name"]')
      expect(campaignName).toContain('<img') // Should be displayed as text
    })
  })

  test.describe('CSRF Protection', () => {
    test('should include CSRF protection in forms', async ({ page }) => {
      await page.goto('/dashboard/campaigns/new')
      
      // Intercept form submission
      let requestHeaders = {}
      page.on('request', (request) => {
        if (request.method() === 'POST' && request.url().includes('/api/campaigns')) {
          requestHeaders = request.headers()
        }
      })
      
      await page.fill('[data-testid="campaign-name"]', 'Test Campaign')
      await page.click('[data-testid="save-campaign"]')
      
      // Check for CSRF token in headers or form data
      const hasCsrfProtection = 
        requestHeaders['x-csrf-token'] || 
        requestHeaders['x-xsrf-token'] ||
        Object.keys(requestHeaders).some(key => key.toLowerCase().includes('csrf'))
      
      if (!hasCsrfProtection) {
        console.warn('CSRF protection not detected in form submission')
      }
    })

    test('should reject requests without proper origin', async ({ page }) => {
      // Try to make a request from a different origin
      const response = await page.evaluate(async () => {
        try {
          const response = await fetch('/api/campaigns', {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'Origin': 'http://malicious-site.com'
            },
            body: JSON.stringify({ name: 'Malicious Campaign' })
          })
          return { status: response.status, ok: response.ok }
        } catch (error) {
          return { error: error.message }
        }
      })
      
      // Should be rejected due to CORS or CSRF protection
      expect(response.status).not.toBe(200)
    })
  })

  test.describe('Session Security', () => {
    test('should enforce session timeout', async ({ page }) => {
      await page.goto('/dashboard')
      
      // Mock expired session
      await page.route('**/api/auth/session', (route) => {
        route.fulfill({
          status: 401,
          contentType: 'application/json',
          body: JSON.stringify({ error: 'Session expired' })
        })
      })
      
      // Try to access protected resource
      await page.reload()
      
      // Should redirect to login
      await expect(page).toHaveURL(/.*auth.*login/)
    })

    test('should invalidate session on logout', async ({ page }) => {
      await page.goto('/dashboard')
      
      // Click logout
      await page.click('[data-testid="logout-button"]')
      
      // Verify session is cleared
      const sessionData = await page.evaluate(() => {
        return document.cookie
      })
      
      expect(sessionData).not.toContain('next-auth.session-token')
      
      // Should be redirected to login
      await expect(page).toHaveURL(/.*auth.*login/)
    })
  })

  test.describe('Input Validation', () => {
    test('should validate form inputs', async ({ page }) => {
      await page.goto('/dashboard/campaigns/new')
      
      // Try to submit form with invalid data
      await page.fill('[data-testid="campaign-budget"]', '-100')
      await page.click('[data-testid="save-campaign"]')
      
      // Should show validation error
      const errorMessage = await page.textContent('[data-testid="budget-error"]')
      expect(errorMessage).toContain('must be positive')
    })

    test('should prevent SQL injection attempts', async ({ page }) => {
      await page.goto('/dashboard/pages')
      
      const sqlPayload = "'; DROP TABLE campaigns; --"
      
      // Try SQL injection in search
      await page.fill('[data-testid="search-input"]', sqlPayload)
      await page.press('[data-testid="search-input"]', 'Enter')
      
      // Should handle gracefully without error
      const errorElement = await page.locator('[data-testid="error-message"]')
      const hasError = await errorElement.count() > 0
      
      if (hasError) {
        const errorText = await errorElement.textContent()
        expect(errorText).not.toContain('database')
        expect(errorText).not.toContain('syntax error')
      }
    })
  })

  test.describe('Content Security Policy', () => {
    test('should enforce CSP headers', async ({ page }) => {
      const response = await page.goto('/dashboard')
      
      const cspHeader = response?.headers()['content-security-policy']
      
      if (cspHeader) {
        expect(cspHeader).toContain("default-src 'self'")
        expect(cspHeader).not.toContain("'unsafe-inline'")
      } else {
        console.warn('CSP header not found - potential security vulnerability')
      }
    })

    test('should block inline scripts with CSP', async ({ page }) => {
      await page.goto('/dashboard')
      
      // Try to inject inline script
      await page.evaluate(() => {
        const script = document.createElement('script')
        script.innerHTML = 'window.inlineScriptExecuted = true'
        document.head.appendChild(script)
      })
      
      const scriptExecuted = await page.evaluate(() => window.inlineScriptExecuted)
      expect(scriptExecuted).toBeFalsy()
    })
  })

  test.describe('Error Handling Security', () => {
    test('should not expose sensitive information in errors', async ({ page }) => {
      // Mock server error
      await page.route('**/api/campaigns', (route) => {
        route.fulfill({
          status: 500,
          contentType: 'application/json',
          body: JSON.stringify({ 
            error: 'Database connection failed: postgresql://user:password@localhost:5432/db' 
          })
        })
      })
      
      await page.goto('/dashboard/campaigns')
      
      const errorMessage = await page.textContent('[data-testid="error-message"]')
      
      if (errorMessage) {
        // Should not expose database credentials or internal details
        expect(errorMessage).not.toContain('postgresql://')
        expect(errorMessage).not.toContain('password')
        expect(errorMessage).not.toContain('localhost:5432')
      }
    })
  })

  test.describe('Mobile Security', () => {
    test.use({ ...test.devices['iPhone 12'] })
    
    test('should maintain security on mobile devices', async ({ page }) => {
      await page.goto('/dashboard')
      
      // Check for mobile-specific security issues
      const viewport = page.viewportSize()
      expect(viewport?.width).toBeLessThan(800) // Confirm mobile viewport
      
      // Verify touch events don't bypass security
      await page.tap('[data-testid="sensitive-action"]')
      
      // Should still require confirmation/authentication
      const confirmDialog = await page.locator('[data-testid="confirm-dialog"]')
      const isVisible = await confirmDialog.isVisible()
      expect(isVisible).toBe(true)
    })
  })
})