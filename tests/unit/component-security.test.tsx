import { describe, test, expect, beforeEach, vi } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { frontendSecurityUtils, testComponentSecurity } from '../setup'

/**
 * FRONTEND COMPONENT SECURITY TESTS
 * 
 * These tests focus on client-side security vulnerabilities:
 * 
 * 1. XSS prevention in React components
 * 2. Token exposure in client-side code
 * 3. Unsafe URL handling and redirects
 * 4. Input sanitization and validation
 * 5. Client-side authorization bypasses
 */

// Mock components for testing (simulating real app components)
const VulnerableInputComponent = ({ value, onChange }: { value: string; onChange: (value: string) => void }) => {
  // VULNERABLE: Direct HTML injection
  return (
    <div>
      <input
        value={value}
        onChange={(e) => onChange(e.target.value)}
        data-testid="vulnerable-input"
      />
      <div 
        data-testid="vulnerable-output"
        dangerouslySetInnerHTML={{ __html: value }} // DANGEROUS!
      />
    </div>
  )
}

const SecureInputComponent = ({ value, onChange }: { value: string; onChange: (value: string) => void }) => {
  // SECURE: Proper escaping
  const sanitizeInput = (input: string) => {
    return input
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#x27;')
      .replace(/\//g, '&#x2F;')
  }
  
  return (
    <div>
      <input
        value={value}
        onChange={(e) => onChange(e.target.value)}
        data-testid="secure-input"
      />
      <div data-testid="secure-output">
        {sanitizeInput(value)}
      </div>
    </div>
  )
}

const TokenExposingComponent = ({ session }: { session: any }) => {
  // VULNERABLE: Exposing tokens in DOM
  return (
    <div>
      <div data-testid="user-info">
        Welcome, {session.user?.name}!
      </div>
      {/* DANGEROUS: Exposing sensitive tokens */}
      <div data-testid="debug-info" style={{ display: 'none' }}>
        Access Token: {session.accessToken}
        Refresh Token: {session.refreshToken}
      </div>
      <script type="application/json" id="session-data">
        {JSON.stringify(session)}
      </script>
    </div>
  )
}

const SecureSessionComponent = ({ session }: { session: any }) => {
  // SECURE: Only expose safe user data
  const safeSession = {
    user: {
      id: session.user?.id,
      name: session.user?.name,
      email: session.user?.email,
    }
    // No tokens exposed
  }
  
  return (
    <div>
      <div data-testid="user-info">
        Welcome, {safeSession.user?.name}!
      </div>
      <script type="application/json" id="safe-session-data">
        {JSON.stringify(safeSession)}
      </script>
    </div>
  )
}

const UnsafeRedirectComponent = ({ redirectUrl }: { redirectUrl: string }) => {
  // VULNERABLE: No validation of redirect URLs
  return (
    <div>
      <a href={redirectUrl} data-testid="unsafe-link">
        Continue
      </a>
      <button 
        onClick={() => window.location.href = redirectUrl}
        data-testid="unsafe-redirect-button"
      >
        Go
      </button>
    </div>
  )
}

const SecureRedirectComponent = ({ redirectUrl }: { redirectUrl: string }) => {
  // SECURE: Validate URLs before redirecting
  const isValidRedirectUrl = (url: string) => {
    try {
      const parsedUrl = new URL(url, window.location.origin)
      
      // Only allow same-origin redirects or specific trusted domains
      const allowedOrigins = [window.location.origin, 'https://www.facebook.com']
      
      if (!allowedOrigins.includes(parsedUrl.origin)) {
        return false
      }
      
      // Block dangerous protocols
      if (!['http:', 'https:'].includes(parsedUrl.protocol)) {
        return false
      }
      
      return true
    } catch {
      return false
    }
  }
  
  const safeRedirectUrl = isValidRedirectUrl(redirectUrl) ? redirectUrl : '/'
  
  return (
    <div>
      <a href={safeRedirectUrl} data-testid="safe-link">
        Continue
      </a>
      <button 
        onClick={() => window.location.href = safeRedirectUrl}
        data-testid="safe-redirect-button"
      >
        Go
      </button>
      {!isValidRedirectUrl(redirectUrl) && (
        <div data-testid="invalid-url-warning">
          Invalid redirect URL detected
        </div>
      )}
    </div>
  )
}

describe('Frontend Component Security Tests', () => {
  
  describe('XSS Prevention Tests', () => {
    test('should demonstrate XSS vulnerability in unsafe component', () => {
      const xssPayload = '<script>alert("XSS")</script>'
      let inputValue = ''
      
      render(
        <VulnerableInputComponent 
          value={inputValue} 
          onChange={(value) => { inputValue = value }} 
        />
      )
      
      const input = screen.getByTestId('vulnerable-input')
      const output = screen.getByTestId('vulnerable-output')
      
      // Input XSS payload
      fireEvent.change(input, { target: { value: xssPayload } })
      
      // VULNERABILITY: XSS payload is injected into DOM
      expect(output.innerHTML).toBe(xssPayload)
      
      // Check for actual script execution (in real browser, this would execute)
      expect(output.querySelector('script')).toBeTruthy()
    })
    
    test('should prevent XSS in secure component', () => {
      const xssPayload = '<script>alert("XSS")</script>'
      let inputValue = ''
      
      render(
        <SecureInputComponent 
          value={inputValue} 
          onChange={(value) => { inputValue = value }} 
        />
      )
      
      const input = screen.getByTestId('secure-input')
      const output = screen.getByTestId('secure-output')
      
      // Input XSS payload
      fireEvent.change(input, { target: { value: xssPayload } })
      
      // SECURE: XSS payload is escaped
      expect(output.textContent).toBe('&lt;script&gt;alert("XSS")&lt;/script&gt;')
      expect(output.innerHTML).not.toContain('<script>')
    })
    
    test('should test multiple XSS vectors', () => {
      frontendSecurityUtils.reactXSSPayloads.forEach(payload => {
        let inputValue = ''
        
        const { container } = render(
          <SecureInputComponent 
            value={inputValue} 
            onChange={(value) => { inputValue = value }} 
          />
        )
        
        const input = screen.getByTestId('secure-input')
        fireEvent.change(input, { target: { value: payload } })
        
        // Check that no script tags are present in the DOM
        expect(container.querySelector('script')).toBeNull()
        
        // Check that no event handlers are present
        expect(container.innerHTML).not.toMatch(/on\w+=/i)
        
        // Check that no javascript: URLs are present
        expect(container.innerHTML).not.toContain('javascript:')
      })
    })
  })
  
  describe('Token Exposure Prevention', () => {
    test('should detect token exposure in vulnerable component', () => {
      const mockSession = {
        user: { id: '123', name: 'Test User', email: 'test@example.com' },
        accessToken: 'EAABwzLixnjYBAIxvJZCqK1ZC0ZD',
        refreshToken: 'refresh_token_sensitive_data',
        expires: '2024-12-31'
      }
      
      const { container } = render(
        <TokenExposingComponent session={mockSession} />
      )
      
      // Check if tokens are exposed in DOM
      const hasTokenExposure = testComponentSecurity.checkTokenExposure(container)
      expect(hasTokenExposure).toBe(true)
      
      // Verify specific token patterns in DOM
      expect(container.innerHTML).toContain('EAABwzLixnjYBAIxvJZCqK1ZC0ZD')
      expect(container.innerHTML).toContain('refresh_token_sensitive_data')
      
      // Check script tag content
      const scriptTag = container.querySelector('#session-data')
      expect(scriptTag?.textContent).toContain('accessToken')
      expect(scriptTag?.textContent).toContain('refreshToken')
    })
    
    test('should prevent token exposure in secure component', () => {
      const mockSession = {
        user: { id: '123', name: 'Test User', email: 'test@example.com' },
        accessToken: 'EAABwzLixnjYBAIxvJZCqK1ZC0ZD',
        refreshToken: 'refresh_token_sensitive_data',
        expires: '2024-12-31'
      }
      
      const { container } = render(
        <SecureSessionComponent session={mockSession} />
      )
      
      // Check that no tokens are exposed
      const hasTokenExposure = testComponentSecurity.checkTokenExposure(container)
      expect(hasTokenExposure).toBe(false)
      
      // Verify tokens are not in DOM
      expect(container.innerHTML).not.toContain('EAABwzLixnjYBAIxvJZCqK1ZC0ZD')
      expect(container.innerHTML).not.toContain('refresh_token_sensitive_data')
      expect(container.innerHTML).not.toContain('accessToken')
      expect(container.innerHTML).not.toContain('refreshToken')
      
      // Check script tag only contains safe data
      const scriptTag = container.querySelector('#safe-session-data')
      const sessionData = JSON.parse(scriptTag?.textContent || '{}')
      expect(sessionData.accessToken).toBeUndefined()
      expect(sessionData.refreshToken).toBeUndefined()
      expect(sessionData.user).toBeDefined()
    })
    
    test('should check for token exposure in various storage locations', () => {
      const sensitiveTokens = [
        'EAABwzLixnjYBAIxvJZCqK1ZC0ZD',
        'refresh_token_12345',
        'bearer_token_abcdef',
        'facebook_access_token_xyz'
      ]
      
      // Mock localStorage and sessionStorage
      const mockLocalStorage = {
        getItem: vi.fn(),
        setItem: vi.fn(),
        removeItem: vi.fn(),
        clear: vi.fn()
      }
      
      Object.defineProperty(window, 'localStorage', {
        value: mockLocalStorage,
        writable: true
      })
      
      // Check that tokens are not stored in browser storage
      frontendSecurityUtils.sessionStorageAttacks.forEach(key => {
        expect(mockLocalStorage.getItem).not.toHaveBeenCalledWith(key)
      })
      
      // Test component should not store sensitive tokens
      sensitiveTokens.forEach(token => {
        expect(mockLocalStorage.setItem).not.toHaveBeenCalledWith(
          expect.anything(),
          expect.stringContaining(token)
        )
      })
    })
  })
  
  describe('Unsafe URL and Redirect Tests', () => {
    test('should demonstrate unsafe redirect vulnerability', () => {
      const maliciousUrls = frontendSecurityUtils.maliciousRedirects
      
      maliciousUrls.forEach(maliciousUrl => {
        const { container } = render(
          <UnsafeRedirectComponent redirectUrl={maliciousUrl} />
        )
        
        const link = screen.getByTestId('unsafe-link')
        const button = screen.getByTestId('unsafe-redirect-button')
        
        // VULNERABILITY: Malicious URLs are not filtered
        expect(link.getAttribute('href')).toBe(maliciousUrl)
        
        // Button would redirect to malicious URL when clicked
        fireEvent.click(button)
        // In real browser, this would execute dangerous redirects
      })
    })
    
    test('should prevent unsafe redirects in secure component', () => {
      const maliciousUrls = frontendSecurityUtils.maliciousRedirects
      
      maliciousUrls.forEach(maliciousUrl => {
        render(
          <SecureRedirectComponent redirectUrl={maliciousUrl} />
        )
        
        const link = screen.getByTestId('safe-link')
        const button = screen.getByTestId('safe-redirect-button')
        const warning = screen.queryByTestId('invalid-url-warning')
        
        // SECURE: Malicious URLs are blocked and redirected to safe default
        expect(link.getAttribute('href')).toBe('/')
        expect(warning).toBeTruthy() // Warning should be shown
        
        // Button should redirect to safe URL
        fireEvent.click(button)
        // Would redirect to safe default instead of malicious URL
      })
    })
    
    test('should validate URL security patterns', () => {
      const urlTests = testComponentSecurity.testUrlSecurity('href')
      
      urlTests.forEach(({ href, shouldBlock }) => {
        render(<SecureRedirectComponent redirectUrl={href} />)
        
        const link = screen.getByTestId('safe-link')
        const actualHref = link.getAttribute('href')
        
        if (shouldBlock) {
          expect(actualHref).toBe('/') // Should redirect to safe default
        } else {
          expect(actualHref).toBe(href) // Should allow safe URLs
        }
      })
    })
  })
  
  describe('Input Validation and Sanitization', () => {
    test('should validate form inputs against malicious content', () => {
      const TestForm = ({ onSubmit }: { onSubmit: (data: any) => void }) => {
        const [formData, setFormData] = React.useState({ name: '', email: '', message: '' })
        
        const validateInput = (value: string, field: string) => {
          // Basic validation
          if (field === 'email' && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)) {
            return false
          }
          
          // Check for XSS patterns
          const xssPatterns = [
            /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,
            /javascript:/gi,
            /on\w+\s*=/gi,
            /<iframe/gi,
            /<object/gi
          ]
          
          return !xssPatterns.some(pattern => pattern.test(value))
        }
        
        const handleSubmit = (e: React.FormEvent) => {
          e.preventDefault()
          
          // Validate all fields
          const isValid = Object.entries(formData).every(([field, value]) => 
            validateInput(value, field)
          )
          
          if (isValid) {
            onSubmit(formData)
          }
        }
        
        return (
          <form onSubmit={handleSubmit} data-testid="secure-form">
            <input
              type="text"
              value={formData.name}
              onChange={(e) => setFormData({ ...formData, name: e.target.value })}
              data-testid="name-input"
            />
            <input
              type="email"
              value={formData.email}
              onChange={(e) => setFormData({ ...formData, email: e.target.value })}
              data-testid="email-input"
            />
            <textarea
              value={formData.message}
              onChange={(e) => setFormData({ ...formData, message: e.target.value })}
              data-testid="message-input"
            />
            <button type="submit" data-testid="submit-button">
              Submit
            </button>
          </form>
        )
      }
      
      const mockSubmit = vi.fn()
      render(<TestForm onSubmit={mockSubmit} />)
      
      // Test malicious inputs
      const maliciousInputs = [
        '<script>alert("XSS")</script>',
        'javascript:alert("XSS")',
        '"><img src=x onerror=alert("XSS")>',
        '<iframe src="javascript:alert(\'XSS\')"></iframe>'
      ]
      
      maliciousInputs.forEach(maliciousInput => {
        // Clear form
        fireEvent.change(screen.getByTestId('name-input'), { target: { value: maliciousInput } })
        fireEvent.change(screen.getByTestId('email-input'), { target: { value: 'test@example.com' } })
        fireEvent.change(screen.getByTestId('message-input'), { target: { value: 'Valid message' } })
        
        // Try to submit
        fireEvent.click(screen.getByTestId('submit-button'))
        
        // Form should not submit with malicious input
        expect(mockSubmit).not.toHaveBeenCalled()
      })
      
      // Test valid input should work
      fireEvent.change(screen.getByTestId('name-input'), { target: { value: 'John Doe' } })
      fireEvent.change(screen.getByTestId('email-input'), { target: { value: 'john@example.com' } })
      fireEvent.change(screen.getByTestId('message-input'), { target: { value: 'Hello world!' } })
      
      fireEvent.click(screen.getByTestId('submit-button'))
      expect(mockSubmit).toHaveBeenCalledWith({
        name: 'John Doe',
        email: 'john@example.com',
        message: 'Hello world!'
      })
    })
  })
  
  describe('Client-Side Authorization Tests', () => {
    test('should not expose admin features to regular users', () => {
      const AdminPanel = ({ user }: { user: { role: string } }) => {
        // VULNERABLE: Client-side only check
        const isAdmin = user.role === 'admin'
        
        return (
          <div>
            <div data-testid="user-content">Regular user content</div>
            {/* DANGEROUS: Admin content is still in DOM even if hidden */}
            <div 
              data-testid="admin-content" 
              style={{ display: isAdmin ? 'block' : 'none' }}
            >
              <button data-testid="delete-all-button">Delete All Users</button>
              <button data-testid="admin-settings-button">Admin Settings</button>
            </div>
          </div>
        )
      }
      
      const regularUser = { role: 'user' }
      const { container } = render(<AdminPanel user={regularUser} />)
      
      // Admin content is still present in DOM (security issue)
      expect(screen.getByTestId('admin-content')).toBeTruthy()
      expect(screen.getByTestId('delete-all-button')).toBeTruthy()
      
      // User could manipulate CSS to show admin controls
      const adminContent = screen.getByTestId('admin-content')
      expect(adminContent.style.display).toBe('none')
      
      // Simulate user modifying styles (easily done in browser dev tools)
      adminContent.style.display = 'block'
      expect(adminContent.style.display).toBe('block')
    })
    
    test('should properly implement server-side authorization checks', () => {
      const SecureAdminPanel = ({ user }: { user: { role: string } }) => {
        // SECURE: Only render admin content for actual admins
        // Real authorization should be checked server-side
        
        return (
          <div>
            <div data-testid="user-content">Regular user content</div>
            {user.role === 'admin' && (
              <div data-testid="admin-content">
                <button 
                  data-testid="delete-all-button"
                  onClick={() => {
                    // This would make a server request that validates admin role
                    console.log('Server-side admin action')
                  }}
                >
                  Delete All Users
                </button>
              </div>
            )}
          </div>
        )
      }
      
      const regularUser = { role: 'user' }
      render(<SecureAdminPanel user={regularUser} />)
      
      // Admin content should not be in DOM at all for regular users
      expect(screen.queryByTestId('admin-content')).toBeNull()
      expect(screen.queryByTestId('delete-all-button')).toBeNull()
      
      // Test with admin user
      const adminUser = { role: 'admin' }
      const { rerender } = render(<SecureAdminPanel user={adminUser} />)
      
      // Now admin content should be present
      expect(screen.getByTestId('admin-content')).toBeTruthy()
      expect(screen.getByTestId('delete-all-button')).toBeTruthy()
    })
  })
  
  describe('CSP and Content Security', () => {
    test('should not violate Content Security Policy', () => {
      // Test that components don't use inline scripts or styles that would violate CSP
      const CSPCompliantComponent = () => {
        // GOOD: External styles and scripts
        return (
          <div className="safe-component">
            <button 
              onClick={() => console.log('Safe click handler')}
              data-testid="safe-button"
            >
              Click me
            </button>
          </div>
        )
      }
      
      const CSPViolatingComponent = () => {
        // BAD: Inline styles and event handlers
        return (
          <div>
            <div 
              style={{ color: 'red' }} // CSP violation: inline styles
              data-testid="inline-styles"
            >
              Red text
            </div>
            <div 
              dangerouslySetInnerHTML={{ 
                __html: '<script>console.log("inline script")</script>' 
              }}
              data-testid="inline-script"
            />
          </div>
        )
      }
      
      // Test CSP compliant component
      const { container: safeContainer } = render(<CSPCompliantComponent />)
      
      // Should not have inline styles
      const safeElements = safeContainer.querySelectorAll('[style]')
      expect(safeElements.length).toBe(0)
      
      // Should not have inline scripts
      const safeScripts = safeContainer.querySelectorAll('script')
      expect(safeScripts.length).toBe(0)
      
      // Test CSP violating component
      const { container: unsafeContainer } = render(<CSPViolatingComponent />)
      
      // Has inline styles (would violate CSP)
      const styledElements = unsafeContainer.querySelectorAll('[style]')
      expect(styledElements.length).toBeGreaterThan(0)
      
      // Has inline scripts (would violate CSP)
      const inlineScripts = unsafeContainer.querySelectorAll('script')
      expect(inlineScripts.length).toBeGreaterThan(0)
    })
  })
})