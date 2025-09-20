import { setupServer } from 'msw/node'
import { http, HttpResponse } from 'msw'

// Mock API responses for testing
export const handlers = [
  // Auth endpoints
  http.post('/api/auth/signin', () => {
    return HttpResponse.json({
      user: {
        id: 'test-user-id',
        name: 'Test User',
        email: 'test@example.com'
      },
      accessToken: 'test-access-token',
      refreshToken: 'test-refresh-token'
    })
  }),

  http.post('/api/auth/signout', () => {
    return HttpResponse.json({ success: true })
  }),

  // Facebook Graph API endpoints
  http.get('https://graph.facebook.com/me/accounts', () => {
    return HttpResponse.json({
      data: [
        {
          id: '123456789',
          name: 'Test Page',
          access_token: 'page-access-token',
          category: 'Business',
          instagram_business_account: {
            id: '987654321'
          }
        }
      ]
    })
  }),

  http.get('https://graph.facebook.com/v18.0/act_*/campaigns', () => {
    return HttpResponse.json({
      data: [
        {
          id: 'campaign_123',
          name: 'Test Campaign',
          status: 'ACTIVE',
          objective: 'REACH',
          budget_remaining: '1000'
        }
      ]
    })
  }),

  http.get('https://graph.facebook.com/v18.0/*/insights', () => {
    return HttpResponse.json({
      data: [
        {
          impressions: '1000',
          reach: '800',
          clicks: '50',
          spend: '25.00',
          date_start: '2024-01-01',
          date_stop: '2024-01-31'
        }
      ]
    })
  }),

  // Backend API endpoints
  http.get('/api/user/profile', () => {
    return HttpResponse.json({
      id: 'test-user-id',
      name: 'Test User',
      email: 'test@example.com',
      facebookPages: [
        {
          id: '123456789',
          name: 'Test Page',
          isConnected: true
        }
      ]
    })
  }),

  http.get('/api/campaigns', () => {
    return HttpResponse.json({
      campaigns: [
        {
          id: 'campaign_123',
          name: 'Test Campaign',
          status: 'ACTIVE',
          budget: 1000,
          impressions: 5000,
          clicks: 250,
          spend: 150.50
        }
      ]
    })
  }),

  http.post('/api/campaigns', () => {
    return HttpResponse.json({
      success: true,
      campaignId: 'new-campaign-123'
    })
  }),

  http.get('/api/pages', () => {
    return HttpResponse.json({
      pages: [
        {
          id: '123456789',
          name: 'Test Page',
          category: 'Business',
          isConnected: true,
          followers: 1500,
          engagement: 5.2
        }
      ]
    })
  }),

  http.post('/api/pages/connect', () => {
    return HttpResponse.json({
      success: true,
      pageId: '123456789'
    })
  }),

  // Security test endpoints
  http.post('/api/test/xss', async ({ request }) => {
    const body = await request.json() as any
    // Return input without sanitization for testing XSS prevention
    return HttpResponse.json({
      echo: body.input,
      sanitized: false
    })
  }),

  http.post('/api/test/csrf', ({ request }) => {
    const csrfToken = request.headers.get('X-CSRF-Token')
    
    if (!csrfToken) {
      return HttpResponse.json(
        { error: 'CSRF token required' },
        { status: 403 }
      )
    }
    
    return HttpResponse.json({ success: true })
  }),

  // Error simulation endpoints
  http.get('/api/test/500', () => {
    return HttpResponse.json(
      { error: 'Internal Server Error' },
      { status: 500 }
    )
  }),

  http.get('/api/test/401', () => {
    return HttpResponse.json(
      { error: 'Unauthorized' },
      { status: 401 }
    )
  }),

  http.get('/api/test/403', () => {
    return HttpResponse.json(
      { error: 'Forbidden' },
      { status: 403 }
    )
  }),

  // Malicious response simulation
  http.get('/api/test/malicious-redirect', () => {
    return HttpResponse.json({
      redirectUrl: 'javascript:alert("XSS")',
      nextPage: 'https://evil-site.com/steal-tokens'
    })
  }),

  // Simulate token exposure vulnerability
  http.get('/api/test/exposed-tokens', () => {
    return HttpResponse.json({
      user: {
        id: 'test-user',
        name: 'Test User'
      },
      // VULNERABILITY: Exposing sensitive tokens
      accessToken: 'EAABwzLixnjYBAIxvJZCqK1ZC0ZD',
      refreshToken: 'refresh_token_should_not_be_exposed',
      facebookToken: 'sensitive_facebook_access_token'
    })
  })
]

// Setup MSW server
export const server = setupServer(...handlers)

// Export handlers for individual test customization
export { http, HttpResponse }