import { DefaultSession, DefaultUser } from 'next-auth'
import { JWT, DefaultJWT } from 'next-auth/jwt'

declare module 'next-auth' {
  interface Session extends DefaultSession {
    accessToken?: string
    refreshToken?: string
    expiresAt?: number
    tokenType?: string
    scope?: string
    profile?: FacebookProfile
    user: {
      id: string
      name?: string | null
      email?: string | null
      image?: string | null
    }
  }

  interface User extends DefaultUser {
    id: string
  }
}

declare module 'next-auth/jwt' {
  interface JWT extends DefaultJWT {
    accessToken?: string
    refreshToken?: string
    expiresAt?: number
    tokenType?: string
    scope?: string
    profile?: FacebookProfile
  }
}

export interface FacebookProfile {
  id: string
  name: string
  email?: string
  picture?: {
    data: {
      height: number
      is_silhouette: boolean
      url: string
      width: number
    }
  }
  first_name?: string
  last_name?: string
  short_name?: string
  name_format?: string
  locale?: string
  timezone?: number
  verified?: boolean
}

export interface FacebookPage {
  id: string
  name: string
  category: string
  category_list: Array<{
    id: string
    name: string
  }>
  access_token: string
  tasks: string[]
  picture?: {
    data: {
      height: number
      is_silhouette: boolean
      url: string
      width: number
    }
  }
  cover?: {
    cover_id: string
    offset_x: number
    offset_y: number
    source: string
    id: string
  }
  fan_count?: number
  link?: string
  location?: {
    city: string
    country: string
    latitude: number
    longitude: number
    state: string
    street: string
    zip: string
  }
  phone?: string
  website?: string
  about?: string
  description?: string
  is_published?: boolean
  can_post?: boolean
  verification_status?: string
}

export interface AuthError {
  type: string
  error: string
  description?: string
}

export interface LoginCredentials {
  email: string
  password: string
  remember?: boolean
}

export interface User {
  id: string
  name: string
  email: string
  image?: string
  provider: 'facebook'
  providerId: string
  connectedPages: FacebookPage[]
  preferences: UserPreferences
  createdAt: Date
  updatedAt: Date
}

export interface UserPreferences {
  theme: 'light' | 'dark' | 'system'
  language: string
  timezone: string
  currency: string
  notifications: {
    email: boolean
    push: boolean
    campaignUpdates: boolean
    performanceAlerts: boolean
    weeklyReports: boolean
  }
  dashboard: {
    defaultDateRange: string
    defaultCurrency: string
    compactMode: boolean
  }
}