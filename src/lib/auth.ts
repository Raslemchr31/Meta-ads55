import { NextAuthOptions } from 'next-auth'
import FacebookProvider from 'next-auth/providers/facebook'

export const authOptions: NextAuthOptions = {
  providers: [
    FacebookProvider({
      clientId: process.env.FACEBOOK_CLIENT_ID!,
      clientSecret: process.env.FACEBOOK_CLIENT_SECRET!,
      authorization: {
        params: {
          scope: [
            'email',
            'public_profile',
            'ads_management',
            'ads_read',
            'business_management',
            'instagram_basic',
            'instagram_manage_insights',
            'pages_read_engagement',
            'pages_show_list',
            'read_insights',
          ].join(','),
          response_type: 'code',
          code_challenge_method: 'S256',
        },
      },
    }),
  ],
  callbacks: {
    async jwt({ token, account, profile }) {
      // Persist the OAuth access_token and or the user id to the token right after signin
      if (account) {
        token.accessToken = account.access_token
        token.refreshToken = account.refresh_token
        token.expiresAt = account.expires_at
        token.tokenType = account.token_type
        token.scope = account.scope
      }
      
      if (profile) {
        token.profile = profile as any
      }
      
      return token
    },
    async session({ session, token }) {
      // Only send safe properties to the client (tokens removed for security)
      if (token && token.profile) {
        session.profile = token.profile as any
      }
      
      return session
    },
    async redirect({ url, baseUrl }) {
      // Allows relative callback URLs
      if (url.startsWith("/")) return `${baseUrl}${url}`
      // Allows callback URLs on the same origin
      else if (new URL(url).origin === baseUrl) return url
      return baseUrl
    },
  },
  pages: {
    signIn: '/auth/login',
    error: '/auth/error',
  },
  session: {
    strategy: 'jwt',
    maxAge: 30 * 24 * 60 * 60, // 30 days
    updateAge: 24 * 60 * 60, // 24 hours
  },
  jwt: {
    maxAge: 30 * 24 * 60 * 60, // 30 days
  },
  secret: process.env.NEXTAUTH_SECRET,
  debug: false, // Disabled for security
}