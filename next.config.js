/** @type {import('next').NextConfig} */
const nextConfig = {
  images: {
    domains: ['localhost', 'platform-lookaside.fbsbx.com', 'scontent.xx.fbcdn.net'],
  },
  env: {
    NEXTAUTH_URL: process.env.NEXTAUTH_URL,
    NEXTAUTH_SECRET: process.env.NEXTAUTH_SECRET,
    FACEBOOK_CLIENT_ID: process.env.FACEBOOK_CLIENT_ID,
    FACEBOOK_CLIENT_SECRET: process.env.FACEBOOK_CLIENT_SECRET,
  },
}

module.exports = nextConfig