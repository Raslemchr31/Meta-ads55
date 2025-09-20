import { getServerSession } from 'next-auth'
import { redirect } from 'next/navigation'
import { authOptions } from '@/lib/auth'
import { DashboardLayout } from '@/components/layout/dashboard-layout'

export default async function Layout({
  children,
}: {
  children: React.ReactNode
}) {
  const session = await getServerSession(authOptions)
  
  // Temporarily disabled for demo mode
  // if (!session) {
  //   redirect('/auth/login')
  // }

  return <DashboardLayout>{children}</DashboardLayout>
}