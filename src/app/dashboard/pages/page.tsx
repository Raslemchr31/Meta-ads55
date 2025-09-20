import { Metadata } from 'next'
import { PagesOverview } from '@/components/pages/pages-overview'
import { ConnectPageButton } from '@/components/pages/connect-page-button'

export const metadata: Metadata = {
  title: 'Pages Management | Meta Ads Intelligence Platform',
  description: 'Manage your connected Facebook pages and their settings',
}

export default function PagesPage() {
  return (
    <div className="space-y-8">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Pages Management</h1>
          <p className="text-muted-foreground">
            Connect and manage your Facebook pages for advertising campaigns
          </p>
        </div>
        <ConnectPageButton />
      </div>

      <PagesOverview />
    </div>
  )
}