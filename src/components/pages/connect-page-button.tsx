'use client'

import { useState } from 'react'
import { Button } from '@/components/ui/button'
import { PlusCircle } from 'lucide-react'
import { PageConnectionWizard } from './page-connection-wizard'

export function ConnectPageButton() {
  const [showWizard, setShowWizard] = useState(false)

  return (
    <>
      <Button 
        onClick={() => setShowWizard(true)}
        leftIcon={<PlusCircle className="h-4 w-4" />}
      >
        Connect Page
      </Button>
      
      <PageConnectionWizard 
        open={showWizard} 
        onOpenChange={setShowWizard} 
      />
    </>
  )
}