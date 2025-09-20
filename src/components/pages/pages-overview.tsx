'use client'

import { useState } from 'react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Avatar, AvatarFallback, AvatarImage } from '@/components/ui/avatar'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from '@/components/ui/alert-dialog'
import {
  Facebook,
  MoreHorizontal,
  ExternalLink,
  Settings,
  Trash2,
  Users,
  TrendingUp,
  Calendar,
  CheckCircle,
  AlertTriangle,
  Play,
  Pause,
  BarChart3,
  Target,
} from 'lucide-react'
import { formatNumber, formatDate } from '@/lib/utils'
import { useAuthStore } from '@/store/auth-store'
import { toast } from 'sonner'

export function PagesOverview() {
  const { connectedPages, removeConnectedPage } = useAuthStore()
  const [disconnectingPageId, setDisconnectingPageId] = useState<string | null>(null)

  const handleDisconnectPage = async (pageId: string) => {
    setDisconnectingPageId(pageId)
    
    try {
      // Simulate API call
      await new Promise(resolve => setTimeout(resolve, 1000))
      
      removeConnectedPage(pageId)
      toast.success('Page disconnected successfully')
    } catch (error) {
      toast.error('Failed to disconnect page')
    } finally {
      setDisconnectingPageId(null)
    }
  }

  if (connectedPages.length === 0) {
    return (
      <Card>
        <CardContent className="flex flex-col items-center justify-center py-12">
          <div className="w-16 h-16 bg-muted rounded-full flex items-center justify-center mb-4">
            <Facebook className="w-8 h-8 text-muted-foreground" />
          </div>
          <h3 className="text-lg font-semibold mb-2">No pages connected</h3>
          <p className="text-muted-foreground text-center mb-6 max-w-md">
            Connect your Facebook pages to start analyzing your social media performance and 
            managing your advertising campaigns.
          </p>
          <Button>
            <Facebook className="w-4 h-4 mr-2" />
            Connect Your First Page
          </Button>
        </CardContent>
      </Card>
    )
  }

  return (
    <div className="space-y-6">
      {/* Summary Stats */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card>
          <CardContent className="p-6">
            <div className="flex items-center space-x-2">
              <Facebook className="w-5 h-5 text-facebook" />
              <div>
                <p className="text-2xl font-bold">{connectedPages.length}</p>
                <p className="text-xs text-muted-foreground">Connected Pages</p>
              </div>
            </div>
          </CardContent>
        </Card>
        
        <Card>
          <CardContent className="p-6">
            <div className="flex items-center space-x-2">
              <Users className="w-5 h-5 text-blue-500" />
              <div>
                <p className="text-2xl font-bold">
                  {formatNumber(
                    connectedPages.reduce((total, page) => total + (page.fan_count || 0), 0),
                    'en-US',
                    'compact'
                  )}
                </p>
                <p className="text-xs text-muted-foreground">Total Followers</p>
              </div>
            </div>
          </CardContent>
        </Card>
        
        <Card>
          <CardContent className="p-6">
            <div className="flex items-center space-x-2">
              <CheckCircle className="w-5 h-5 text-green-500" />
              <div>
                <p className="text-2xl font-bold">
                  {connectedPages.filter(page => page.can_post).length}
                </p>
                <p className="text-xs text-muted-foreground">Active Pages</p>
              </div>
            </div>
          </CardContent>
        </Card>
        
        <Card>
          <CardContent className="p-6">
            <div className="flex items-center space-x-2">
              <TrendingUp className="w-5 h-5 text-purple-500" />
              <div>
                <p className="text-2xl font-bold">24</p>
                <p className="text-xs text-muted-foreground">Active Campaigns</p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Pages Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {connectedPages.map((page) => (
          <Card key={page.id} className="hover:shadow-md transition-shadow">
            <CardHeader className="pb-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center space-x-3">
                  <Avatar className="w-12 h-12">
                    <AvatarImage 
                      src={page.picture?.data?.url} 
                      alt={page.name} 
                    />
                    <AvatarFallback>{page.name.charAt(0)}</AvatarFallback>
                  </Avatar>
                  <div>
                    <CardTitle className="text-base line-clamp-1">
                      {page.name}
                    </CardTitle>
                    <CardDescription className="text-sm">
                      {page.category}
                    </CardDescription>
                  </div>
                </div>
                
                <DropdownMenu>
                  <DropdownMenuTrigger asChild>
                    <Button variant="ghost" size="icon" className="h-8 w-8">
                      <MoreHorizontal className="w-4 h-4" />
                    </Button>
                  </DropdownMenuTrigger>
                  <DropdownMenuContent align="end">
                    <DropdownMenuLabel>Page Actions</DropdownMenuLabel>
                    <DropdownMenuSeparator />
                    <DropdownMenuItem>
                      <ExternalLink className="w-4 h-4 mr-2" />
                      View on Facebook
                    </DropdownMenuItem>
                    <DropdownMenuItem>
                      <Settings className="w-4 h-4 mr-2" />
                      Page Settings
                    </DropdownMenuItem>
                    <DropdownMenuItem>
                      <Play className="w-4 h-4 mr-2" />
                      View Campaigns
                    </DropdownMenuItem>
                    <DropdownMenuSeparator />
                    <AlertDialog>
                      <AlertDialogTrigger asChild>
                        <DropdownMenuItem 
                          onSelect={(e) => e.preventDefault()}
                          className="text-destructive focus:text-destructive"
                        >
                          <Trash2 className="w-4 h-4 mr-2" />
                          Disconnect Page
                        </DropdownMenuItem>
                      </AlertDialogTrigger>
                      <AlertDialogContent>
                        <AlertDialogHeader>
                          <AlertDialogTitle>Are you sure?</AlertDialogTitle>
                          <AlertDialogDescription>
                            This will disconnect "{page.name}" from your account. 
                            You'll lose access to its analytics and won't be able to 
                            manage campaigns for this page.
                          </AlertDialogDescription>
                        </AlertDialogHeader>
                        <AlertDialogFooter>
                          <AlertDialogCancel>Cancel</AlertDialogCancel>
                          <AlertDialogAction
                            onClick={() => handleDisconnectPage(page.id)}
                            className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
                          >
                            {disconnectingPageId === page.id ? 'Disconnecting...' : 'Disconnect'}
                          </AlertDialogAction>
                        </AlertDialogFooter>
                      </AlertDialogContent>
                    </AlertDialog>
                  </DropdownMenuContent>
                </DropdownMenu>
              </div>
            </CardHeader>
            
            <CardContent>
              <div className="space-y-3">
                {/* Stats */}
                <div className="grid grid-cols-2 gap-4 text-sm">
                  <div>
                    <p className="font-medium">
                      {formatNumber(page.fan_count || 0, 'en-US', 'compact')}
                    </p>
                    <p className="text-muted-foreground">Followers</p>
                  </div>
                  <div>
                    <p className="font-medium">12</p>
                    <p className="text-muted-foreground">Campaigns</p>
                  </div>
                </div>

                {/* Status badges */}
                <div className="flex flex-wrap gap-2">
                  {page.can_post && (
                    <Badge variant="success" className="text-xs">
                      <CheckCircle className="w-3 h-3 mr-1" />
                      Active
                    </Badge>
                  )}
                  
                  {page.verification_status === 'verified' && (
                    <Badge variant="default" className="text-xs">
                      Verified
                    </Badge>
                  )}
                  
                  {page.tasks.includes('ads_management') && (
                    <Badge variant="secondary" className="text-xs">
                      Ads Enabled
                    </Badge>
                  )}
                </div>

                {/* Quick stats */}
                <div className="pt-3 border-t text-xs text-muted-foreground space-y-1">
                  <div className="flex items-center justify-between">
                    <span>This Month Spend:</span>
                    <span className="font-medium">$2,450</span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span>ROAS:</span>
                    <span className="font-medium text-green-600">4.2x</span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span>Last Updated:</span>
                    <span>2 hours ago</span>
                  </div>
                </div>

                {/* Action buttons */}
                <div className="pt-3 flex space-x-2">
                  <Button size="sm" variant="outline" className="flex-1">
                    <BarChart3 className="w-4 h-4 mr-1" />
                    Analytics
                  </Button>
                  <Button size="sm" className="flex-1">
                    <Target className="w-4 h-4 mr-1" />
                    Campaigns
                  </Button>
                </div>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  )
}