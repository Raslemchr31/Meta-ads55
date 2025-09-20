'use client'

import { useState } from 'react'
import { useSession, signOut } from 'next-auth/react'
import { useTheme } from '@/hooks/use-theme'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Badge } from '@/components/ui/badge'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { Avatar, AvatarFallback, AvatarImage } from '@/components/ui/avatar'
import {
  Menu,
  Search,
  Bell,
  Sun,
  Moon,
  User,
  Settings,
  LogOut,
  HelpCircle,
  Zap,
} from 'lucide-react'
import { cn } from '@/lib/utils'

interface HeaderProps {
  onMenuClick: () => void
  sidebarCollapsed: boolean
}

export function Header({ onMenuClick, sidebarCollapsed }: HeaderProps) {
  const { data: session } = useSession()
  const { theme, setTheme } = useTheme()
  const [searchValue, setSearchValue] = useState('')
  
  // Demo user data when no session exists
  const demoUser = {
    name: 'Demo User',
    email: 'demo@metaads.ai',
    image: null
  }
  
  const currentUser = session?.user || demoUser
  const [notifications] = useState([
    {
      id: 1,
      title: 'Campaign Performance Alert',
      message: 'Your "Summer Sale" campaign has exceeded its daily budget',
      type: 'warning',
      time: '5 min ago',
      unread: true,
    },
    {
      id: 2,
      title: 'New Audience Insights',
      message: 'AI has identified a high-converting audience segment',
      type: 'info',
      time: '1 hour ago',
      unread: true,
    },
    {
      id: 3,
      title: 'Weekly Report Ready',
      message: 'Your weekly performance report is now available',
      type: 'success',
      time: '2 hours ago',
      unread: false,
    },
  ])

  const unreadCount = notifications.filter(n => n.unread).length

  const handleSignOut = () => {
    signOut({ callbackUrl: '/auth/login' })
  }

  const getInitials = (name: string) => {
    return name
      .split(' ')
      .map(n => n[0])
      .join('')
      .toUpperCase()
      .slice(0, 2)
  }

  return (
    <header className={cn(
      "h-16 bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/60 border-b transition-all duration-300",
      sidebarCollapsed ? "lg:pl-16" : "lg:pl-64"
    )}>
      <div className="flex items-center justify-between h-full px-6">
        {/* Left side */}
        <div className="flex items-center space-x-4">
          {/* Mobile menu button */}
          <Button
            variant="ghost"
            size="icon"
            className="lg:hidden"
            onClick={onMenuClick}
          >
            <Menu className="h-5 w-5" />
          </Button>

          {/* Search */}
          <div className="relative hidden md:block">
            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-muted-foreground" />
            <Input
              placeholder="Search campaigns, pages, insights..."
              value={searchValue}
              onChange={(e) => setSearchValue(e.target.value)}
              className="w-80 pl-10 bg-muted/50"
            />
          </div>
        </div>

        {/* Right side */}
        <div className="flex items-center space-x-3">
          {/* Quick actions */}
          <Button variant="ghost" size="icon" className="relative">
            <div>
              <Zap className="h-5 w-5" />
              <Badge 
                variant="success" 
                className="absolute -top-1 -right-1 h-5 w-5 p-0 flex items-center justify-center text-xs"
              >
                AI
              </Badge>
            </div>
          </Button>

          {/* Theme toggle */}
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="ghost" size="icon">
                <div className="relative">
                  <Sun className="h-5 w-5 rotate-0 scale-100 transition-all dark:-rotate-90 dark:scale-0" />
                  <Moon className="absolute inset-0 h-5 w-5 rotate-90 scale-0 transition-all dark:rotate-0 dark:scale-100" />
                  <span className="sr-only">Toggle theme</span>
                </div>
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end">
              <DropdownMenuItem onClick={() => setTheme("light")}>
                Light
              </DropdownMenuItem>
              <DropdownMenuItem onClick={() => setTheme("dark")}>
                Dark
              </DropdownMenuItem>
              <DropdownMenuItem onClick={() => setTheme("system")}>
                System
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>

          {/* Notifications */}
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="ghost" size="icon" className="relative">
                <div>
                  <Bell className="h-5 w-5" />
                  {unreadCount > 0 && (
                    <Badge 
                      variant="destructive" 
                      className="absolute -top-1 -right-1 h-5 w-5 p-0 flex items-center justify-center text-xs"
                    >
                      {unreadCount}
                    </Badge>
                  )}
                </div>
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end" className="w-80">
              <DropdownMenuLabel className="flex items-center justify-between">
                Notifications
                {unreadCount > 0 && (
                  <Badge variant="secondary" className="text-xs">
                    {unreadCount} new
                  </Badge>
                )}
              </DropdownMenuLabel>
              <DropdownMenuSeparator />
              <div className="max-h-80 overflow-y-auto">
                {notifications.map((notification) => (
                  <DropdownMenuItem key={notification.id} className="flex flex-col items-start p-4">
                    <div className="flex items-start justify-between w-full">
                      <div className="flex-1">
                        <div className="flex items-center space-x-2">
                          <span className="font-medium text-sm">
                            {notification.title}
                          </span>
                          {notification.unread && (
                            <div className="w-2 h-2 bg-primary rounded-full" />
                          )}
                        </div>
                        <p className="text-xs text-muted-foreground mt-1">
                          {notification.message}
                        </p>
                        <span className="text-xs text-muted-foreground mt-1">
                          {notification.time}
                        </span>
                      </div>
                    </div>
                  </DropdownMenuItem>
                ))}
              </div>
              <DropdownMenuSeparator />
              <DropdownMenuItem className="text-center justify-center">
                View all notifications
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>

          {/* User menu */}
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="ghost" className="relative h-10 w-10 rounded-full">
                <Avatar className="h-10 w-10">
                  <AvatarImage 
                    src={currentUser?.image || ''} 
                    alt={currentUser?.name || 'User'} 
                  />
                  <AvatarFallback>
                    {currentUser?.name ? getInitials(currentUser.name) : 'U'}
                  </AvatarFallback>
                </Avatar>
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent className="w-56" align="end" forceMount>
              <DropdownMenuLabel className="font-normal">
                <div className="flex flex-col space-y-1">
                  <p className="text-sm font-medium leading-none">
                    {currentUser?.name || 'User'}
                  </p>
                  <p className="text-xs leading-none text-muted-foreground">
                    {currentUser?.email}
                  </p>
                </div>
              </DropdownMenuLabel>
              <DropdownMenuSeparator />
              <DropdownMenuItem>
                <User className="mr-2 h-4 w-4" />
                <span>Profile</span>
              </DropdownMenuItem>
              <DropdownMenuItem>
                <Settings className="mr-2 h-4 w-4" />
                <span>Settings</span>
              </DropdownMenuItem>
              <DropdownMenuItem>
                <HelpCircle className="mr-2 h-4 w-4" />
                <span>Help & Support</span>
              </DropdownMenuItem>
              <DropdownMenuSeparator />
              <DropdownMenuItem onClick={handleSignOut}>
                <LogOut className="mr-2 h-4 w-4" />
                <span>Log out</span>
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        </div>
      </div>
    </header>
  )
}