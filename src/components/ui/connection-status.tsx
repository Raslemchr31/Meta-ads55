'use client'

import { Badge } from '@/components/ui/badge'
import { useRealTime } from '@/components/real-time-provider'
import { Wifi, WifiOff, AlertTriangle, Loader2 } from 'lucide-react'

export function ConnectionStatus() {
  const { isConnected, connectionStatus } = useRealTime()

  const getStatusInfo = () => {
    switch (connectionStatus) {
      case 'connected':
        return {
          icon: Wifi,
          label: 'Live',
          variant: 'default' as const,
          className: 'bg-green-100 text-green-700 dark:bg-green-900/20 dark:text-green-400'
        }
      case 'connecting':
        return {
          icon: Loader2,
          label: 'Connecting...',
          variant: 'secondary' as const,
          className: 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/20 dark:text-yellow-400'
        }
      case 'disconnected':
        return {
          icon: WifiOff,
          label: 'Offline',
          variant: 'secondary' as const,
          className: 'bg-gray-100 text-gray-700 dark:bg-gray-900/20 dark:text-gray-400'
        }
      case 'error':
        return {
          icon: AlertTriangle,
          label: 'Error',
          variant: 'destructive' as const,
          className: 'bg-red-100 text-red-700 dark:bg-red-900/20 dark:text-red-400'
        }
      default:
        return {
          icon: WifiOff,
          label: 'Unknown',
          variant: 'secondary' as const,
          className: 'bg-gray-100 text-gray-700 dark:bg-gray-900/20 dark:text-gray-400'
        }
    }
  }

  const { icon: Icon, label, variant, className } = getStatusInfo()

  return (
    <Badge variant={variant} className={`text-xs ${className}`}>
      <Icon className={`h-3 w-3 mr-1 ${connectionStatus === 'connecting' ? 'animate-spin' : ''}`} />
      {label}
    </Badge>
  )
}