'use client'

import { useTheme as useNextTheme } from 'next-themes'
import { useEffect, useState } from 'react'

export function useTheme() {
  const [mounted, setMounted] = useState(false)
  const { theme, setTheme, resolvedTheme } = useNextTheme()

  useEffect(() => {
    setMounted(true)
  }, [])

  // Avoid hydration mismatch by returning safe defaults until mounted
  if (!mounted) {
    return {
      theme: undefined,
      setTheme,
      resolvedTheme: undefined,
    }
  }

  return {
    theme,
    setTheme,
    resolvedTheme,
  }
}