import { useMemo } from 'react'

export function useOutputDir(): string {
  return useMemo(
    () => {
      // Get absolute path to project root's output directory
      // This is injected by Vite config via define
      const injectedPath = import.meta.env.VITE_OUTPUT_DIR
      if (injectedPath) {
        return injectedPath
      }
      
      // Fallback: try to construct from import.meta.url
      try {
        const url = new URL(import.meta.url)
        if (url.protocol === 'file:') {
          let filePath = url.pathname
          if (/^\/[A-Za-z]:/.test(filePath)) {
            filePath = filePath.substring(1)
          }
          const match = filePath.match(/^(.+?)[\/\\]display[\/\\]src[\/\\]/i)
          if (match) {
            return `${match[1].replace(/\\/g, '/')}/output`
          }
        }
      } catch (e) {
        console.warn('Path resolution error:', e)
      }
      
      // Last resort fallback
      console.warn('Using fallback path - may not work correctly')
      return '../bin/output'
    },
    []
  )
}

