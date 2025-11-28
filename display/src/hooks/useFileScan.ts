import { useCallback, useState, useRef } from 'react'

const API_URL = '' // Use proxy from vite.config

export interface ScanResult {
  file: string
  path: string
  status: 'suspicious' | 'safe'
  severity: 'high' | 'medium' | 'low' | 'safe'
  pattern: string | null
  color: 'red' | 'yellow' | 'orange' | 'blue'
}

export function useFileScan(onComplete?: (results: ScanResult[]) => void) {
  const [terminalOutput, setTerminalOutput] = useState<string[]>([])
  const [isScanning, setIsScanning] = useState(false)
  const [scanResults, setScanResults] = useState<ScanResult[]>([])
  const abortControllerRef = useRef<AbortController | null>(null)

  const scanFiles = useCallback(async (files: File[]) => {
    // Cancel any existing scan
    if (abortControllerRef.current) {
      abortControllerRef.current.abort()
    }

    // Create new abort controller
    const abortController = new AbortController()
    abortControllerRef.current = abortController

    setIsScanning(true)
    setTerminalOutput([])
    setScanResults([])

    try {
      // Extract file paths/names from File objects
      const filePaths = files.map(f => f.name)
      
      console.log('Starting scan request for', filePaths.length, 'files')
      
      let response: Response
      try {
        response = await fetch(`${API_URL}/api/scan`, {
          method: 'POST',
          signal: abortController.signal,
          headers: {
            'Accept': 'text/event-stream',
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ files: filePaths }),
        })
      } catch (fetchError: any) {
        console.error('Fetch error:', fetchError)
        if (fetchError.name === 'AbortError') {
          throw fetchError
        }
        throw new Error(`Failed to connect: ${fetchError.message}`)
      }

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`)
      }

      const reader = response.body?.getReader()
      const decoder = new TextDecoder()

      if (!reader) {
        throw new Error('No response body')
      }

      let buffer = ''
      const results: ScanResult[] = []

      const readStream = async () => {
        try {
          while (true) {
            if (abortController.signal.aborted) {
              reader.cancel()
              break
            }

            const { done, value } = await reader.read()

            if (done) {
              break
            }

            buffer += decoder.decode(value, { stream: true })
            const lines = buffer.split('\n\n')
            buffer = lines.pop() || ''

            for (const line of lines) {
              if (line.startsWith('data: ')) {
                try {
                  const data = JSON.parse(line.substring(6))
                  
                  if (data.type === 'start' || data.type === 'scan_progress' || data.type === 'scan_summary') {
                    setTerminalOutput((prev) => [...prev, data.message])
                  } else                   if (data.type === 'scan_result') {
                    setTerminalOutput((prev) => [...prev, data.message])
                    if (data.result) {
                      results.push(data.result)
                      // Update scan results progressively (one by one)
                      setScanResults((prev) => [...prev, data.result])
                    }
                  } else if (data.type === 'scan_progress') {
                    setTerminalOutput((prev) => [...prev, data.message])
                  } else if (data.type === 'scan_summary') {
                    setTerminalOutput((prev) => [...prev, data.message])
                  } else if (data.type === 'end') {
                    setTerminalOutput((prev) => [...prev, data.message])
                    setIsScanning(false)
                    if (data.results) {
                      setScanResults(data.results)
                      if (onComplete) {
                        onComplete(data.results)
                      }
                    }
                    return
                  } else if (data.type === 'error') {
                    setTerminalOutput((prev) => [...prev, data.message])
                    setIsScanning(false)
                    return
                  }
                } catch (e) {
                  console.error('Error parsing SSE data:', e, 'Line:', line)
                }
              }
            }
          }
        } catch (streamError: unknown) {
          console.error('Stream read error:', streamError)
          if (streamError instanceof Error && streamError.name !== 'AbortError') {
            setTerminalOutput((prev) => [...prev, `\n[Stream error: ${streamError.message}]\n`])
          }
          setIsScanning(false)
        }
      }

      await readStream()
    } catch (error: any) {
      if (error.name === 'AbortError') {
        setTerminalOutput((prev) => [...prev, '\n[Scan cancelled]\n'])
      } else {
        const msg = error instanceof Error ? error.message : String(error)
        setTerminalOutput((prev) => [...prev, `\n[Error: ${msg}]\n`])
      }
      setIsScanning(false)
    }
  }, [onComplete])

  const stopScan = useCallback(() => {
    if (abortControllerRef.current) {
      abortControllerRef.current.abort()
      abortControllerRef.current = null
    }
    setIsScanning(false)
  }, [])

  const reset = useCallback(() => {
    setTerminalOutput([])
    setScanResults([])
    setIsScanning(false)
    if (abortControllerRef.current) {
      abortControllerRef.current.abort()
      abortControllerRef.current = null
    }
  }, [])

  return {
    terminalOutput,
    isScanning,
    scanResults,
    scanFiles,
    stopScan,
    reset
  }
}

