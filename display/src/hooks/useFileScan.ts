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
                  
                  // Handle C++ simulator output (stdout/stderr)
                  if (data.type === 'stdout' || data.type === 'stderr') {
                    const message = data.message || ''
                    setTerminalOutput((prev) => [...prev, message])
                    
                    // Parse C++ output to extract scan results
                    // Look for lines like: "[1/32] Analyzing: filename" and "✓ Result: SUSPICIOUS/SAFE"
                    const analyzingMatch = message.match(/\[(\d+)\/(\d+)\]\s*Analyzing:\s*([^\n\r]+)/i)
                    if (analyzingMatch) {
                      const fileName = analyzingMatch[3].trim()
                      // Extract filename from path if needed
                      const cleanFileName = fileName.split(/[/\\]/).pop() || fileName
                      
                      // Check if we already have this result
                      const existingIndex = results.findIndex(r => r.file === cleanFileName)
                      if (existingIndex === -1) {
                        // Create a placeholder result (will be updated when we see the result)
                        const newResult: ScanResult = {
                          file: cleanFileName,
                          path: fileName,
                          status: 'safe', // Will be updated
                          severity: 'safe',
                          pattern: null,
                          color: 'blue'
                        }
                        results.push(newResult)
                        setScanResults((prev) => [...prev, newResult])
                      }
                    }
                    
                    // Look for result lines: "✓ Result: SUSPICIOUS (pattern)" or "✓ Result: SAFE"
                    // These come right after the analyzing line, so match to the most recent unupdated result
                    const resultMatch = message.match(/✓\s*Result:\s*(SUSPICIOUS|SAFE)(?:\s*\(([^)]+)\))?/i)
                    if (resultMatch) {
                      const status = resultMatch[1].toLowerCase() === 'suspicious' ? 'suspicious' : 'safe'
                      const pattern = resultMatch[2] || null
                      
                      // Find the most recent result that hasn't been fully updated
                      // Look for the last result that is still a placeholder (has default values)
                      let updated = false
                      for (let i = results.length - 1; i >= 0; i--) {
                        // Check if this result is still a placeholder
                        // A placeholder has: status='safe', pattern=null, severity='safe'
                        const isPlaceholder = results[i].status === 'safe' && 
                                             results[i].pattern === null && 
                                             results[i].severity === 'safe'
                        
                        if (isPlaceholder) {
                          // Update this result with the actual status
                          const updatedResult: ScanResult = {
                            ...results[i],
                            status: status,
                            severity: status === 'suspicious' 
                              ? (pattern === 'executable' || pattern === 'screensaver' ? 'high' : 
                                 pattern === 'batch_file' || pattern === 'vbscript' ? 'medium' : 'low')
                              : 'safe',
                            pattern: pattern,
                            color: status === 'suspicious'
                              ? (pattern === 'executable' || pattern === 'screensaver' ? 'red' : 
                                 pattern === 'batch_file' || pattern === 'vbscript' ? 'yellow' : 'orange')
                              : 'blue'
                          }
                          results[i] = updatedResult
                          setScanResults((prev) => {
                            const newResults = [...prev]
                            newResults[i] = updatedResult
                            return newResults
                          })
                          updated = true
                          break
                        }
                      }
                      
                      // If no placeholder found but we have a result, create a new one
                      // This handles cases where the result comes before the analyzing line
                      if (!updated && resultMatch) {
                        const newResult: ScanResult = {
                          file: `file_${results.length + 1}`, // Fallback name
                          path: '',
                          status: status,
                          severity: status === 'suspicious' 
                            ? (pattern === 'executable' || pattern === 'screensaver' ? 'high' : 
                               pattern === 'batch_file' || pattern === 'vbscript' ? 'medium' : 'low')
                            : 'safe',
                          pattern: pattern,
                          color: status === 'suspicious'
                            ? (pattern === 'executable' || pattern === 'screensaver' ? 'red' : 
                               pattern === 'batch_file' || pattern === 'vbscript' ? 'yellow' : 'orange')
                            : 'blue'
                        }
                        results.push(newResult)
                        setScanResults((prev) => [...prev, newResult])
                      }
                    }
                    // Also parse the final summary line: "✓ Safe files: X" and "✗ Suspicious files: Y"
                    const safeCountMatch = message.match(/✓\s*Safe files:\s*(\d+)/i)
                    const suspiciousCountMatch = message.match(/✗\s*Suspicious files:\s*(\d+)/i)
                    
                    if (safeCountMatch || suspiciousCountMatch) {
                      // Summary found - ensure all results are properly set
                      // Results should already be parsed from individual file results above
                      // Just ensure the final state is correct
                      setScanResults((prev) => [...prev]) // Trigger re-render with current results
                    }
                  } 
                  // Handle legacy scan types (for backward compatibility)
                  else if (data.type === 'start' || data.type === 'scan_progress' || data.type === 'scan_summary') {
                    setTerminalOutput((prev) => [...prev, data.message])
                  } else if (data.type === 'scan_result') {
                    setTerminalOutput((prev) => [...prev, data.message])
                    if (data.result) {
                      results.push(data.result)
                      // Update scan results progressively (one by one)
                      setScanResults((prev) => [...prev, data.result])
                    }
                  } else if (data.type === 'end') {
                    setTerminalOutput((prev) => [...prev, data.message])
                    setIsScanning(false)
                    if (data.results) {
                      setScanResults(data.results)
                      if (onComplete) {
                        onComplete(data.results)
                      }
                    } else if (results.length > 0) {
                      // Use parsed results if available - ensure all are properly set
                      setScanResults(results)
                      if (onComplete) {
                        onComplete(results)
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

