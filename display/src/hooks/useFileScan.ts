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

export interface VisitedState {
  stateId: string // e.g., "q0", "q1"
  fileIndex: number // Which file was being processed
  status: 'suspicious' | 'safe'
  severity?: 'high' | 'medium' | 'low' | 'safe'
  timestamp: number
}

export function useFileScan(onComplete?: (results: ScanResult[]) => void) {
  const [terminalOutput, setTerminalOutput] = useState<string[]>([])
  const [isScanning, setIsScanning] = useState(false)
  const [scanResults, setScanResults] = useState<ScanResult[]>([])
  const [visitedStates, setVisitedStates] = useState<VisitedState[]>([])
  const currentFileIndexRef = useRef<number>(0)
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
    setVisitedStates([])
    currentFileIndexRef.current = 0

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
                    
                    // Split message by newlines to handle multi-line messages
                    const lines = message.split(/\r?\n/)
                    
                    // Debug: log if message contains state transitions
                    if (message.includes('State:') || message.includes('Final state')) {
                      console.log('📦 Message contains state transitions, splitting into', lines.length, 'lines')
                      console.log('📦 Sample lines:', lines.slice(0, 3).map(l => l.substring(0, 50)))
                    }
                    
                    // Parse each line individually
                    for (const line of lines) {
                      // Parse C++ output to extract scan results
                      // Look for lines like: "[1/32] Analyzing: filename" and "✓ Result: SUSPICIOUS/SAFE"
                      const analyzingMatch = line.match(/\[(\d+)\/(\d+)\]\s*Analyzing:\s*([^\n\r]+)/i)
                      if (analyzingMatch) {
                        const fileIndex = parseInt(analyzingMatch[1]) - 1 // Convert to 0-based
                        currentFileIndexRef.current = fileIndex
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
                        } else {
                          // Update file index if result already exists
                          currentFileIndexRef.current = existingIndex
                        }
                      }
                      
                      // Look for result lines: "✓ Result: SUSPICIOUS (pattern)" or "✓ Result: SAFE"
                      // These come right after the analyzing line, so match to the most recent unupdated result
                      const resultMatch = line.match(/✓\s*Result:\s*(SUSPICIOUS|SAFE)(?:\s*\(([^)]+)\))?/i)
                      if (resultMatch) {
                        const status = resultMatch[1].toLowerCase() === 'suspicious' ? 'suspicious' : 'safe'
                        const pattern = resultMatch[2] || null
                        const severity = status === 'suspicious' 
                          ? (pattern === 'executable' || pattern === 'screensaver' ? 'high' : 
                             pattern === 'batch_file' || pattern === 'vbscript' ? 'medium' : 'low')
                          : 'safe'
                        
                        // Find the most recent result that hasn't been fully updated
                        // Look for the last result that is still a placeholder (has default values)
                        let updated = false
                        let updatedIndex = -1
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
                              severity: severity,
                              pattern: pattern,
                              color: status === 'suspicious'
                                ? (pattern === 'executable' || pattern === 'screensaver' ? 'red' : 
                                   pattern === 'batch_file' || pattern === 'vbscript' ? 'yellow' : 'orange')
                                : 'blue'
                            }
                            results[i] = updatedResult
                            updatedIndex = i
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
                            severity: severity,
                            pattern: pattern,
                            color: status === 'suspicious'
                              ? (pattern === 'executable' || pattern === 'screensaver' ? 'red' : 
                                 pattern === 'batch_file' || pattern === 'vbscript' ? 'yellow' : 'orange')
                              : 'blue'
                          }
                          results.push(newResult)
                          updatedIndex = results.length - 1
                          setScanResults((prev) => [...prev, newResult])
                        }
                        
                        // Update all visited states for this file index with the correct status
                        if (updatedIndex >= 0) {
                          const fileIndex = updatedIndex
                          setVisitedStates((prev) => {
                            return prev.map(vs => {
                              if (vs.fileIndex === fileIndex) {
                                return {
                                  ...vs,
                                  status: status,
                                  severity: severity,
                                  timestamp: Date.now() // Update timestamp to keep it recent
                                }
                              }
                              return vs
                            })
                          })
                        }
                      }
                      
                      // Parse state transitions: "State: q0 → q1" or "q0 → q1"
                      // Also match "Final state: q1"
                      // The line might have leading spaces: "  State: q0 → q0"
                      const trimmedLine = line.trim()
                      
                      // Check if line contains state transition patterns
                      if (trimmedLine.includes('State:') || trimmedLine.includes('Final state')) {
                        // Try multiple regex patterns to match state transitions
                        // The format is: "State: q0 → q1 (symbol: 'x')" or "Final state: q1"
                        // Pattern 1: "State: q0 → q1" - match the exact format with Unicode arrow (may have text after)
                        let stateTransitionMatch = trimmedLine.match(/State:\s*q(\d+)\s*→\s*q(\d+)/i)
                        // Pattern 2: "State: q0 -> q1" - match ASCII arrow
                        if (!stateTransitionMatch) {
                          stateTransitionMatch = trimmedLine.match(/State:\s*q(\d+)\s*->\s*q(\d+)/i)
                        }
                        // Pattern 3: "q0 → q1" (without "State:")
                        if (!stateTransitionMatch) {
                          stateTransitionMatch = trimmedLine.match(/^q(\d+)\s*→\s*q(\d+)/i)
                        }
                        if (!stateTransitionMatch) {
                          stateTransitionMatch = trimmedLine.match(/^q(\d+)\s*->\s*q(\d+)/i)
                        }
                        // Pattern 4: "Final state: q1"
                        const finalStateMatch = trimmedLine.match(/Final\s+state:\s*q(\d+)/i)
                        
                        // Always log to see what's happening
                        console.log('🔍 State line analysis:', {
                          line: trimmedLine.substring(0, 60),
                          stateTransitionMatch: stateTransitionMatch ? `q${stateTransitionMatch[1]} → q${stateTransitionMatch[2]}` : null,
                          finalStateMatch: finalStateMatch ? `q${finalStateMatch[1]}` : null,
                          isScanning,
                          hasMatch: !!(stateTransitionMatch || finalStateMatch),
                          regexTest1: /State:\s*q(\d+)\s*→\s*q(\d+)/i.test(trimmedLine),
                          regexTest2: /State:\s*q(\d+)\s*->\s*q(\d+)/i.test(trimmedLine)
                        })
                        
                        // Process state transition if matched
                        // Process even if isScanning is false (might be stale closure value)
                        // As long as we have results, we're in a scan context
                        if (stateTransitionMatch || finalStateMatch) {
                          const stateTo = finalStateMatch 
                            ? `q${finalStateMatch[1]}` 
                            : `q${stateTransitionMatch![2]}`
                          
                          // Get current file result - use the most recent one if available
                          // Use the file index from the ref, or fall back to the last result
                          const fileIndex = currentFileIndexRef.current >= 0 
                            ? currentFileIndexRef.current 
                            : (results.length > 0 ? results.length - 1 : 0)
                          
                          // Get the result for this file index
                          // Note: The result might still be a placeholder (status='safe') if the result line hasn't been parsed yet
                          // It will be updated later when the result line is parsed
                          const currentFileResult = results[fileIndex] || results[results.length - 1]
                          
                          // Debug logging
                          console.log('🔵 State transition detected:', {
                            originalLine: line.substring(0, 50),
                            trimmedLine: trimmedLine.substring(0, 50),
                            stateTo,
                            fileIndex: fileIndex,
                            currentFileResult: currentFileResult?.status,
                            isPlaceholder: currentFileResult?.status === 'safe' && currentFileResult?.pattern === null,
                            totalResults: results.length,
                            isScanning, // Log for debugging
                            stateTransitionMatch: stateTransitionMatch ? `q${stateTransitionMatch[1]} → q${stateTransitionMatch[2]}` : null,
                            finalStateMatch: finalStateMatch ? `q${finalStateMatch[1]}` : null
                          })
                          
                          // Add visited state with current file's status
                          // Note: If the result is still a placeholder, it will be updated when the result line is parsed
                          const visitedState: VisitedState = {
                            stateId: stateTo,
                            fileIndex: fileIndex,
                            status: currentFileResult?.status || 'safe',
                            severity: currentFileResult?.severity || 'safe',
                            timestamp: Date.now()
                          }
                          
                          setVisitedStates((prev) => {
                            // Add the state - allow multiple visits but keep the most recent
                            const existingIndex = prev.findIndex(v => v.stateId === stateTo && v.fileIndex === visitedState.fileIndex)
                            if (existingIndex >= 0) {
                              // Update existing visit with new timestamp
                              const updated = [...prev]
                              updated[existingIndex] = visitedState
                              console.log('🟢 Updated visited state:', stateTo, 'Total visited:', updated.length)
                              return updated
                            } else {
                              // Add new visit
                              const newList = [...prev, visitedState]
                              console.log('🟢 Added visited state:', stateTo, 'Total visited:', newList.length)
                              return newList
                            }
                          })
                        }
                      }
                      
                      // Also parse the final summary line: "✓ Safe files: X" and "✗ Suspicious files: Y"
                      const safeCountMatch = line.match(/✓\s*Safe files:\s*(\d+)/i)
                      const suspiciousCountMatch = line.match(/✗\s*Suspicious files:\s*(\d+)/i)
                      
                      if (safeCountMatch || suspiciousCountMatch) {
                        // Summary found - ensure all results are properly set
                        // Results should already be parsed from individual file results above
                        // Just ensure the final state is correct
                        setScanResults((prev) => [...prev]) // Trigger re-render with current results
                      }
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
    setVisitedStates([])
    currentFileIndexRef.current = 0
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
    visitedStates,
    scanFiles,
    stopScan,
    reset
  }
}

