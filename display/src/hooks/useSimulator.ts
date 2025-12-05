import { useCallback, useState, useRef } from 'react'

const API_URL = '' // Use proxy from vite.config

export function useSimulator(onComplete?: () => void) {
  const [terminalOutput, setTerminalOutput] = useState<string[]>([])
  const [isRunning, setIsRunning] = useState(false)
  const [hasRunSimulator, setHasRunSimulator] = useState(false)
  const abortControllerRef = useRef<AbortController | null>(null)

  const runSimulator = useCallback(async () => {
    // Cancel any existing run
    if (abortControllerRef.current) {
      abortControllerRef.current.abort()
    }

    // Create new abort controller
    const abortController = new AbortController()
    abortControllerRef.current = abortController

    setIsRunning(true)
    setTerminalOutput([])
    setHasRunSimulator(false) // Reset when starting a new run

    try {
      console.log('Starting fetch request to /api/run-simulator')
      
      // Use a separate try-catch for the fetch itself
      let response: Response
      try {
        response = await fetch(`${API_URL}/api/run-simulator`, {
          method: 'POST',
          signal: abortController.signal,
          headers: {
            'Accept': 'text/event-stream',
          },
        })
      } catch (fetchError: any) {
        console.error('Fetch error:', fetchError)
        if (fetchError.name === 'AbortError') {
          throw fetchError // Re-throw abort errors
        }
        throw new Error(`Failed to connect: ${fetchError.message}`)
      }

      console.log('Response received, status:', response.status, 'ok:', response.ok)

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`)
      }

      const reader = response.body?.getReader()
      const decoder = new TextDecoder()

      if (!reader) {
        throw new Error('No response body')
      }

      console.log('Starting to read stream...')
      let buffer = ''

      // Read stream in a loop
      const readStream = async () => {
        try {
          let hasReceivedData = false
          while (true) {
            if (abortController.signal.aborted) {
              console.log('Stream aborted by user')
              try {
                reader.cancel()
              } catch (e) {
                console.error('Error cancelling reader:', e)
              }
              break
            }

            const { done, value } = await reader.read()

            if (done) {
              console.log('Stream done, received data:', hasReceivedData)
              if (!hasReceivedData) {
                console.warn('Stream ended without receiving any data')
                setTerminalOutput((prev) => [...prev, '\n[Warning: Stream ended without data]\n'])
              }
              break
            }

            hasReceivedData = true

            buffer += decoder.decode(value, { stream: true })
            const lines = buffer.split('\n\n')
            buffer = lines.pop() || ''

            for (const line of lines) {
              if (line.startsWith('data: ')) {
                try {
                  const data = JSON.parse(line.substring(6))
                  console.log('Received SSE data type:', data.type)
                  
                  if (data.type === 'stdout' || data.type === 'stderr') {
                    // Split message by newlines to handle multi-line messages
                    const message = data.message || ''
                    const lines = message.split(/\r?\n/)
                    
                    // Filter out duplicate "Starting simulator" messages from stdout/stderr
                    // (C++ program also outputs this, but server already sends it as 'start' message)
                    const filteredLines = lines.filter((line: string) => {
                      const trimmed = line.trim().toLowerCase()
                      // Skip if it's a duplicate "Starting simulator" message
                      return !(trimmed === 'starting simulator...' || trimmed === 'starting simulator')
                    })
                    
                    // Add each line separately to the terminal output
                    // Preserve empty lines for proper formatting
                    setTerminalOutput((prev) => [...prev, ...filteredLines])
                  } else if (data.type === 'end') {
                    // Check if simulator completed successfully (code 0)
                    const success = data.code === 0
                    if (success) {
                      setHasRunSimulator(true) // Enable Load Automata button
                      if (onComplete) {
                        onComplete()
                      }
                    } else {
                      setHasRunSimulator(false) // Don't enable if it failed
                    }
                    setIsRunning(false)
                    return // Exit the read loop
                  } else if (data.type === 'error') {
                    setTerminalOutput((prev) => [...prev, data.message])
                    setIsRunning(false)
                    setHasRunSimulator(false) // Don't enable if there was an error
                    return // Exit the read loop
                  } else if (data.type === 'start') {
                    // Split start message by newlines and filter empty lines
                    const message = data.message || ''
                    const lines = message.split(/\r?\n/).filter((line:string) => line.trim().length > 0)
                    // Only add if we have lines and avoid duplicates
                    if (lines.length > 0) {
                      setTerminalOutput((prev) => {
                        // Check if any of the new lines already exist in the last few lines to avoid duplicates
                        const lastFewLines = prev.slice(-3) // Check last 3 lines
                        const newLinesToAdd = lines.filter((newLine: string) => {
                          // Skip if this line already exists in recent output
                          return !lastFewLines.some(existingLine => 
                            existingLine.trim() === newLine.trim() || 
                            (existingLine.includes('Starting simulator') && newLine.includes('Starting simulator'))
                          )
                        })
                        return newLinesToAdd.length > 0 ? [...prev, ...newLinesToAdd] : prev
                      })
                    }
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
            setIsRunning(false)
          } else if (streamError instanceof Error && streamError.name === 'AbortError') {
            console.log('Stream read aborted')
          } else {
            const errorMessage = streamError instanceof Error ? streamError.message : String(streamError)
            setTerminalOutput((prev) => [...prev, `\n[Stream error: ${errorMessage}]\n`])
            setIsRunning(false)
          }
        }
      }

      await readStream()
    } catch (error: any) {
      if (error.name === 'AbortError') {
        setTerminalOutput((prev) => [...prev, '\n[Process cancelled]\n'])
      } else {
        const msg = error instanceof Error ? error.message : String(error)
        setTerminalOutput((prev) => [...prev, `\n[Error: ${msg}]\n`])
      }
      setIsRunning(false)
      setHasRunSimulator(false) // Don't enable if there was an error
    }
  }, [onComplete])

  const stopSimulator = useCallback(() => {
    if (abortControllerRef.current) {
      abortControllerRef.current.abort()
      abortControllerRef.current = null
    }
    setIsRunning(false)
    setHasRunSimulator(false) // Reset since we stopped it
  }, [])

  const reset = useCallback(() => {
    if (abortControllerRef.current) {
      abortControllerRef.current.abort()
      abortControllerRef.current = null
    }
    setTerminalOutput([])
    setIsRunning(false)
    setHasRunSimulator(false)
  }, [])

  return {
    terminalOutput,
    isRunning,
    hasRunSimulator,
    runSimulator,
    stopSimulator,
    reset
  }
}

