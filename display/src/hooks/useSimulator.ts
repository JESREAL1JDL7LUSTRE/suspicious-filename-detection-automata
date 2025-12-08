import { useCallback, useState, useRef } from 'react'
import { API_BASE_URL } from '../config'

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
    setHasRunSimulator(false)

    try {
      const url = `${API_BASE_URL}/api/run-simulator`;
      console.log('Fetching from:', url);
      
      let response: Response
      try {
        response = await fetch(url, {
          method: 'POST',
          signal: abortController.signal,
          headers: {
            'Accept': 'text/event-stream',
          },
        })
      } catch (fetchError: any) {
        console.error('Fetch error:', fetchError);
        if (fetchError.name === 'AbortError') {
          throw fetchError
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
                    const message = data.message || ''
                    const lines = message.split(/\r?\n/)
                    
                    const filteredLines = lines.filter((line: string) => {
                      const trimmed = line.trim().toLowerCase()
                      return !(trimmed === 'starting simulator...' || trimmed === 'starting simulator')
                    })
                    
                    setTerminalOutput((prev) => [...prev, ...filteredLines])
                  } else if (data.type === 'end') {
                    const success = data.code === 0
                    if (success) {
                      setHasRunSimulator(true)
                      if (onComplete) {
                        onComplete()
                      }
                    } else {
                      setHasRunSimulator(false)
                    }
                    setIsRunning(false)
                    return
                  } else if (data.type === 'error') {
                    setTerminalOutput((prev) => [...prev, data.message])
                    setIsRunning(false)
                    setHasRunSimulator(false)
                    return
                  } else if (data.type === 'start') {
                    const message = data.message || ''
                    const lines = message.split(/\r?\n/).filter((line:string) => line.trim().length > 0)
                    if (lines.length > 0) {
                      setTerminalOutput((prev) => {
                        const lastFewLines = prev.slice(-3)
                        const newLinesToAdd = lines.filter((newLine: string) => {
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
      setHasRunSimulator(false)
    }
  }, [onComplete])

  const stopSimulator = useCallback(() => {
    if (abortControllerRef.current) {
      abortControllerRef.current.abort()
      abortControllerRef.current = null
    }
    setIsRunning(false)
    setHasRunSimulator(false)
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