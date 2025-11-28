import { useEffect, useRef, useState } from 'react'

interface TerminalProps {
  output: string[]
  isRunning: boolean
}

interface ParsedLine {
  text: string
  type: 'header' | 'info' | 'success' | 'error' | 'warning' | 'table' | 'section' | 'metric' | 'normal'
}

// Parse a line to determine its type and styling
function parseLine(line: string): ParsedLine {
  const trimmed = line.trim()
  
  // Box-drawing headers (╔═══╗)
  if (/^╔═+╗$/.test(trimmed) || /^║.*║$/.test(trimmed) || /^╚═+╝$/.test(trimmed)) {
    return { text: line, type: 'header' }
  }
  
  // Section headers (+---+)
  if (/^\+-+\+$/.test(trimmed) || /^\|.*\|$/.test(trimmed)) {
    return { text: line, type: 'section' }
  }
  
  // Table borders (┌─┬─┐, ├─┼─┤, └─┴─┘)
  if (/^[┌├└][─┬┼┴]+[┐┤┘]$/.test(trimmed) || /^│.*│$/.test(trimmed)) {
    return { text: line, type: 'table' }
  }
  
  // [INFO] tags
  if (/^\[INFO\]/.test(trimmed)) {
    return { text: line, type: 'info' }
  }
  
  // [SUCCESS] tags
  if (/^\[SUCCESS\]/.test(trimmed)) {
    return { text: line, type: 'success' }
  }
  
  // [ERROR] or [WARN] tags
  if (/^\[ERROR\]/.test(trimmed)) {
    return { text: line, type: 'error' }
  }
  
  if (/^\[WARN\]/.test(trimmed)) {
    return { text: line, type: 'warning' }
  }
  
  // Metrics (lines with numbers/percentages)
  if (/^\s*[✓✗].*:/.test(trimmed) || /^\s*[A-Za-z\s]+:\s*\d/.test(trimmed)) {
    return { text: line, type: 'metric' }
  }
  
  // Empty lines
  if (trimmed === '') {
    return { text: line, type: 'normal' }
  }
  
  return { text: line, type: 'normal' }
}

// Get color class for a line type
function getColorClass(type: ParsedLine['type']): string {
  switch (type) {
    case 'header':
      return 'text-cyan-400 font-bold'
    case 'section':
      return 'text-blue-400 font-semibold'
    case 'info':
      return 'text-blue-300'
    case 'success':
      return 'text-green-300'
    case 'error':
      return 'text-red-400'
    case 'warning':
      return 'text-yellow-400'
    case 'metric':
      return 'text-cyan-300'
    case 'table':
      return 'text-gray-300'
    default:
      return 'text-green-400'
  }
}

export function Terminal({ output, isRunning }: TerminalProps) {
  const terminalRef = useRef<HTMLDivElement>(null)
  const [displayedOutput, setDisplayedOutput] = useState<string[]>([])
  const displayedIndexRef = useRef(0)
  const timeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null)
  const lastOutputLengthRef = useRef(0)

  // Progressive reveal effect: show lines one by one with a small delay
  useEffect(() => {
    // Reset if output was cleared
    if (output.length === 0) {
      setDisplayedOutput([])
      displayedIndexRef.current = 0
      lastOutputLengthRef.current = 0
      if (timeoutRef.current) {
        clearTimeout(timeoutRef.current)
      }
      return
    }

    // Check if we have new output to process
    if (output.length > lastOutputLengthRef.current) {
      lastOutputLengthRef.current = output.length
    }

    // Process next line if available
    const processNextLine = () => {
      if (displayedIndexRef.current < output.length) {
        const nextLine = output[displayedIndexRef.current]
        setDisplayedOutput((prev) => [...prev, nextLine])
        displayedIndexRef.current++

        // Schedule next line with a small delay (15-25ms per line)
        const delay = Math.random() * 10 + 15
        timeoutRef.current = setTimeout(processNextLine, delay)
      }
    }

    // Start processing if we're behind
    if (displayedIndexRef.current < output.length) {
      processNextLine()
    }

    return () => {
      if (timeoutRef.current) {
        clearTimeout(timeoutRef.current)
      }
    }
  }, [output])

  // Auto-scroll to bottom when new output arrives
  useEffect(() => {
    if (terminalRef.current) {
      terminalRef.current.scrollTop = terminalRef.current.scrollHeight
    }
  }, [displayedOutput])

  return (
    <div className="custom-scroll-bar min-h-screen max-h-screen flex flex-col bg-gray-900 text-green-400 font-mono text-sm rounded-lg border border-gray-700">
      <div className="px-4 py-2 bg-gray-800 border-b border-gray-700 flex items-center justify-between shrink-0">
        <div className="flex items-center gap-2">
          <div className="w-3 h-3 rounded-full bg-red-500"></div>
          <div className="w-3 h-3 rounded-full bg-yellow-500"></div>
          <div className="w-3 h-3 rounded-full bg-green-500"></div>
          <span className="ml-2 text-gray-400 text-xs">Terminal</span>
        </div>
        {isRunning && (
          <div className="flex items-center gap-2 text-xs text-yellow-400">
            <div className="w-2 h-2 bg-yellow-400 rounded-full animate-pulse"></div>
            Running...
          </div>
        )}
      </div>
      <div
        ref={terminalRef}
        className="flex-1 overflow-y-auto p-4 space-y-0.5 min-h-0 leading-relaxed custom-scroll-bar"
      >
        {displayedOutput.length === 0 ? (
          <div className="text-gray-500">Ready. Click "Run Simulator" to start...</div>
        ) : (
          displayedOutput.map((line, index) => {
            const parsed = parseLine(line)
            const colorClass = getColorClass(parsed.type)
            
            return (
              <div 
                key={index} 
                className={`whitespace-pre-wrap wrap-break-word ${colorClass} ${
                  parsed.type === 'header' ? 'my-1' : ''
                } ${parsed.type === 'section' ? 'my-0.5' : ''}`}
              >
                {parsed.type === 'success' && (
                  <span className="text-green-500 mr-1">✓</span>
                )}
                {parsed.type === 'error' && (
                  <span className="text-red-500 mr-1">✗</span>
                )}
                {parsed.type === 'warning' && (
                  <span className="text-yellow-500 mr-1">⚠</span>
                )}
                {parsed.text}
                {index === displayedOutput.length - 1 && isRunning && (
                  <span className="text-green-400 animate-pulse ml-1">▋</span>
                )}
              </div>
            )
          })
        )}
      </div>
    </div>
  )
}
