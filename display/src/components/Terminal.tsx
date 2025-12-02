import { useEffect, useRef, useState } from 'react'

interface TerminalProps {
  output: string[]
  isRunning: boolean
  scanMode?: boolean // Whether we're in scan mode
}

interface ParsedLine {
  text: string
  type: 'header' | 'info' | 'success' | 'error' | 'warning' | 'table' | 'section' | 'metric' | 'normal' | 'state_transition' | 'file_processing'
  stateFrom?: string
  stateTo?: string
  fileName?: string
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
  
  // State transitions (q0 → q1, State: q0 → q1, q0->q1, etc.)
  // Use alternation instead of character class to avoid range issues
  const stateTransitionMatch = trimmed.match(/(?:State:\s*)?q?(\d+)\s*(?:→|->)\s*q?(\d+)/i)
  if (stateTransitionMatch) {
    return { 
      text: line, 
      type: 'state_transition',
      stateFrom: stateTransitionMatch[1],
      stateTo: stateTransitionMatch[2]
    }
  }
  
  // Also check for state transitions in format like "q0 → q1" or "State: q0 → q1"
  const stateTransitionMatch2 = trimmed.match(/(?:State:\s*)?(q\d+)\s*(?:→|->)\s*(q\d+)/i)
  if (stateTransitionMatch2) {
    const fromMatch = stateTransitionMatch2[1].match(/(\d+)/)
    const toMatch = stateTransitionMatch2[2].match(/(\d+)/)
    if (fromMatch && toMatch) {
      return { 
        text: line, 
        type: 'state_transition',
        stateFrom: fromMatch[1],
        stateTo: toMatch[1]
      }
    }
  }
  
  // File processing lines ([1/32] Analyzing: filename)
  const fileProcessingMatch = trimmed.match(/\[(\d+)\/(\d+)\]\s*Analyzing:\s*(.+)/i)
  if (fileProcessingMatch) {
    return {
      text: line,
      type: 'file_processing',
      fileName: fileProcessingMatch[3]
    }
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

// Get color class for a line type with progressive state coloring
function getColorClass(parsed: ParsedLine): string {
  const { type, stateFrom, stateTo } = parsed
  
  // Progressive state transition coloring
  if (type === 'state_transition' && stateFrom && stateTo) {
    const stateNum = parseInt(stateTo)
    // Color based on state number with gradient
    const colors = [
      'text-blue-400',      // q0 - initial
      'text-cyan-400',      // q1
      'text-teal-400',      // q2
      'text-green-400',      // q3 - accepting
      'text-yellow-400',    // q4
      'text-orange-400',    // q5
      'text-red-400'        // q6+
    ]
    const colorIndex = Math.min(stateNum, colors.length - 1)
    return `${colors[colorIndex]} font-semibold animate-pulse`
  }
  
  // File processing lines
  if (type === 'file_processing') {
    return 'text-purple-300 font-semibold'
  }
  
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

interface TypingLineProps {
  text: string
  delay: number
  onComplete?: () => void
}

function TypingLine({ text, delay, onComplete }: TypingLineProps) {
  const [displayedText, setDisplayedText] = useState('')
  const currentIndexRef = useRef(0)
  const timeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null)

  useEffect(() => {
    // Reset when text changes
    setDisplayedText('')
    currentIndexRef.current = 0
    
    if (timeoutRef.current) {
      clearTimeout(timeoutRef.current)
    }

    const typeNextChar = () => {
      if (currentIndexRef.current < text.length) {
        setDisplayedText(text.substring(0, currentIndexRef.current + 1))
        currentIndexRef.current++
        timeoutRef.current = setTimeout(typeNextChar, delay)
      } else if (onComplete) {
        onComplete()
      }
    }
    
    if (text.length > 0) {
      timeoutRef.current = setTimeout(typeNextChar, delay)
    }
    
    return () => {
      if (timeoutRef.current) {
        clearTimeout(timeoutRef.current)
      }
    }
  }, [text, delay, onComplete])

  return <span>{displayedText}</span>
}

export function Terminal({ output, isRunning, scanMode = false }: TerminalProps) {
  const terminalRef = useRef<HTMLDivElement>(null)
  
  // Filter output in scan mode to show only file processing details
  const filteredOutput = scanMode && isRunning
    ? output.filter((line) => {
        const trimmed = line.trim()
        const parsed = parseLine(line)
        
        // Show file processing related lines
        const isFileProcessing = parsed.type === 'file_processing' || 
                                 parsed.type === 'info' && (trimmed.includes('Analyzing') || trimmed.includes('Pattern match') || trimmed.includes('Total files') || trimmed.includes('Loaded detection')) ||
                                 parsed.type === 'success' && trimmed.includes('Result:') ||
                                 parsed.type === 'header' && trimmed.includes('FILE SCAN')
        
        return isFileProcessing || parsed.type === 'header' || parsed.type === 'file_processing'
      })
    : output

  // Auto-scroll to bottom when new output arrives
  useEffect(() => {
    if (terminalRef.current) {
      terminalRef.current.scrollTop = terminalRef.current.scrollHeight
    }
  }, [filteredOutput])

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
        {filteredOutput.length === 0 ? (
          <div className="text-gray-500">Ready. Click "Run Simulator" to start...</div>
        ) : (
          filteredOutput.map((line, index) => {
            const parsed = parseLine(line)
            const colorClass = getColorClass(parsed)
            
            return (
              <div 
                key={index} 
                className={`whitespace-pre-wrap wrap-break-word ${colorClass} ${
                  parsed.type === 'header' ? 'my-1' : ''
                } ${parsed.type === 'section' ? 'my-0.5' : ''
                } ${parsed.type === 'state_transition' ? 'my-1 transition-all duration-300' : ''
                } ${parsed.type === 'file_processing' ? 'my-1' : ''}`}
                style={{
                  animation: parsed.type === 'state_transition' 
                    ? 'fadeIn 0.3s ease-in' 
                    : undefined
                }}
              >
                {parsed.type === 'state_transition' && parsed.stateFrom && parsed.stateTo ? (
                  <>
                    {line.includes('State:') && <span className="text-gray-400">State: </span>}
                    <span className="text-blue-400 font-semibold">q{parsed.stateFrom}</span>
                    <span className="text-gray-500 mx-2">→</span>
                    <span className="text-cyan-400 font-bold animate-pulse">q{parsed.stateTo}</span>
                    {line.includes('→') && (
                      <span className="ml-2 text-gray-400">
                        {line.substring(line.indexOf('→') + 1).replace(/q\d+/i, '').trim()}
                      </span>
                    )}
                    {!line.includes('→') && line.includes('->') && (
                      <span className="ml-2 text-gray-400">
                        {line.substring(line.indexOf('->') + 2).replace(/q\d+/i, '').trim()}
                      </span>
                    )}
                  </>
                ) : null}
                {parsed.type === 'file_processing' && (
                  <>
                    <span className="text-purple-400">📄</span>
                    <span className="ml-2">{parsed.text}</span>
                  </>
                )}
                {parsed.type !== 'state_transition' && parsed.type !== 'file_processing' && (
                  <>
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
                  </>
                )}
                {index === filteredOutput.length - 1 && isRunning && (
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
