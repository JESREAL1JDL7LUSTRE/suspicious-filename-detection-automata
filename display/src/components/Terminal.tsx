import { useEffect, useRef, useState, useCallback } from 'react'

interface TerminalProps {
  output: string[]
  isRunning: boolean
  scanMode?: boolean // Whether we're in scan mode
}

interface ParsedLine {
  text: string
  type: 'header' | 'info' | 'success' | 'error' | 'warning' | 'table' | 'section' | 'metric' | 'normal' | 'state_transition' | 'final_state' | 'file_processing'
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
  // Also handle "State: → q0" format (missing from state, assume q0)
  const stateTransitionMatch = trimmed.match(/(?:State:\s*)?(?:q?(\d+)\s*)?(?:→|->)\s*q?(\d+)/i)
  if (stateTransitionMatch) {
    const fromState = stateTransitionMatch[1] || '0' // Default to q0 if missing
    const toState = stateTransitionMatch[2]
    return { 
      text: line, 
      type: 'state_transition',
      stateFrom: fromState,
      stateTo: toState
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
  
  // Final state lines (Final state: q3)
  const finalStateMatch = trimmed.match(/Final\s+state:\s*q?(\d+)/i)
  if (finalStateMatch) {
    return {
      text: line,
      type: 'final_state',
      stateTo: finalStateMatch[1]
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
  
  // Final state coloring
  if (type === 'final_state' && stateTo) {
    const stateNum = parseInt(stateTo)
    const colors = [
      'text-blue-400',      // q0
      'text-cyan-400',      // q1
      'text-teal-400',      // q2
      'text-green-400',      // q3 - accepting
      'text-yellow-400',    // q4
      'text-orange-400',    // q5
      'text-red-400'        // q6+
    ]
    const colorIndex = Math.min(stateNum, colors.length - 1)
    return `${colors[colorIndex]} font-bold animate-pulse`
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

export function Terminal({ output, isRunning, scanMode = false }: TerminalProps) {
  const terminalRef = useRef<HTMLDivElement>(null)
  const [autoScroll, setAutoScroll] = useState(true)
  const [showAllStates, setShowAllStates] = useState(false)
  const prevOutputLengthRef = useRef<number>(0)
  const hasInitializedRef = useRef<boolean>(false)
  const isUserScrollingRef = useRef<boolean>(false)
  const scrollAnimationFrameRef = useRef<number | null>(null)
  const isProgrammaticScrollRef = useRef  <boolean>(false)
  
    let filteredOutput = scanMode
    ? output // Show everything in scan mode
    : output


  // Filter out unwanted sections and their content
  const unwantedSections = [
    '[TEST DATASET LABELS]',
    '[CONTEXT-FREE PROPERTY]',
    '[KEY PROPERTY]',
    '[KEY INSIGHT]',
    '[EDGE-CASE BEHAVIOR]',
    '[TOKENIZATION DISCIPLINE]'
  ]
  
  let inUnwantedSection = false
  filteredOutput = filteredOutput.filter((line) => {
    const trimmed = line.trim()
    
    // Check if this line is an unwanted section header (exact match or contains the section name)
    const isUnwantedSectionHeader = unwantedSections.some(section => 
      trimmed === section || trimmed.includes(section.replace(/[[\]]/g, ''))
    )
    
    if (isUnwantedSectionHeader) {
      inUnwantedSection = true
      return false
    }
    
    // Check if we're entering a new section (any section header resets the flag)
    // Section headers are lines that start with [ and end with ]
    if (trimmed.startsWith('[') && trimmed.endsWith(']')) {
      const isUnwanted = unwantedSections.some(section => 
        trimmed === section || trimmed.includes(section.replace(/[[\]]/g, ''))
      )
      if (isUnwanted) {
        inUnwantedSection = true
        return false
      } else {
        // This is a different section, stop filtering
        inUnwantedSection = false
      }
    }
    
    // If we're in an unwanted section, filter out this line
    // Also filter out lines that contain key phrases from these sections
    if (inUnwantedSection) {
      return false
    }
    
    // Filter out lines that contain content from these sections even if section header wasn't caught
    // IMPORTANT: Always allow [INFO], [SUCCESS], [ERROR], [WARN] messages through
    const isImportantMessage = trimmed.startsWith('[INFO]') || trimmed.startsWith('[SUCCESS]') || trimmed.startsWith('[ERROR]') || trimmed.startsWith('[WARN]')
    
    // Skip filtering for important messages
    if (isImportantMessage) {
      return true
    }
    
    // Filter unwanted content only from non-important lines
    if (trimmed.includes('Ground truth derived from:') ||
        (trimmed.includes('Labels:') && trimmed.includes('field indicates ground truth')) ||
        (trimmed.includes('Dataset contains') && (trimmed.includes('malicious filename patterns') || trimmed.includes('TCP handshake sequences'))) ||
        trimmed.includes('This is a Type-2 (Context-Free) language because:') ||
        trimmed.includes('Requires STACK memory to track pairing') ||
        trimmed.includes('Cannot be recognized by DFA (Type-3)') ||
        trimmed.includes('SYN must be paired with SYN-ACK') ||
        trimmed.includes('SYN-ACK must be paired with ACK') ||
        trimmed.includes('Stack usage demonstrates Type-2 (CF) language:') ||
        trimmed.includes('Stack needed to track SYN') ||
        trimmed.includes('Cannot be recognized by finite automaton (DFA)') ||
        trimmed.includes('Requires unbounded memory for nested structures') ||
        trimmed.includes('Accepting condition: State-based (q3) AND empty stack') ||
        trimmed.includes('The Chomsky Hierarchy demonstrates computational power:') ||
        trimmed.includes('Type 3 (Regular): Fast pattern matching') ||
        trimmed.includes('Type 2 (CF): Can handle nested/paired structures') ||
        trimmed.includes('Security systems need BOTH for comprehensive detection') ||
        // Filter tokenization discipline content (only if not in important message)
        trimmed.includes('Method: Per-character tokenization') ||
        trimmed.includes('Alphabet: Printable ASCII') ||
        trimmed.includes('Processing: Sequential character-by-character') ||
        // Filter complexity notes (only standalone lines, not in important messages)
        (trimmed.includes('Complexity: O(') && !trimmed.startsWith('[')) ||
        (trimmed.includes('Complexity: O(2^') && !trimmed.startsWith('[')) ||
        (trimmed.includes('Complexity: O(k n log n)') && !trimmed.startsWith('[')) ||
        (trimmed.includes('Empirical:') && !trimmed.startsWith('[')) ||
        // Filter dataset validation output (only if it's a standalone line, not part of [SUCCESS])
        ((trimmed.includes('Malicious:') && trimmed.includes('Benign:')) && !trimmed.startsWith('[')) ||
        (trimmed.includes('Unique extensions:') && !trimmed.startsWith('[')) ||
        (trimmed.includes('Extensions:') && (trimmed.includes('exe') || trimmed.includes('bat') || trimmed.includes('scr')) && !trimmed.startsWith('['))) {
      return false
    }
    
    // Filter out bullet points that are part of these sections
    if ((trimmed.startsWith('•') || trimmed.startsWith('-')) && 
        (trimmed.includes('Stack') || trimmed.includes('DFA') || trimmed.includes('SYN') || 
         trimmed.includes('Chomsky') || trimmed.includes('Type 3') || trimmed.includes('Type 2') ||
         trimmed.includes('Security systems'))) {
      return false
    }
    
    return true
  })

  // Filter state transitions: hide all when toggle is off
  if (!showAllStates) {
    filteredOutput = filteredOutput.filter((line) => {
      const parsed = parseLine(line)
      // Hide all state transitions and final states when toggle is off
      return parsed.type !== 'state_transition' && parsed.type !== 'final_state'
    })
  }

  // Custom smooth scroll function with configurable duration
  // forceScroll: if true, ignore autoScroll state check (for manual toggle)
  const smoothScrollToBottom = useCallback((duration: number = 250, forceScroll: boolean = false) => {
    if (!terminalRef.current) return
    
    // Only check user scrolling if not forcing
    if (!forceScroll && isUserScrollingRef.current) return
    
    // Cancel any existing scroll animation
    if (scrollAnimationFrameRef.current !== null) {
      cancelAnimationFrame(scrollAnimationFrameRef.current)
      scrollAnimationFrameRef.current = null
    }
    
    const container = terminalRef.current
    const start = container.scrollTop
    const target = container.scrollHeight - container.clientHeight
    const distance = target - start
    
    // If already at bottom or very close, don't scroll
    if (Math.abs(distance) < 10) return
    
    // Mark that we're doing programmatic scrolling
    isProgrammaticScrollRef.current = true
    
    const startTime = performance.now()
    const initialAutoScroll = autoScroll // Capture at start
    
    const animateScroll = (currentTime: number) => {
      // Check if auto-scroll was disabled (only if not forcing) or user is scrolling
      if ((!forceScroll && !initialAutoScroll) || (!forceScroll && isUserScrollingRef.current) || !terminalRef.current) {
        scrollAnimationFrameRef.current = null
        isProgrammaticScrollRef.current = false
        return
      }
      
      const elapsed = currentTime - startTime
      const progress = Math.min(elapsed / duration, 1)
      
      // Use linear easing for very slow scrolls to make it more readable
      const easing = duration > 10000 
        ? progress // Linear for very slow scrolls
        : 1 - Math.pow(1 - progress, 3) // Ease-out for faster scrolls
      
      if (terminalRef.current) {
        const newScrollTop = start + distance * easing
        terminalRef.current.scrollTop = newScrollTop
      }
      
      if (progress < 1) {
        scrollAnimationFrameRef.current = requestAnimationFrame(animateScroll)
      } else {
        scrollAnimationFrameRef.current = null
        // Reset programmatic scroll flag after a short delay
        setTimeout(() => {
          isProgrammaticScrollRef.current = false
        }, 100)
      }
    }
    
    scrollAnimationFrameRef.current = requestAnimationFrame(animateScroll)
  }, [autoScroll])

  // Auto-scroll to bottom when new output arrives (only if auto-scroll is enabled)
  useEffect(() => {
    const currentLength = filteredOutput.length
    const hasNewContent = currentLength > prevOutputLengthRef.current
    
    if (hasNewContent) {
      prevOutputLengthRef.current = currentLength
    }
    
    if (terminalRef.current && autoScroll && hasNewContent && !isUserScrollingRef.current) {
      // Use smooth scrolling behavior for new content
      const scrollToBottom = () => {
        if (terminalRef.current && !isUserScrollingRef.current) {
          const container = terminalRef.current
          // Always use smooth scroll for auto-scroll
          container.scrollTo({
            top: container.scrollHeight,
            behavior: 'smooth'
          })
        }
      }
      
      // Wait for DOM to update, then scroll smoothly
      const timeoutId = setTimeout(scrollToBottom, 50)
      return () => clearTimeout(timeoutId)
    } else if (hasNewContent) {
      prevOutputLengthRef.current = currentLength
    }
  }, [filteredOutput, autoScroll])

  // Scroll to bottom when auto-scroll is enabled (even if content already exists)
  // This handles: initial mount with content, or toggling auto-scroll on
  const prevAutoScrollRef = useRef<boolean>(autoScroll)
  useEffect(() => {
    // Only scroll if auto-scroll was just enabled (changed from false to true) or on initial mount
    const wasJustEnabled = !prevAutoScrollRef.current && autoScroll
    const isInitialMount = !hasInitializedRef.current && autoScroll && filteredOutput.length > 0
    
    if (isInitialMount) {
      hasInitializedRef.current = true
    }
    
    prevAutoScrollRef.current = autoScroll
    
    if (terminalRef.current && (wasJustEnabled || isInitialMount) && filteredOutput.length > 0 && !isUserScrollingRef.current) {
      const scrollToBottomSmooth = () => {
        if (terminalRef.current && !isUserScrollingRef.current) {
          const container = terminalRef.current
          const { scrollTop, scrollHeight, clientHeight } = container
          const isAtBottom = scrollHeight - scrollTop - clientHeight < 10
          
          // Only scroll if not already at bottom
          if (!isAtBottom) {
            // Faster scroll for readability
            smoothScrollToBottom(8000)
          }
        }
      }
      
      // Scroll smoothly when auto-scroll is toggled on or on initial mount
      // Use a delay to ensure DOM is ready
      const timeoutId = setTimeout(scrollToBottomSmooth, 100)
      return () => clearTimeout(timeoutId)
    }
  }, [autoScroll, filteredOutput.length, smoothScrollToBottom])
  
  // Also check if user manually scrolled up (disable auto-scroll if they did)
  useEffect(() => {
    let scrollTimeout: ReturnType<typeof setTimeout> | null = null
    
    const handleScroll = () => {
      // Ignore scroll events from programmatic scrolling
      if (isProgrammaticScrollRef.current) {
        return
      }
      
      // Mark that user is scrolling
      isUserScrollingRef.current = true
      
      // Clear any existing timeout
      if (scrollTimeout) {
        clearTimeout(scrollTimeout)
      }
      
      // Reset the flag after scrolling stops
      scrollTimeout = setTimeout(() => {
        isUserScrollingRef.current = false
      }, 150)
      
      if (terminalRef.current && autoScroll) {
        const { scrollTop, scrollHeight, clientHeight } = terminalRef.current
        const isNearBottom = scrollHeight - scrollTop - clientHeight < 50 // 50px threshold
        // If user scrolled away from bottom, disable auto-scroll
        if (!isNearBottom) {
          setAutoScroll(false)
        }
      }
    }
    
    const terminal = terminalRef.current
    if (terminal) {
      terminal.addEventListener('scroll', handleScroll, { passive: true })
      return () => {
        terminal.removeEventListener('scroll', handleScroll)
        if (scrollTimeout) {
          clearTimeout(scrollTimeout)
        }
      }
    }
  }, [autoScroll])

  // Scroll functions
  const scrollToTop = () => {
    if (terminalRef.current) {
      terminalRef.current.scrollTop = 0
    }
  }

  const scrollToBottom = () => {
    if (terminalRef.current) {
      // Use instant scroll for manual "Down" button
      const container = terminalRef.current
      const lastChild = container.lastElementChild
      if (lastChild) {
        lastChild.scrollIntoView({ behavior: 'auto', block: 'end' })
      } else {
        container.scrollTop = container.scrollHeight
      }
    }
  }

  const toggleAutoScroll = () => {
    const newAutoScroll = !autoScroll
    
    // If disabling auto-scroll, cancel any ongoing scroll animation
    if (!newAutoScroll) {
      if (scrollAnimationFrameRef.current !== null) {
        cancelAnimationFrame(scrollAnimationFrameRef.current)
        scrollAnimationFrameRef.current = null
      }
    }
    
    setAutoScroll(newAutoScroll)
    
    // If enabling auto-scroll, scroll to bottom smoothly regardless of current position
    if (newAutoScroll && terminalRef.current) {
      // Reset user scrolling flag to allow programmatic scroll
      isUserScrollingRef.current = false
      
      // Use requestAnimationFrame to ensure DOM is ready
      requestAnimationFrame(() => {
        setTimeout(() => {
          if (terminalRef.current) {
            const container = terminalRef.current
            const { scrollTop, scrollHeight, clientHeight } = container
            const isAtBottom = scrollHeight - scrollTop - clientHeight < 10
            
            // Always scroll if not at bottom, even if user was at top
            if (!isAtBottom) {
              // Use smooth scroll for existing content, force it to complete
              smoothScrollToBottom(4000, true) // forceScroll = true to ignore state checks
            }
          }
        }, 50)
      })
    }
  }

  return (
    <div className="custom-scroll-bar min-h-screen max-h-screen flex flex-col bg-gray-900 text-green-400 font-mono text-sm rounded-lg border border-gray-700">
      <div className="px-4 py-2 bg-gray-800 border-b border-gray-700 flex items-center justify-between shrink-0">
        <div className="flex items-center gap-2">
          <div className="w-3 h-3 rounded-full bg-red-500"></div>
          <div className="w-3 h-3 rounded-full bg-yellow-500"></div>
          <div className="w-3 h-3 rounded-full bg-green-500"></div>
          <span className="ml-2 text-gray-400 text-xs">Terminal</span>
        </div>
        <div className="flex items-center gap-2">
          {/* State transitions toggle */}
          <button
            onClick={() => setShowAllStates(!showAllStates)}
            className={`px-2 py-1 text-xs rounded transition-colors ${
              showAllStates
                ? 'bg-blue-600 hover:bg-blue-700 text-white'
                : 'bg-gray-700 hover:bg-gray-600 text-gray-300'
            }`}
            title={showAllStates ? 'Showing all state transitions' : 'Showing first 3 state transitions (click to show all)'}
          >
            {showAllStates ? 'All States' : 'States (3)'}
          </button>
          {/* Scroll control buttons */}
          <button
            onClick={scrollToTop}
            className="px-2 py-1 text-xs bg-gray-700 hover:bg-gray-600 text-gray-300 rounded transition-colors"
            title="Scroll to top"
          >
            Top
          </button>
          <button
            onClick={scrollToBottom}
            className="px-2 py-1 text-xs bg-gray-700 hover:bg-gray-600 text-gray-300 rounded transition-colors"
            title="Scroll to bottom"
          >
            Down
          </button>
          <button
            onClick={toggleAutoScroll}
            className={`px-2 py-1 text-xs rounded transition-colors ${
              autoScroll
                ? 'bg-green-600 hover:bg-green-700 text-white'
                : 'bg-gray-700 hover:bg-gray-600 text-gray-300'
            }`}
            title={autoScroll ? 'Auto-scroll enabled' : 'Auto-scroll disabled'}
          >
            Auto Scroll
          </button>
          {isRunning && (
            <div className="flex items-center gap-2 text-xs text-yellow-400 ml-2">
              <div className="w-2 h-2 bg-yellow-400 rounded-full animate-pulse"></div>
              Running...
            </div>
          )}
        </div>
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
                } ${parsed.type === 'state_transition' || parsed.type === 'final_state' ? 'my-1 transition-all duration-300' : ''
                } ${parsed.type === 'file_processing' ? 'my-1' : ''}`}
                style={{
                  animation: parsed.type === 'state_transition' || parsed.type === 'final_state'
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
                ) : parsed.type === 'final_state' && parsed.stateTo ? (
                  <>
                    <span className="text-gray-400">Final state: </span>
                    <span className="text-green-400 font-bold animate-pulse">q{parsed.stateTo}</span>
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