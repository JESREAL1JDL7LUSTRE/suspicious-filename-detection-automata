import { useEffect, useState } from 'react'
import type { ScanResult } from '../hooks/useFileScan'

interface FileProcessingIndicatorProps {
  scanResults: ScanResult[]
  isScanning: boolean
  totalFiles?: number
  terminalOutput?: string[]
}

export function FileProcessingIndicator({ 
  scanResults, 
  isScanning, 
  totalFiles,
  terminalOutput = []
}: FileProcessingIndicatorProps) {
  const [currentFileName, setCurrentFileName] = useState<string>('')
  const [currentFileIndex, setCurrentFileIndex] = useState<number>(0)

  // Parse terminal output to find current file being processed
  useEffect(() => {
    if (!isScanning && !currentFileName) {
      // Only reset if we don't have a current file
      return
    }

    // Look for lines like "[1/32] Analyzing: filename" in terminal output
    let latestMatch: { index: number; fileName: string } | null = null
    
    // Combine all terminal output chunks and search through it
    // Each chunk might be a full line or part of a line
    const allText = terminalOutput.join('')
    
    // Debug: log terminal output to see what we're parsing (only in development)
    if (terminalOutput.length > 0 && isScanning && process.env.NODE_ENV === 'development') {
      console.log('FileProcessingIndicator - Terminal output chunks:', terminalOutput.length)
      const lastChunk = terminalOutput[terminalOutput.length - 1]
      if (lastChunk) {
        console.log('FileProcessingIndicator - Last chunk:', lastChunk.substring(0, 200))
      }
    }
    
    // Try multiple regex patterns to catch the file name
    // Pattern 1: Complete line with filename on same line - most common format
    // Matches: "[1/32] Analyzing: filename" or "[1/32] Analyzing: filename\n"
    const pattern1 = /\[(\d+)\/(\d+)\]\s*Analyzing:\s*([^\n\r]+)/gi
    let match
    while ((match = pattern1.exec(allText)) !== null) {
      const fileIndex = parseInt(match[1])
      let fileName = match[3].trim()
      
      // Clean up filename - remove any trailing markers, arrows, etc.
      fileName = fileName.replace(/[\n\r\t]/g, '')
        .replace(/\s*→.*$/, '')
        .replace(/\s*Extracting.*$/, '')
        .replace(/\s*Pattern.*$/, '')
        .replace(/\s*Result.*$/, '')
        .trim()
      
      if (fileName && fileName.length > 0 && fileName.length < 500) { // Reasonable filename length
        if (!latestMatch || fileIndex >= latestMatch.index) {
          latestMatch = { index: fileIndex, fileName: fileName }
        }
      }
    }
    
    // Pattern 2: File might be on next line after "Analyzing:"
    if (!latestMatch) {
      const pattern2 = /\[(\d+)\/(\d+)\]\s*Analyzing:\s*\n\s*([^\n\r\[\]]+)/gi
      while ((match = pattern2.exec(allText)) !== null) {
        const fileIndex = parseInt(match[1])
        let fileName = match[3].trim()
        fileName = fileName.replace(/[\n\r\t]/g, '').trim()
        
        if (fileName && fileName.length > 0 && fileName.length < 500) {
          if (!latestMatch || fileIndex >= latestMatch.index) {
            latestMatch = { index: fileIndex, fileName: fileName }
          }
        }
      }
    }
    
    // Pattern 3: Also check for partial matches (in case text is still being typed)
    if (!latestMatch) {
      const pattern3 = /\[(\d+)\/(\d+)\]\s*Analyzing:\s*([^\n\r]{1,200})/gi
      while ((match = pattern3.exec(allText)) !== null) {
        const fileIndex = parseInt(match[1])
        let fileName = match[3].trim()
        fileName = fileName.replace(/[\n\r\t]/g, '')
          .replace(/\s*→.*$/, '')
          .replace(/\s*Extracting.*$/, '')
          .trim()
        
        if (fileName && fileName.length > 0 && fileName.length < 500) {
          if (!latestMatch || fileIndex >= latestMatch.index) {
            latestMatch = { index: fileIndex, fileName: fileName }
          }
        }
      }
    }
    
    // Update state if we found a match
    if (latestMatch) {
      setCurrentFileIndex(latestMatch.index)
      setCurrentFileName(latestMatch.fileName)
    } else if (scanResults.length > 0 && !currentFileName) {
      // Fallback: use the last scan result if we don't have a current file
      const lastResult = scanResults[scanResults.length - 1]
      if (lastResult && lastResult.file) {
        setCurrentFileIndex(scanResults.length)
        setCurrentFileName(lastResult.file)
      }
    }
  }, [terminalOutput, isScanning, scanResults, currentFileName])

  // Show when scanning OR if we have scan results (to prevent disappearing too early)
  if (!isScanning && !currentFileName && scanResults.length === 0) {
    return null
  }

  // Calculate progress based on current file index or scan results length
  const progress = totalFiles && currentFileIndex > 0 
    ? (currentFileIndex / totalFiles) * 100 
    : (totalFiles && scanResults.length > 0 ? (scanResults.length / totalFiles) * 100 : 0)
  
  // Find current result - match by filename or use the most recent one
  // Also check by index to ensure we get the right result
  let currentResult: ScanResult | null = null
  if (currentFileName) {
    // First try to find by exact filename match
    currentResult = scanResults.find(r => r.file === currentFileName)
    
    // If not found, try partial match
    if (!currentResult) {
      currentResult = scanResults.find(r => 
        r.file.includes(currentFileName) || 
        currentFileName.includes(r.file) ||
        r.path.includes(currentFileName) ||
        currentFileName.includes(r.path)
      )
    }
    
    // If still not found, try by index (currentFileIndex is 1-based, scanResults is 0-based)
    if (!currentResult && currentFileIndex > 0 && currentFileIndex <= scanResults.length) {
      currentResult = scanResults[currentFileIndex - 1]
    }
  }
  
  // Fallback to most recent result
  if (!currentResult && scanResults.length > 0) {
    currentResult = scanResults[scanResults.length - 1]
  }

  const getStatusColor = (status: string, severity?: string) => {
    if (status === 'suspicious') {
      if (severity === 'high') return 'bg-red-500'
      if (severity === 'medium') return 'bg-yellow-500'
      return 'bg-orange-500'
    }
    return 'bg-blue-500'
  }

  const getStatusText = (status: string) => {
    return status === 'suspicious' ? 'SUSPICIOUS' : 'SAFE'
  }

  return (
    <div className="mt-4 p-4 bg-white rounded-lg border border-gray-300 shadow-sm">
      <div className="flex items-center justify-between mb-3">
        <h3 className="text-sm font-semibold text-gray-700">File Processing</h3>
        {totalFiles && (currentFileIndex > 0 || scanResults.length > 0) && (
          <span className="text-xs text-gray-500">
            {currentFileIndex > 0 ? currentFileIndex : scanResults.length} / {totalFiles} files
          </span>
        )}
      </div>

      {/* Progress bar */}
      {totalFiles && (currentFileIndex > 0 || scanResults.length > 0) && (
        <div className="w-full bg-gray-200 rounded-full h-2 mb-4">
          <div
            className="bg-blue-500 h-2 rounded-full transition-all duration-300 ease-out"
            style={{ width: `${progress}%` }}
          />
        </div>
      )}

      {/* Current file being processed */}
      <div className="space-y-2">
        {currentFileName ? (
          <>
            <div className="flex items-center gap-2">
              <div className="w-3 h-3 rounded-full bg-blue-500 animate-pulse" />
              <span className="text-sm font-medium text-gray-700">
                Processing:
              </span>
            </div>
            <div className="pl-5">
              <div className="text-sm text-gray-800 font-mono break-all">
                {currentFileName}
              </div>
              {currentResult && (
                <div className="flex items-center gap-2 mt-2">
                  <span className={`text-xs px-2 py-0.5 rounded ${getStatusColor(currentResult.status, currentResult.severity)} text-white`}>
                    {getStatusText(currentResult.status)}
                  </span>
                  {currentResult.pattern && (
                    <span className="text-xs text-gray-500">
                      Pattern: {currentResult.pattern}
                    </span>
                  )}
                </div>
              )}
            </div>
          </>
        ) : (
          <div className="flex items-center gap-2 text-sm text-gray-500">
            <div className="w-3 h-3 rounded-full bg-blue-500 animate-pulse" />
            <span>Initializing scan...</span>
          </div>
        )}
      </div>
    </div>
  )
}

