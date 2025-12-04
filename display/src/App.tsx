import { useState, useCallback } from 'react'
import './App.css'
import { Terminal } from './components/Terminal'
import { Header } from './components/Header'
import { GraphVisualization } from './components/GraphVisualization'
import { FileUpload } from './components/FileUpload'
import { FileProcessingIndicator } from './components/FileProcessingIndicator'
import { useSimulator } from './hooks/useSimulator'
import { useGraphLoader } from './hooks/useGraphLoader'
import { useFileScan } from './hooks/useFileScan'
import { Button } from './components/ui/button'

function App() {
  const [mode, setMode] = useState<'simulator' | 'scan'>('simulator')
  const [selectedFiles, setSelectedFiles] = useState<File[]>([])
  
  const graphLoader = useGraphLoader()
  
  const simulator = useSimulator(() => {
    graphLoader.setStatus('Simulator completed successfully - Click "Load Automata" to view graphs')
  })

  const fileScan = useFileScan((results) => {
    // Auto-load graph after scan completes
    graphLoader.setStatus(`Scan completed - ${results.length} file(s) processed`)
    // Always load the automata graph to show scan results
    // The graph will be colored by scan results automatically
    setTimeout(() => {
      graphLoader.loadGraph()
    }, 500)
  })
  
  // Auto-load graph when scan starts (if not already loaded)
  const handleScanStart = useCallback(() => {
    if (selectedFiles.length > 0) {
      setMode('scan')
      // Load graph first if empty, then start scan
      if (graphLoader.graph.nodes.length === 0) {
        graphLoader.loadGraph().then(() => {
          fileScan.scanFiles(selectedFiles)
        })
      } else {
        fileScan.scanFiles(selectedFiles)
      }
    } else {
      simulator.runSimulator()
      setMode('simulator')
    }
  }, [selectedFiles, fileScan, simulator, graphLoader])

  const handleFilesSelected = useCallback((files: File[]) => {
    setSelectedFiles(files)
  }, [])

  const handleScan = handleScanStart

  const handleReset = useCallback(() => {
    simulator.reset() // Reset simulator (clears terminal output)
    fileScan.reset() // Reset scan (clears scan results and terminal)
    setSelectedFiles([]) // Clear selected files
    setMode('simulator') // Reset to simulator mode
    graphLoader.setStatus('Ready - Click "Run Simulator" to start')
    graphLoader.resetGraph() // Reset graph to empty state
  }, [simulator, fileScan, graphLoader])

  // Determine which output to show
  const terminalOutput = mode === 'scan' ? fileScan.terminalOutput : simulator.terminalOutput
  const isRunning = mode === 'scan' ? fileScan.isScanning : simulator.isRunning

  return (
    <div className="min-h-screen w-full bg-gray-50 text-gray-900 flex flex-col">
      <Header
        isRunning={isRunning}
        selected={graphLoader.selected}
        files={graphLoader.files}
        hasRunSimulator={simulator.hasRunSimulator || fileScan.scanResults.length > 0}
        onRunClick={handleScan}
        onStopClick={mode === 'scan' ? fileScan.stopScan : simulator.stopSimulator}
        onLoadClick={graphLoader.loadGraph}
        onFileChange={graphLoader.setSelected}
        onReset={handleReset}
      />

      <main className="flex-1 flex gap-4 p-4 overflow-hidden min-h-0">
        {/* Terminal on the left */}
        <div className="w-1/3 min-w-[550px] shrink-0 flex flex-col min-h-0">
          <Terminal output={terminalOutput} isRunning={isRunning} scanMode={mode === 'scan'} />
        </div>

          {/* Graph visualization */}
          <div className="flex-2 min-h-0" style={{ minHeight: '800px' }}>
            <GraphVisualization
              graph={graphLoader.graph}
              status={graphLoader.status}
              selected={graphLoader.selected}
              hasRunSimulator={simulator.hasRunSimulator || fileScan.scanResults.length > 0}
              isRunning={isRunning}
              scanResults={fileScan.scanResults}
              visitedStates={fileScan.visitedStates}
              isScanMode={mode === 'scan' && (fileScan.isScanning || fileScan.scanResults.length > 0)}
              totalFiles={selectedFiles.length}
            />
          </div>
          
          {/* File Upload Section */}
          <div className="flex-1 flex flex-col">
            <FileUpload
              onFilesSelected={handleFilesSelected}
              onFolderSelected={handleFilesSelected}
              disabled={isRunning}
            />
            
            {selectedFiles.length > 0 && (
              <div className="mt-3 p-3 border rounded-lg bg-white">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-sm font-semibold">Ready to Scan</span>
                  <Button
                    onClick={handleScan}
                    disabled={isRunning}
                    size="sm"
                    className="text-xs"
                  >
                    {isRunning ? 'Scanning...' : `Scan ${selectedFiles.length} File(s)`}
                  </Button>
                </div>
                <p className="text-xs text-gray-500">
                  Files will be scanned for suspicious patterns. Click "Run Simulator" to use default dataset instead.
                </p>
              </div>
            )}
            
            {/* File Processing Indicator - shown at bottom during scanning */}
            {mode === 'scan' && isRunning && (
              <FileProcessingIndicator
                scanResults={fileScan.scanResults}
                isScanning={isRunning}
                totalFiles={selectedFiles.length}
                terminalOutput={fileScan.terminalOutput}
              />
            )}
          </div>
      </main>
    </div>
  )
}

export default App
