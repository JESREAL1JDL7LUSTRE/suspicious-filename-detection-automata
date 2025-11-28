import { useMemo } from 'react'
import ReactFlow, { Background, Controls, MiniMap, ReactFlowProvider } from 'reactflow'
import type { Node } from 'reactflow'
import 'reactflow/dist/style.css'
import type { Graph } from '../parser/json'
import type { ScanResult } from '../hooks/useFileScan'

// Memoize nodeTypes and edgeTypes outside component to avoid React Flow warning
const nodeTypes = {}
const edgeTypes = {}

interface GraphVisualizationProps {
  graph: Graph
  status: string
  selected: string
  hasRunSimulator: boolean
  isRunning: boolean
  scanResults?: ScanResult[]
  isScanMode?: boolean
}

// Color mapping for status
const getStatusColor = (status: string, severity?: string): string => {
  if (status === 'suspicious') {
    if (severity === 'high') return '#ef4444' // red
    if (severity === 'medium') return '#eab308' // yellow
    return '#f97316' // orange
  }
  return '#3b82f6' // blue (safe)
}

export function GraphVisualization({
  graph,
  status,
  selected,
  hasRunSimulator,
  isRunning,
  scanResults = [],
  isScanMode = false
}: GraphVisualizationProps) {
  // Debug logging
  console.log('GraphVisualization render:', {
    nodes: graph.nodes.length,
    edges: graph.edges.length,
    isScanMode,
    scanResults: scanResults.length
  })
  
  // Update node colors based on scan results - progressive coloring
  const coloredNodes = useMemo(() => {
    // If not in scan mode or no results, return original nodes
    if (!isScanMode || scanResults.length === 0) {
      return graph.nodes
    }

    // Create a map of scan results by index for progressive coloring
    // Each scan result corresponds to a node index (modulo for cycling)
    return graph.nodes.map((node: Node, nodeIndex: number) => {
      // Map scan results to nodes progressively
      // Use modulo to cycle through nodes if we have more results than nodes
      const resultIndex = nodeIndex % scanResults.length
      const result = scanResults[resultIndex]
      
      // Also try to match by pattern name in node label
      // ReactFlow stores label in node.data.label, not node.label
      const nodeLabel = ((node.data?.label as string) || node.id || '').toLowerCase()
      let matchedResult: ScanResult | null = result
      
      // Try to find a better match based on pattern
      for (const scanResult of scanResults) {
        if (scanResult.pattern && nodeLabel.includes(scanResult.pattern.toLowerCase())) {
          matchedResult = scanResult
          break
        }
      }
      
      // Color based on the matched result
      if (matchedResult) {
        return {
          ...node,
          style: {
            ...node.style,
            backgroundColor: getStatusColor(matchedResult.status, matchedResult.severity),
            borderColor: getStatusColor(matchedResult.status, matchedResult.severity),
            color: '#ffffff',
            transition: 'background-color 0.3s ease, border-color 0.3s ease'
          }
        }
      }

      // Default: blue for safe/unknown
      return {
        ...node,
        style: {
          ...node.style,
          backgroundColor: '#3b82f6',
          borderColor: '#3b82f6',
          color: '#ffffff'
        }
      }
    })
  }, [graph.nodes, scanResults, isScanMode])

  return (
    <div className="flex-1 flex flex-col min-h-0">
      <div className="mb-2 text-sm text-gray-600 shrink-0">
        Status: {status}
        {!hasRunSimulator && !isRunning && !isScanMode && (
          <span className="ml-2 text-xs text-amber-600">
            (Run simulator first to generate output files)
          </span>
        )}
        {isScanMode && scanResults.length > 0 && (
          <span className="ml-2 text-xs">
            <span className="text-blue-600">Safe: {scanResults.filter(r => r.status === 'safe').length}</span>
            {' | '}
            <span className="text-red-600">Suspicious: {scanResults.filter(r => r.status === 'suspicious').length}</span>
          </span>
        )}
      </div>
      <div className="flex-1 rounded border bg-white" style={{ position: 'relative', minHeight: '800px', height: '100%' }}>
        {graph.nodes.length > 0 ? (
          <ReactFlowProvider>
            <div style={{ width: '100%', height: '100%', position: 'absolute', top: 0, left: 0, right: 0, bottom: 0 }}>
              <ReactFlow 
                nodes={coloredNodes} 
                edges={graph.edges} 
                fitView
                nodeTypes={nodeTypes}
                edgeTypes={edgeTypes}
              >
                <MiniMap />
                <Controls />
                <Background />
              </ReactFlow>
            </div>
          </ReactFlowProvider>
        ) : (
          <div className="flex items-center justify-center h-full text-gray-400">
            <div className="text-center">
              <p className="text-lg mb-2">No graph data</p>
              <p className="text-sm">
                {hasRunSimulator 
                  ? 'Click "Load Automata" to view the graph'
                  : 'Run the simulator first to generate graph data'}
              </p>
            </div>
          </div>
        )}
      </div>
      <div className="mt-2 text-xs text-gray-500 shrink-0">
        <p>
          {isScanMode 
            ? `Scan visualization - ${scanResults.length} file(s) processed`
            : `Visualization of automata graphs from ${selected}`}
        </p>
        {isScanMode && (
          <div className="mt-1 flex gap-3">
            <span className="flex items-center gap-1">
              <span className="w-3 h-3 rounded bg-blue-500"></span> Safe
            </span>
            <span className="flex items-center gap-1">
              <span className="w-3 h-3 rounded bg-yellow-500"></span> Medium Risk
            </span>
            <span className="flex items-center gap-1">
              <span className="w-3 h-3 rounded bg-red-500"></span> High Risk
            </span>
          </div>
        )}
      </div>
    </div>
  )
}

