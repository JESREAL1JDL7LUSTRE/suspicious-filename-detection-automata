import { useMemo } from 'react'
import ReactFlow, { Background, Controls, MiniMap, ReactFlowProvider } from 'reactflow'
import type { Node } from 'reactflow'
import 'reactflow/dist/style.css'
import type { Graph } from '../parser/json'
import type { ScanResult } from '../hooks/useFileScan'
import { FileProcessingIndicator } from './FileProcessingIndicator'

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
  totalFiles?: number
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
  isScanMode = false,
  totalFiles
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

    // Color nodes based on scan results
    // Collect all unique patterns and their severities from scan results
    const patternSeverityMap = new Map<string, 'high' | 'medium' | 'low' | 'safe'>()
    const patternStatusMap = new Map<string, 'suspicious' | 'safe'>()
    
    for (const result of scanResults) {
      if (result.pattern) {
        // Store the highest severity for each pattern (high > medium > low)
        const currentSeverity = patternSeverityMap.get(result.pattern)
        if (!currentSeverity || 
            (result.severity === 'high') ||
            (result.severity === 'medium' && currentSeverity !== 'high') ||
            (result.severity === 'low' && currentSeverity === 'safe')) {
          patternSeverityMap.set(result.pattern, result.severity)
          patternStatusMap.set(result.pattern, result.status)
        }
      }
    }
    
    return graph.nodes.map((node: Node) => {
      // Get node label for matching
      const nodeLabel = ((node.data?.label as string) || node.id || '').toLowerCase()
      let matchedPattern: string | null = null
      let matchedSeverity: 'high' | 'medium' | 'low' | 'safe' = 'safe'
      let matchedStatus: 'suspicious' | 'safe' = 'safe'
      
      // Try to match by pattern name in node label
      for (const [pattern, severity] of patternSeverityMap.entries()) {
        const patternLower = pattern.toLowerCase()
        // Check if node label contains pattern or pattern-related terms
        if (nodeLabel.includes(patternLower) || 
            nodeLabel.includes(patternLower.replace('_', ' ')) ||
            nodeLabel.includes(patternLower.replace('_', ''))) {
          matchedPattern = pattern
          matchedSeverity = severity
          matchedStatus = patternStatusMap.get(pattern) || 'safe'
          break
        }
      }
      
      // Color based on the matched result
      if (matchedPattern && matchedStatus === 'suspicious') {
        // Color based on severity: red for high, yellow for medium, orange for low
        const color = matchedSeverity === 'high' ? '#ef4444' : // red
                     matchedSeverity === 'medium' ? '#eab308' : // yellow
                     '#f97316' // orange
        return {
          ...node,
          style: {
            ...node.style,
            backgroundColor: color,
            borderColor: color,
            borderWidth: 2,
            color: '#ffffff',
            transition: 'background-color 0.5s ease, border-color 0.5s ease'
          }
        }
      } else if (matchedPattern && matchedStatus === 'safe') {
        // Blue for safe files
        return {
          ...node,
          style: {
            ...node.style,
            backgroundColor: '#3b82f6', // blue
            borderColor: '#2563eb', // blue-600
            borderWidth: 2,
            color: '#ffffff',
            transition: 'background-color 0.5s ease, border-color 0.5s ease'
          }
        }
      }

      // Default: consistent gray color for unmatched nodes (states not related to scan results)
      return {
        ...node,
        style: {
          ...node.style,
          backgroundColor: '#94a3b8', // slate-400 - consistent gray
          borderColor: '#64748b', // slate-500
          borderWidth: 2,
          color: '#ffffff',
          transition: 'background-color 0.5s ease, border-color 0.5s ease'
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

