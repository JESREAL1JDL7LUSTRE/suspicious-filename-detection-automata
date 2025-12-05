import { useMemo } from 'react'
import ReactFlow, { Background, Controls, MiniMap, ReactFlowProvider, MarkerType, type Edge } from 'reactflow'
import type { Node } from 'reactflow'
import 'reactflow/dist/style.css'
import type { Graph } from '../parser/json'
import type { ScanResult, VisitedState } from '../hooks/useFileScan'

// Memoize nodeTypes and edgeTypes outside component to avoid React Flow warning
// These are empty objects because we're using default node/edge types from ReactFlow
const nodeTypes: Record<string, never> = {}
const edgeTypes: Record<string, never> = {}

interface GraphVisualizationProps {
  graph: Graph
  status: string
  selected: string
  hasRunSimulator: boolean
  isRunning: boolean
  scanResults?: ScanResult[]
  visitedStates?: VisitedState[]
  isScanMode?: boolean
}

export function GraphVisualization({
  graph,
  status,
  selected,
  hasRunSimulator,
  isRunning,
  scanResults = [],
  visitedStates = [],
  isScanMode = false
}: GraphVisualizationProps) {
  // Debug logging
  console.log('GraphVisualization render:', {
    nodes: graph.nodes.length,
    edges: graph.edges.length,
    isScanMode,
    scanResults: scanResults.length
  })
  
  // Update node colors based on visited states - progressive coloring
  const coloredNodes = useMemo(() => {
    // Base style for all nodes - ensures they're always circular
    const baseCircleStyle = {
      borderRadius: '50%',
      width: 80,
      height: 80,
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      transition: 'background-color 0.3s ease, border-color 0.3s ease'
    }

    // If not in scan mode, return nodes with base circular style
    if (!isScanMode) {
      return graph.nodes.map((node: Node) => ({
        ...node,
        style: {
          ...node.style,
          ...baseCircleStyle,
          backgroundColor: '#94a3b8', // slate-400
          borderColor: '#64748b', // slate-500
          borderWidth: 2,
          color: '#ffffff'
        }
      }))
    }

    // Create a map of visited states with their status and severity
    // Use the most recent visit for each state (in case it's visited multiple times)
    const stateVisitMap = new Map<string, { status: 'suspicious' | 'safe', severity: 'high' | 'medium' | 'low' | 'safe', timestamp: number }>()
    
    for (const visitedState of visitedStates) {
      const existing = stateVisitMap.get(visitedState.stateId)
      // Keep the most recent visit (higher timestamp = later)
      if (!existing || visitedState.timestamp > existing.timestamp) {
        stateVisitMap.set(visitedState.stateId, {
          status: visitedState.status,
          severity: visitedState.severity || 'safe',
          timestamp: visitedState.timestamp
        })
      }
    }
    
    // Debug: log visited states and node IDs
    if (visitedStates.length > 0) {
      console.log('🔴 GraphVisualization - Visited states:', visitedStates.map(v => v.stateId))
      console.log('🔴 GraphVisualization - State visit map keys:', Array.from(stateVisitMap.keys()))
      console.log('🔴 GraphVisualization - Sample node IDs:', graph.nodes.slice(0, 5).map(n => ({ id: n.id, label: n.data?.label })))
      console.log('🔴 GraphVisualization - Total nodes:', graph.nodes.length, 'Total visited:', visitedStates.length)
    } else {
      console.log('🔴 GraphVisualization - No visited states yet. isScanMode:', isScanMode, 'visitedStates.length:', visitedStates.length)
    }
    
    return graph.nodes.map((node: Node) => {
      // Extract state ID from node (could be in id, label, or data.label)
      const nodeId = node.id || ''
      const nodeLabel = ((node.data?.label as string) || node.id || '').toLowerCase()
      
      // Try to match node to visited state
      // Check if node ID matches a visited state (e.g., "q0", "q1")
      let visitedStateInfo: { status: 'suspicious' | 'safe', severity: 'high' | 'medium' | 'low' | 'safe' } | null = null
      
      // Try exact match first (node.id might be "q0", "q1", etc.)
      if (stateVisitMap.has(nodeId)) {
        visitedStateInfo = stateVisitMap.get(nodeId)!
      } else {
        // Try to extract state number from node ID or label
        const stateMatch = (nodeId || nodeLabel).match(/q?(\d+)/i)
        if (stateMatch) {
          const stateId = `q${stateMatch[1]}`
          if (stateVisitMap.has(stateId)) {
            visitedStateInfo = stateVisitMap.get(stateId)!
          }
        }
      }
      
      // Color based on visited state
      if (visitedStateInfo) {
        if (visitedStateInfo.status === 'suspicious') {
          // Color based on severity: red for high, yellow for medium, orange for low
          const color = visitedStateInfo.severity === 'high' ? '#ef4444' : // red
                       visitedStateInfo.severity === 'medium' ? '#eab308' : // yellow
                       '#f97316' // orange
          return {
            ...node,
            style: {
              ...node.style,
              backgroundColor: color,
              borderColor: color,
              borderWidth: 3,
              borderRadius: '50%',
              width: 80,
              height: 80,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              color: '#ffffff',
              transition: 'background-color 0.3s ease, border-color 0.3s ease, border-width 0.3s ease',
              boxShadow: '0 0 8px rgba(239, 68, 68, 0.5)'
            }
          }
        } else {
          // Blue for safe files
          return {
            ...node,
            style: {
              ...node.style,
              backgroundColor: '#3b82f6', // blue
              borderColor: '#2563eb', // blue-600
              borderWidth: 3,
              borderRadius: '50%',
              width: 80,
              height: 80,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              color: '#ffffff',
              transition: 'background-color 0.3s ease, border-color 0.3s ease, border-width 0.3s ease',
              boxShadow: '0 0 8px rgba(59, 130, 246, 0.5)'
            }
          }
        }
      }

      // Default: gray for unvisited states
      return {
        ...node,
        style: {
          ...node.style,
          backgroundColor: '#94a3b8', // slate-400 - consistent gray
          borderColor: '#64748b', // slate-500
          borderWidth: 2,
          borderRadius: '50%',
          width: 80,
          height: 80,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          color: '#ffffff',
          transition: 'background-color 0.3s ease, border-color 0.3s ease'
        }
      }
    })
  }, [graph.nodes, visitedStates, isScanMode])

  // Style edges with arrow heads, curved paths, and dynamic coloring
  const styledEdges = useMemo(() => {
    // Create a set of visited state IDs for quick lookup
    const visitedStateIds = new Set(visitedStates.map(vs => vs.stateId))
    
    // Create a map of visited states with their colors (most recent visit wins)
    // Use the same logic as coloredNodes for consistency
    const stateVisitMap = new Map<string, { status: 'suspicious' | 'safe', severity: 'high' | 'medium' | 'low' | 'safe', timestamp: number }>()
    for (const visitedState of visitedStates) {
      const existing = stateVisitMap.get(visitedState.stateId)
      if (!existing || visitedState.timestamp > existing.timestamp) {
        stateVisitMap.set(visitedState.stateId, {
          status: visitedState.status,
          severity: visitedState.severity || 'safe',
          timestamp: visitedState.timestamp
        })
      }
    }
    
    // Build color map from stateVisitMap
    const stateColorMap = new Map<string, string>()
    for (const [stateId, info] of stateVisitMap.entries()) {
      if (info.status === 'suspicious') {
        const color = info.severity === 'high' ? '#ef4444' : // red
                     info.severity === 'medium' ? '#eab308' : // yellow
                     '#f97316' // orange
        stateColorMap.set(stateId, color)
      } else {
        stateColorMap.set(stateId, '#3b82f6') // blue
      }
    }
    
    return graph.edges.map((edge: Edge) => {
      // Extract state IDs from source and target
      const sourceStateMatch = edge.source.match(/q?(\d+)/i)
      const targetStateMatch = edge.target.match(/q?(\d+)/i)
      const sourceStateId = sourceStateMatch ? `q${sourceStateMatch[1]}` : null
      const targetStateId = targetStateMatch ? `q${targetStateMatch[1]}` : null
      
      // Check if this edge connects visited states
      const sourceVisited = sourceStateId && visitedStateIds.has(sourceStateId)
      const targetVisited = targetStateId && visitedStateIds.has(targetStateId)
      const isVisitedEdge = sourceVisited && targetVisited
      
      // Determine edge color based on visited state
      let edgeColor = '#64748b' // Default gray
      const strokeWidth = 1.5 // Slim lines so they feel like moving dots when animated
      const arrowSize = 14 // Slightly larger arrow head
      
      if (isVisitedEdge && isScanMode && targetStateId) {
        // Use target state color (where the transition leads)
        const targetColor = stateColorMap.get(targetStateId)
        if (targetColor) {
          edgeColor = targetColor
        }
      }
      
      return {
        ...edge,
        type: 'default', // Classic bezier-style curve
        animated: !!(isVisitedEdge && isScanMode), // Only visited transitions get motion
        markerEnd: {
          type: MarkerType.ArrowClosed,
          width: arrowSize,
          height: arrowSize,
          color: edgeColor
        },
        style: {
          strokeWidth: strokeWidth,
          stroke: edgeColor,
          transition: 'stroke 0.3s ease, stroke-width 0.3s ease' // Smooth color transitions
        },
        labelStyle: {
          fill: '#374151', // Dark gray for label text
          fontWeight: 600,
          fontSize: 13,
          background: '#ffffff',
          padding: '2px 6px',
          borderRadius: '4px',
          border: `1px solid ${edgeColor}80`
        },
        labelBgStyle: {
          fill: '#ffffff', // White background for label
          fillOpacity: 0.9,
          stroke: edgeColor,
          strokeWidth: 1,
          strokeOpacity: 0.3
        }
      }
    })
  }, [graph.edges, visitedStates, isScanMode])

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
                edges={styledEdges} 
                fitView
                nodeTypes={nodeTypes}
                edgeTypes={edgeTypes}
                defaultEdgeOptions={{
                  type: 'default', // Classic bezier-style curve
                  animated: false,
                  markerEnd: {
                    type: MarkerType.ArrowClosed,
                    width: 14,
                    height: 14,
                    color: '#64748b'
                  },
                  style: {
                    strokeWidth: 1.5,
                    stroke: '#64748b'
                  }
                }}
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