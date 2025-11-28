import ReactFlow, { Background, Controls, MiniMap } from 'reactflow'
import 'reactflow/dist/style.css'
import type { Graph } from '../parser/json'

// Memoize nodeTypes and edgeTypes outside component to avoid React Flow warning
const nodeTypes = {}
const edgeTypes = {}

interface GraphVisualizationProps {
  graph: Graph
  status: string
  selected: string
  hasRunSimulator: boolean
  isRunning: boolean
}

export function GraphVisualization({
  graph,
  status,
  selected,
  hasRunSimulator,
  isRunning
}: GraphVisualizationProps) {
  return (
    <div className="flex-1 flex flex-col">
      <div className="mb-2 text-sm text-gray-600">
        Status: {status}
        {!hasRunSimulator && !isRunning && (
          <span className="ml-2 text-xs text-amber-600">
            (Run simulator first to generate output files)
          </span>
        )}
      </div>
      <div className="flex-1 rounded border bg-white min-h-0">
        <ReactFlow 
          nodes={graph.nodes} 
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
      <div className="mt-2 text-xs text-gray-500">
        <p>
          Visualization of automata graphs from <code>{selected}</code>
        </p>
      </div>
    </div>
  )
}

