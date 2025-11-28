import type { Edge, Node } from 'reactflow'

export type AutomataJson = {
  type: 'DFA' | 'PDA' | 'NFA'
  start: string
  accept: string[]
  nodes: Array<{
    id: string
    label?: string
    meta?: Record<string, unknown>
  }>
  edges: Array<{
    source: string
    target: string
    label?: string
    meta?: Record<string, unknown>
  }>
}

export type Graph = { nodes: Node[]; edges: Edge[] }

export async function fetchAutomataJson(absPath: string): Promise<AutomataJson> {
  const url = `/@fs/${absPath.replace(/\\/g, '/')}`
  const res = await fetch(url)
  if (!res.ok) throw new Error(`Failed to load ${absPath}: ${res.status}`)
  return await res.json()
}

export function toReactFlowGraph(json: AutomataJson): Graph {
  const nodeIndex = new Map<string, number>()
  const nodes: Node[] = json.nodes.map((n, idx) => {
    nodeIndex.set(n.id, idx)
    const base: Node = {
      id: n.id,
      position: { x: (idx % 5) * 220, y: Math.floor(idx / 5) * 160 },
      data: { label: n.label ?? n.id }
    }
    const isAccept = json.accept.includes(n.id)
    if (isAccept) {
      base.style = { border: '2px solid #22c55e', borderRadius: 8 }
    } else {
      base.style = { border: '1px solid #e5e7eb', borderRadius: 8 }
    }
    return base
  })

  const edges: Edge[] = json.edges.map((e, i) => ({
    id: `${e.source}-${e.target}-${i}`,
    source: e.source,
    target: e.target,
    label: e.label ?? ''
  }))

  // Highlight start node visually
  const startNode = nodes.find((n) => n.id === json.start)
  if (startNode) {
    startNode.style = { ...(startNode.style ?? {}), boxShadow: '0 0 0 2px #3b82f6' }
  }

  return { nodes, edges }
}
