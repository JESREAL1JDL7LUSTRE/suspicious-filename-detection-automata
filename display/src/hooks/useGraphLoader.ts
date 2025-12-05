import { useCallback, useState, useMemo } from 'react'
import { fetchAutomataJson, toReactFlowGraph, type AutomataJson, type Graph } from '../parser/json'
import { useOutputDir } from './useOutputDir'

export function useGraphLoader() {
  const [graph, setGraph] = useState<Graph>({ nodes: [], edges: [] })
  const [status, setStatus] = useState<string>('Ready - Click "Run Simulator" to start')
  const [selected, setSelected] = useState<string>('automata.json')
  const outputDir = useOutputDir()

  const files = useMemo(
    () => [
      'automata.json',
      'pda.json',
      'dfa_min_0.json'
    ],
    []
  )

  const loadGraph = useCallback(async () => {
    try {
      setStatus('Loading...')
      console.log('Loading graph from:', `${outputDir}/${selected}`)
      const aj: AutomataJson = await fetchAutomataJson(`${outputDir}/${selected}`)
      console.log('Loaded JSON:', aj)
      const gf = toReactFlowGraph(aj)
      console.log('Converted to ReactFlow graph:', gf, 'Nodes:', gf.nodes.length, 'Edges:', gf.edges.length)
      setGraph(gf)
      setStatus(`Loaded - ${gf.nodes.length} nodes, ${gf.edges.length} edges`)
      return Promise.resolve()
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e)
      console.error('Error loading graph:', e)
      setStatus(`Error: ${msg}`)
      return Promise.reject(e)
    }
  }, [outputDir, selected])

  const resetGraph = useCallback(() => {
    setGraph({ nodes: [], edges: [] })
  }, [])

  return {
    graph,
    status,
    selected,
    files,
    setSelected,
    loadGraph,
    setStatus,
    resetGraph
  }
}

