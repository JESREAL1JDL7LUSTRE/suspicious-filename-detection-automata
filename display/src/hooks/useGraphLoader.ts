import { useCallback, useState, useMemo } from 'react'
import { fetchAutomataJson, toReactFlowGraph, type AutomataJson, type Graph } from '../parser/json'
import { useOutputDir } from './useOutputDir'
import { API_BASE_URL } from '../config'

export function useGraphLoader() {
  const [graph, setGraph] = useState<Graph>({ nodes: [], edges: [] })
  const [status, setStatus] = useState<string>('Ready - Click "Run Simulator" to start')
  const [selected, setSelected] = useState<string>('automata.json')
  const outputDir = useOutputDir()

  const files = useMemo(
    () => [
      'automata.json',
      'pda.json',
      'dfa_min_0.json',
      'dfa_min_1.json',
      'dfa_min_2.json',
      'dfa_min_3.json',
      'dfa_min_4.json',
      'dfa_min_5.json',
      'dfa_min_6.json',
      'dfa_min_7.json',
      'dfa_min_8.json',
    ],
    []
  )

  const loadGraph = useCallback(async () => {
    try {
      setStatus('Loading...')
      console.log('Loading graph from:', `${outputDir}/${selected}`)
      
      // In Electron production, use API endpoint to read files
      let aj: AutomataJson;
      
      if (API_BASE_URL) {
        // Running in Electron - use backend API to read file
        console.log('Loading via backend API:', `${API_BASE_URL}/api/graph/${selected}`)
        const response = await fetch(`${API_BASE_URL}/api/graph/${selected}`)
        
        if (!response.ok) {
          throw new Error(`HTTP ${response.status}: ${response.statusText}`)
        }
        
        aj = await response.json()
      } else {
        // Development - use Vite's file system access
        aj = await fetchAutomataJson(`${outputDir}/${selected}`)
      }
      
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