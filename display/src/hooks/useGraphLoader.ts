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
      'dfa_0.json',
      'dfa_1.json',
      'dfa_2.json',
      'dfa_3.json',
      'dfa_4.json'
    ],
    []
  )

  const loadGraph = useCallback(async () => {
    try {
      setStatus('Loading...')
      const aj: AutomataJson = await fetchAutomataJson(`${outputDir}/${selected}`)
      const gf = toReactFlowGraph(aj)
      setGraph(gf)
      setStatus('Loaded')
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e)
      setStatus(`Error: ${msg}`)
    }
  }, [outputDir, selected])

  return {
    graph,
    status,
    selected,
    files,
    setSelected,
    loadGraph,
    setStatus
  }
}

