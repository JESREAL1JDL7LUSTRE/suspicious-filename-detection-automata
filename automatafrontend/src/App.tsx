import { useCallback, useMemo, useState } from 'react'
import './App.css'
import { Button } from './components/ui/button'
import ReactFlow, { Background, Controls, MiniMap } from 'reactflow'
import 'reactflow/dist/style.css'

import { fetchAutomataJson, toReactFlowGraph, type AutomataJson, type Graph } from './parser/json'

function App() {
  const [graph, setGraph] = useState<Graph>({ nodes: [], edges: [] })
  const [status, setStatus] = useState<string>('Idle')
  const [selected, setSelected] = useState<string>('automata.json')

  const outputDir = useMemo(
    () => 'D:/SCHOOL/Automata/finalProject/output',
    []
  )

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

  // Load on demand via button only

  return (
    <div className="min-h-screen w-full bg-gray-50 text-gray-900">
      <header className="w-full border-b bg-white">
        <div className="mx-auto max-w-6xl px-4 py-4 flex items-center justify-between">
          <h1 className="text-xl font-semibold">Automata Visualizer</h1>
          <div className="flex items-center gap-2">
            <select
              className="rounded border px-3 py-2 text-sm"
              value={selected}
              onChange={(e) => setSelected(e.target.value)}
              title="Choose JSON file"
            >
              {files.map((f) => (
                <option key={f} value={f}>
                  {f}
                </option>
              ))}
            </select>
            <Button onClick={loadGraph}>Load Automata</Button>
          </div>
        </div>
      </header>

      <main className="mx-auto max-w-6xl px-4 py-6">
        <div className="mb-3 text-sm text-gray-600">Status: {status}</div>

        <div className="h-[70vh] w-full rounded border bg-white">
          <ReactFlow nodes={graph.nodes} edges={graph.edges} fitView>
            <MiniMap />
            <Controls />
            <Background />
          </ReactFlow>
        </div>

        <div className="mt-4 text-sm text-gray-700">
          <p>
            This visualization reads <code>automata.json</code> produced by the C++ backend
            from <code>{outputDir}</code> using Vite <code>@fs</code> paths. Click the button
            after running the backend to refresh.
          </p>
        </div>
      </main>
    </div>
  )
}

export default App
