import './App.css'
import { Terminal } from './components/Terminal'
import { Header } from './components/Header'
import { GraphVisualization } from './components/GraphVisualization'
import { useSimulator } from './hooks/useSimulator'
import { useGraphLoader } from './hooks/useGraphLoader'

function App() {
  const graphLoader = useGraphLoader()
  
  const simulator = useSimulator(() => {
    graphLoader.setStatus('Simulator completed successfully - Click "Load Automata" to view graphs')
  })

  // Load on demand via button only

  return (
    <div className="min-h-screen w-full bg-gray-50 text-gray-900 flex flex-col">
      <Header
        isRunning={simulator.isRunning}
        selected={graphLoader.selected}
        files={graphLoader.files}
        hasRunSimulator={simulator.hasRunSimulator}
        onRunClick={simulator.runSimulator}
        onStopClick={simulator.stopSimulator}
        onLoadClick={graphLoader.loadGraph}
        onFileChange={graphLoader.setSelected}
      />

      <main className="flex-1 flex gap-4 p-4 overflow-hidden min-h-0">
        {/* Terminal on the left */}
        <div className="w-1/3 min-w-[550px] shrink-0 flex flex-col min-h-0">
          <Terminal output={simulator.terminalOutput} isRunning={simulator.isRunning} />
        </div>

        {/* Graph visualization on the right */}
        <GraphVisualization
          graph={graphLoader.graph}
          status={graphLoader.status}
          selected={graphLoader.selected}
          hasRunSimulator={simulator.hasRunSimulator}
          isRunning={simulator.isRunning}
        />
      </main>
    </div>
  )
}

export default App
