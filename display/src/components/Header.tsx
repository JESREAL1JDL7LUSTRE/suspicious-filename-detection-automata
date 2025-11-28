import { Button } from './ui/button'

interface HeaderProps {
  isRunning: boolean
  selected: string
  files: string[]
  hasRunSimulator: boolean
  onRunClick: () => void
  onStopClick: () => void
  onLoadClick: () => void
  onFileChange: (file: string) => void
  onReset: () => void
}

export function Header({
  isRunning,
  selected,
  files,
  hasRunSimulator,
  onRunClick,
  onStopClick,
  onLoadClick,
  onFileChange,
  onReset
}: HeaderProps) {
  return (
    <header className="w-full border-b bg-white">
      <div className="mx-auto max-w-[95vw] px-4 py-4 flex items-center justify-between">
        <h1 className="text-xl font-semibold">Automata Visualizer</h1>
        <div className="flex items-center gap-2">
          <Button
            onClick={isRunning ? onStopClick : onRunClick}
            variant={isRunning ? 'destructive' : 'default'}
          >
            {isRunning ? 'Stop Simulator' : 'Run Simulator'}
          </Button>
          <select
            className="rounded border px-3 py-2 text-sm"
            value={selected}
            onChange={(e) => onFileChange(e.target.value)}
            title="Choose JSON file"
            disabled={isRunning}
          >
            {files.map((f) => (
              <option key={f} value={f}>
                {f}
              </option>
            ))}
          </select>
          <Button 
            onClick={onLoadClick} 
            disabled={isRunning || !hasRunSimulator}
            title={!hasRunSimulator ? "Run the simulator first to generate output files" : "Load the selected automata graph"}
          >
            Load Automata
          </Button>
          <Button
            onClick={onReset}
            variant="outline"
            disabled={isRunning}
            title="Reset all state"
          >
            Reset
          </Button>
        </div>
      </div>
    </header>
  )
}

