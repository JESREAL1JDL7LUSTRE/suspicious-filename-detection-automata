import express from 'express'
import { spawn } from 'child_process'
import { fileURLToPath } from 'url'
import { dirname, join, resolve } from 'path'
import cors from 'cors'

const __filename = fileURLToPath(import.meta.url)
const __dirname = dirname(__filename)

const app = express()
const PORT = 3001

app.use(cors())
app.use(express.json())

// Get project root (one level up from display/)
const projectRoot = resolve(__dirname, '..')
// Use .exe on Windows, no extension on Unix
const isWindows = process.platform === 'win32'
const simulatorPath = join(projectRoot, isWindows ? 'simulator.exe' : 'simulator')

// Endpoint to run the simulator
app.post('/api/run-simulator', async (req, res) => {
  console.log('Received request to run simulator')
  
  // Set up Server-Sent Events for streaming output
  res.setHeader('Content-Type', 'text/event-stream')
  res.setHeader('Cache-Control', 'no-cache')
  res.setHeader('Connection', 'keep-alive')
  res.setHeader('Access-Control-Allow-Origin', '*')
  res.setHeader('X-Accel-Buffering', 'no') // Disable nginx buffering if present

  // Send initial connection message
  console.log('Sending start message')
  res.write(`data: ${JSON.stringify({ type: 'start', message: 'Starting simulator...\n' })}\n\n`)
  
  // Flush the headers
  if (res.flushHeaders) {
    res.flushHeaders()
  }
  
  // Send periodic keepalive to prevent connection timeout
  const keepAliveInterval = setInterval(() => {
    try {
      res.write(`: keepalive\n\n`)
    } catch (e) {
      clearInterval(keepAliveInterval)
    }
  }, 30000) // Every 30 seconds

  try {
    console.log(`Spawning simulator: ${simulatorPath}`)
    console.log(`Working directory: ${projectRoot}`)
    
    // Spawn the simulator process
    // On Windows, we need shell: true to properly capture console output
    // But we need to quote the path if it contains spaces
    let simulator
    if (isWindows) {
      // Quote the path to handle spaces
      const quotedPath = `"${simulatorPath}"`
      simulator = spawn(quotedPath, [], {
        cwd: projectRoot,
        stdio: ['ignore', 'pipe', 'pipe'],
        shell: true
      })
    } else {
      simulator = spawn(simulatorPath, [], {
        cwd: projectRoot,
        stdio: ['ignore', 'pipe', 'pipe'],
        shell: false
      })
    }
    
    console.log(`Simulator process spawned with PID: ${simulator.pid}`)
    console.log(`Command: ${isWindows ? `"${simulatorPath}"` : simulatorPath}`)
    console.log(`Using shell: ${isWindows}`)
    
    // Set encoding for output streams BEFORE attaching listeners
    if (simulator.stdout) {
      simulator.stdout.setEncoding('utf8')
    }
    if (simulator.stderr) {
      simulator.stderr.setEncoding('utf8')
    }

    // Handle stdout (standard output)
    if (simulator.stdout) {
      simulator.stdout.on('data', (data) => {
        const output = data.toString('utf8')
        console.log('STDOUT received, length:', output.length)
        if (output.length > 0) {
          console.log('STDOUT preview:', output.substring(0, 100).replace(/\n/g, '\\n'))
        }
        try {
          res.write(`data: ${JSON.stringify({ type: 'stdout', message: output })}\n\n`)
        } catch (e) {
          console.error('Error writing to response:', e)
        }
      })
      
      simulator.stdout.on('end', () => {
        console.log('STDOUT stream ended')
      })
    }

    // Handle stderr (error output)
    if (simulator.stderr) {
      simulator.stderr.on('data', (data) => {
        const output = data.toString('utf8')
        console.log('STDERR received, length:', output.length)
        if (output.length > 0) {
          console.log('STDERR preview:', output.substring(0, 100).replace(/\n/g, '\\n'))
        }
        try {
          res.write(`data: ${JSON.stringify({ type: 'stderr', message: output })}\n\n`)
        } catch (e) {
          console.error('Error writing to response:', e)
        }
      })
      
      simulator.stderr.on('end', () => {
        console.log('STDERR stream ended')
      })
    }

    // Handle errors
    simulator.on('error', (error) => {
      console.error('Simulator spawn error:', error)
      clearInterval(keepAliveInterval)
      res.write(`data: ${JSON.stringify({ type: 'error', message: `Error: ${error.message}\nPath: ${simulatorPath}\n` })}\n\n`)
      res.end()
    })
    
    // Add timeout to detect if process hangs
    const timeout = setTimeout(() => {
      if (!simulator.killed) {
        console.warn('Simulator process timeout - killing process')
        simulator.kill()
        res.write(`data: ${JSON.stringify({ type: 'error', message: '\nProcess timeout - simulator may be stuck\n' })}\n\n`)
        res.end()
      }
    }, 60000) // 60 second timeout

    // Handle process completion
    simulator.on('close', (code, signal) => {
      console.log(`Simulator process closed - code: ${code}, signal: ${signal}`)
      clearTimeout(timeout)
      clearInterval(keepAliveInterval)
      try {
        const exitMessage = code !== null 
          ? `\nProcess exited with code ${code}\n`
          : signal 
            ? `\nProcess terminated by signal: ${signal}\n`
            : `\nProcess closed\n`
        res.write(`data: ${JSON.stringify({ type: 'end', code, signal, message: exitMessage })}\n\n`)
        res.end()
      } catch (e) {
        console.error('Error closing response:', e)
      }
    })
    
    // Also handle exit event
    simulator.on('exit', (code, signal) => {
      console.log(`Simulator process exit - code: ${code}, signal: ${signal}`)
    })

    // Handle client disconnect - but don't kill immediately
    // Give it a moment in case it's just a temporary network hiccup
    let clientDisconnected = false
    
    // Use res.on('close') instead of req.on('close') for SSE
    // req.on('close') fires when request body is read, not when client disconnects
    res.on('close', () => {
      console.log('Response stream closed (client may have disconnected)')
      clearInterval(keepAliveInterval)
      clientDisconnected = true
      // Only kill if process is still running after a delay
      // This allows the process to complete if it's almost done
      setTimeout(() => {
        if (simulator && !simulator.killed && clientDisconnected) {
          console.log('Killing simulator process due to client disconnect')
          try {
            simulator.kill('SIGTERM')
            setTimeout(() => {
              if (simulator && !simulator.killed) {
                simulator.kill('SIGKILL')
              }
            }, 2000)
          } catch (e) {
            console.error('Error killing simulator:', e)
          }
        }
      }, 2000) // Wait 2 seconds before killing to allow process to start
    })
    
    // Handle request abort (different from response close)
    req.on('aborted', () => {
      console.log('Request aborted by client')
      clearInterval(keepAliveInterval)
      clientDisconnected = true
    })
  } catch (error) {
    res.write(`data: ${JSON.stringify({ type: 'error', message: `Failed to start simulator: ${error.message}\n` })}\n\n`)
    res.end()
  }
})

// Health check endpoint
// Scan endpoint - processes files/folders for suspicious patterns
app.post('/api/scan', async (req, res) => {
  console.log('Received scan request')
  
  res.setHeader('Content-Type', 'text/event-stream')
  res.setHeader('Cache-Control', 'no-cache')
  res.setHeader('Connection', 'keep-alive')
  res.setHeader('Access-Control-Allow-Origin', '*')
  
  const { files: filePaths } = req.body
  
  if (!filePaths || filePaths.length === 0) {
    res.write(`data: ${JSON.stringify({ type: 'error', message: 'No files provided\n' })}\n\n`)
    res.end()
    return
  }
  
  res.write(`data: ${JSON.stringify({ type: 'start', message: '╔═══════════════════════════════════════════════════════════╗\n' })}\n\n`)
  res.write(`data: ${JSON.stringify({ type: 'start', message: '║   FILE SCAN MODULE - SUSPICIOUS FILENAME DETECTION        ║\n' })}\n\n`)
  res.write(`data: ${JSON.stringify({ type: 'start', message: '╚═══════════════════════════════════════════════════════════╝\n\n' })}\n\n`)
  
  res.write(`data: ${JSON.stringify({ type: 'start', message: '[INFO] Initializing scan module...\n' })}\n\n`)
  res.write(`data: ${JSON.stringify({ type: 'start', message: `[INFO] Total files to scan: ${filePaths.length}\n` })}\n\n`)
  
  // DFA patterns (same as C++ code)
  const patterns = [
    { regex: /\.exe$/i, name: 'executable', severity: 'high', description: 'Executable file' },
    { regex: /\.scr$/i, name: 'screensaver', severity: 'high', description: 'Screensaver file' },
    { regex: /\.bat$/i, name: 'batch_file', severity: 'medium', description: 'Batch script' },
    { regex: /\.vbs$/i, name: 'vbscript', severity: 'medium', description: 'VBScript file' },
    { regex: /update/i, name: 'mimic_legitimate', severity: 'low', description: 'Mimics legitimate update file' }
  ]
  
  res.write(`data: ${JSON.stringify({ type: 'start', message: '[INFO] Loaded detection patterns:\n' })}\n\n`)
  patterns.forEach((p, idx) => {
    res.write(`data: ${JSON.stringify({ type: 'start', message: `  Pattern ${idx + 1}: ${p.name} (${p.severity} risk) - ${p.description}\n` })}\n\n`)
  })
  res.write(`data: ${JSON.stringify({ type: 'start', message: '\n' })}\n\n`)
  
  const scanResults = []
  let suspiciousCount = 0
  let safeCount = 0
  
  try {
    for (let i = 0; i < filePaths.length; i++) {
      const filePath = filePaths[i]
      const fileName = filePath.split(/[/\\]/).pop() || filePath
      
      res.write(`data: ${JSON.stringify({ 
        type: 'scan_progress', 
        message: `\n[${i + 1}/${filePaths.length}] Analyzing: ${fileName}\n`,
        file: fileName,
        index: i,
        total: filePaths.length
      })}\n\n`)
      
      res.write(`data: ${JSON.stringify({ 
        type: 'scan_progress', 
        message: `  → Extracting filename: ${fileName}\n`,
      })}\n\n`)
      
      let detected = false
      let matchedPattern = null
      const checks = []
      
      // Check against patterns
      for (const pattern of patterns) {
        const matches = pattern.regex.test(fileName)
        checks.push({ pattern: pattern.name, matches })
        if (matches && !detected) {
          detected = true
          matchedPattern = pattern
          res.write(`data: ${JSON.stringify({ 
            type: 'scan_progress', 
            message: `  → Pattern match: ${pattern.name} (${pattern.severity} risk)\n`,
          })}\n\n`)
        }
      }
      
      // Check for double extensions
      const dotCount = (fileName.match(/\./g) || []).length
      if (dotCount >= 2 && !detected) {
        detected = true
        matchedPattern = { name: 'double_extension', severity: 'medium', description: 'Double extension detected' }
        res.write(`data: ${JSON.stringify({ 
          type: 'scan_progress', 
          message: `  → Double extension detected (${dotCount} dots)\n`,
        })}\n\n`)
      }
      
      // Check for unicode tricks
      const hasUnicode = /[^\x00-\x7F]/.test(fileName)
      if (hasUnicode && !detected) {
        detected = true
        matchedPattern = { name: 'unicode_trick', severity: 'medium', description: 'Unicode characters detected' }
        res.write(`data: ${JSON.stringify({ 
          type: 'scan_progress', 
          message: `  → Unicode characters detected\n`,
        })}\n\n`)
      }
      
      const status = detected ? 'suspicious' : 'safe'
      const severity = detected ? matchedPattern.severity : 'safe'
      
      if (status === 'suspicious') {
        suspiciousCount++
      } else {
        safeCount++
      }
      
      scanResults.push({
        file: fileName,
        path: filePath,
        status,
        severity,
        pattern: matchedPattern?.name || null
      })
      
      const statusColor = status === 'suspicious' 
        ? (severity === 'high' ? 'red' : severity === 'medium' ? 'yellow' : 'orange')
        : 'blue'
      
      res.write(`data: ${JSON.stringify({ 
        type: 'scan_result',
        message: `  ✓ Result: ${status.toUpperCase()}${matchedPattern ? ` (${matchedPattern.name})` : ''}\n`,
        result: {
          file: fileName,
          status,
          severity,
          pattern: matchedPattern?.name || null,
          color: statusColor
        }
      })}\n\n`)
    }
    
    // Summary
    res.write(`data: ${JSON.stringify({ 
      type: 'scan_summary',
      message: `\n╔═══════════════════════════════════════════════════════════╗\n`
    })}\n\n`)
    res.write(`data: ${JSON.stringify({ 
      type: 'scan_summary',
      message: `║                    SCAN SUMMARY                          ║\n`
    })}\n\n`)
    res.write(`data: ${JSON.stringify({ 
      type: 'scan_summary',
      message: `╚═══════════════════════════════════════════════════════════╝\n\n`
    })}\n\n`)
    
    res.write(`data: ${JSON.stringify({ 
      type: 'scan_summary',
      message: `[RESULTS]\n`
    })}\n\n`)
    res.write(`data: ${JSON.stringify({ 
      type: 'scan_summary',
      message: `  ✓ Safe files:        ${safeCount}\n`
    })}\n\n`)
    res.write(`data: ${JSON.stringify({ 
      type: 'scan_summary',
      message: `  ✗ Suspicious files:  ${suspiciousCount}\n`
    })}\n\n`)
    res.write(`data: ${JSON.stringify({ 
      type: 'scan_summary',
      message: `  Total scanned:       ${scanResults.length}\n\n`
    })}\n\n`)
    
    if (suspiciousCount > 0) {
      res.write(`data: ${JSON.stringify({ 
        type: 'scan_summary',
        message: `[SUSPICIOUS FILES DETECTED]\n`
      })}\n\n`)
      scanResults.filter(r => r.status === 'suspicious').forEach((result, idx) => {
        res.write(`data: ${JSON.stringify({ 
          type: 'scan_summary',
          message: `  ${idx + 1}. ${result.file} (${result.pattern || 'unknown pattern'}, ${result.severity} risk)\n`
        })}\n\n`)
      })
      res.write(`data: ${JSON.stringify({ 
        type: 'scan_summary',
        message: `\n`
      })}\n\n`)
    }
    
    res.write(`data: ${JSON.stringify({ 
      type: 'end', 
      code: 0,
      results: scanResults,
      message: '\nScan completed successfully\n'
    })}\n\n`)
    
    res.end()
  } catch (error) {
    console.error('Scan error:', error)
    res.write(`data: ${JSON.stringify({ 
      type: 'error', 
      message: `Scan error: ${error.message}\n`
    })}\n\n`)
    res.end()
  }
})

app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', simulatorPath })
})

app.listen(PORT, () => {
  console.log(`Backend server running on http://localhost:${PORT}`)
  console.log(`Simulator path: ${simulatorPath}`)
})

