const { app, BrowserWindow } = require('electron');
const { spawn } = require('child_process');
const path = require('path');
const express = require('express');
const cors = require('cors');
const fs = require('fs');

let mainWindow;
let backendServer;
let backendPort = 3001;

function getAppPaths() {
  const isDev = !app.isPackaged;
  
  if (isDev) {
    return {
      simulatorPath: path.join(__dirname, '..', process.platform === 'win32' ? 'simulator.exe' : 'simulator'),
      workingDir: path.join(__dirname, '..'),
      frontendUrl: 'http://localhost:5173',
      outputDir: path.join(__dirname, '..', 'output')
    };
  } else {
    const resourcesPath = process.resourcesPath;
    return {
      simulatorPath: path.join(resourcesPath, 'bin', process.platform === 'win32' ? 'simulator.exe' : 'simulator'),
      workingDir: path.join(resourcesPath, 'bin'),
      frontendUrl: `file://${path.join(__dirname, 'renderer', 'index.html')}`,
      outputDir: path.join(resourcesPath, 'bin', 'output')
    };
  }
}

async function startBackendServer() {
  return new Promise((resolve, reject) => {
    const expressApp = express();
    
    expressApp.use(cors());
    expressApp.use(express.json());

    const paths = getAppPaths();
    const isDev = !app.isPackaged;

    // Ensure output directory exists
    if (!fs.existsSync(paths.outputDir)) {
      fs.mkdirSync(paths.outputDir, { recursive: true });
    }

    // Serve static files in production
    if (!isDev) {
      expressApp.use(express.static(path.join(__dirname, 'renderer')));
    }

    // Health check endpoint
    expressApp.get('/api/health', (req, res) => {
      res.json({ 
        status: 'ok', 
        simulatorPath: paths.simulatorPath,
        simulatorExists: fs.existsSync(paths.simulatorPath),
        workingDir: paths.workingDir
      });
    });

    // Graph file endpoint
    expressApp.get('/api/graph/:filename', (req, res) => {
      const filename = req.params.filename;
      
      if (!filename.match(/^[a-zA-Z0-9_\-\.]+\.json$/)) {
        return res.status(400).json({ error: 'Invalid filename' });
      }
      
      const filePath = path.join(paths.outputDir, filename);
      
      if (!fs.existsSync(filePath)) {
        return res.status(404).json({ error: 'File not found' });
      }
      
      try {
        const data = fs.readFileSync(filePath, 'utf8');
        res.json(JSON.parse(data));
      } catch (error) {
        res.status(500).json({ error: 'Failed to read file' });
      }
    });

    // Run simulator endpoint
    expressApp.post('/api/run-simulator', async (req, res) => {
      res.setHeader('Content-Type', 'text/event-stream');
      res.setHeader('Cache-Control', 'no-cache');
      res.setHeader('Connection', 'keep-alive');
      res.setHeader('Access-Control-Allow-Origin', '*');
      res.setHeader('X-Accel-Buffering', 'no');

      res.write(`data: ${JSON.stringify({ type: 'start', message: 'Starting simulator...\n' })}\n\n`);
      if (res.flushHeaders) res.flushHeaders();

      const keepAliveInterval = setInterval(() => {
        try {
          res.write(`: keepalive\n\n`);
        } catch (e) {
          clearInterval(keepAliveInterval);
        }
      }, 30000);

      try {
        if (!fs.existsSync(paths.simulatorPath)) {
          throw new Error(`Simulator not found at: ${paths.simulatorPath}`);
        }

        const isWindows = process.platform === 'win32';
        const simulator = isWindows
          ? spawn(`"${paths.simulatorPath}"`, [], {
              cwd: paths.workingDir,
              stdio: ['ignore', 'pipe', 'pipe'],
              shell: true
            })
          : spawn(paths.simulatorPath, [], {
              cwd: paths.workingDir,
              stdio: ['ignore', 'pipe', 'pipe'],
              shell: false
            });

        if (simulator.stdout) {
          simulator.stdout.setEncoding('utf8');
          simulator.stdout.on('data', (data) => {
            try {
              res.write(`data: ${JSON.stringify({ type: 'stdout', message: data })}\n\n`);
            } catch (e) {}
          });
        }

        if (simulator.stderr) {
          simulator.stderr.setEncoding('utf8');
          simulator.stderr.on('data', (data) => {
            try {
              res.write(`data: ${JSON.stringify({ type: 'stderr', message: data })}\n\n`);
            } catch (e) {}
          });
        }

        simulator.on('error', (error) => {
          clearInterval(keepAliveInterval);
          res.write(`data: ${JSON.stringify({ type: 'error', message: `Error: ${error.message}\n` })}\n\n`);
          res.end();
        });

        const timeout = setTimeout(() => {
          if (!simulator.killed) {
            simulator.kill();
            res.write(`data: ${JSON.stringify({ type: 'error', message: '\nProcess timeout\n' })}\n\n`);
            res.end();
          }
        }, 120000);

        simulator.on('close', (code, signal) => {
          clearTimeout(timeout);
          clearInterval(keepAliveInterval);
          try {
            res.write(`data: ${JSON.stringify({ type: 'end', code, signal, message: `\nProcess exited with code ${code}\n` })}\n\n`);
            res.end();
          } catch (e) {}
        });

        res.on('close', () => {
          clearInterval(keepAliveInterval);
          if (simulator && !simulator.killed) {
            setTimeout(() => {
              try {
                simulator.kill('SIGTERM');
              } catch (e) {}
            }, 2000);
          }
        });
      } catch (error) {
        res.write(`data: ${JSON.stringify({ type: 'error', message: `Failed: ${error.message}\n` })}\n\n`);
        res.end();
      }
    });

    // Scan endpoint
    expressApp.post('/api/scan', async (req, res) => {
      res.setHeader('Content-Type', 'text/event-stream');
      res.setHeader('Cache-Control', 'no-cache');
      res.setHeader('Connection', 'keep-alive');
      res.setHeader('Access-Control-Allow-Origin', '*');
      
      const { files: filePaths } = req.body;
      
      if (!filePaths || filePaths.length === 0) {
        res.write(`data: ${JSON.stringify({ type: 'error', message: 'No files provided\n' })}\n\n`);
        res.end();
        return;
      }

      res.write(`data: ${JSON.stringify({ type: 'start', message: 'Starting C++ DFA scanner...\n' })}\n\n`);
      if (res.flushHeaders) res.flushHeaders();

      const keepAliveInterval = setInterval(() => {
        try {
          res.write(`: keepalive\n\n`);
        } catch (e) {
          clearInterval(keepAliveInterval);
        }
      }, 30000);

      try {
        if (!fs.existsSync(paths.simulatorPath)) {
          throw new Error(`Simulator not found at: ${paths.simulatorPath}`);
        }

        const args = ['--dfa-verbose', ...filePaths.map(p => p.includes(' ') ? `"${p}"` : p)];
        const isWindows = process.platform === 'win32';
        
        const simulator = isWindows
          ? spawn(`"${paths.simulatorPath}"`, args, {
              cwd: paths.workingDir,
              stdio: ['ignore', 'pipe', 'pipe'],
              shell: true
            })
          : spawn(paths.simulatorPath, args, {
              cwd: paths.workingDir,
              stdio: ['ignore', 'pipe', 'pipe'],
              shell: false
            });

        if (simulator.stdout) {
          simulator.stdout.setEncoding('utf8');
          simulator.stdout.on('data', (data) => {
            try {
              res.write(`data: ${JSON.stringify({ type: 'stdout', message: data })}\n\n`);
            } catch (e) {}
          });
        }

        if (simulator.stderr) {
          simulator.stderr.setEncoding('utf8');
          simulator.stderr.on('data', (data) => {
            try {
              res.write(`data: ${JSON.stringify({ type: 'stderr', message: data })}\n\n`);
            } catch (e) {}
          });
        }

        simulator.on('error', (error) => {
          clearInterval(keepAliveInterval);
          res.write(`data: ${JSON.stringify({ type: 'error', message: `Error: ${error.message}\n` })}\n\n`);
          res.end();
        });

        simulator.on('close', (code, signal) => {
          clearInterval(keepAliveInterval);
          try {
            res.write(`data: ${JSON.stringify({ type: 'end', code, signal, message: `\nScan completed with code ${code}\n` })}\n\n`);
            res.end();
          } catch (e) {}
        });

        res.on('close', () => {
          clearInterval(keepAliveInterval);
          if (simulator && !simulator.killed) {
            setTimeout(() => {
              try {
                simulator.kill('SIGTERM');
              } catch (e) {}
            }, 2000);
          }
        });

      } catch (error) {
        res.write(`data: ${JSON.stringify({ type: 'error', message: `Failed: ${error.message}\n` })}\n\n`);
        res.end();
      }
    });

    // Start server with retry logic
    let attempts = 0;
    const maxAttempts = 5;

    const tryListen = () => {
      attempts++;
      const server = expressApp.listen(backendPort, '127.0.0.1', () => {
        backendServer = server;
        resolve();
      });

      server.on('error', (err) => {
        if (err.code === 'EADDRINUSE') {
          backendPort++;
          server.close();
          
          if (attempts < maxAttempts) {
            setTimeout(tryListen, 100);
          } else {
            reject(new Error('Could not find available port'));
          }
        } else {
          reject(err);
        }
      });
    };

    tryListen();
  });
}

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1280,
    height: 800,
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      webSecurity: false,
      allowRunningInsecureContent: true
    },
    icon: path.join(__dirname, 'icon.png')
  });

  const paths = getAppPaths();

  if (!app.isPackaged) {
    mainWindow.loadURL(paths.frontendUrl);
    mainWindow.webContents.openDevTools();
  } else {
    setTimeout(() => {
      mainWindow.loadFile(path.join(__dirname, 'renderer', 'index.html'));
      
      mainWindow.webContents.on('did-finish-load', () => {
        mainWindow.webContents.executeJavaScript(`
          const originalFetch = window.fetch;
          window.fetch = function(url, options) {
            if (typeof url === 'string' && url.startsWith('/api/')) {
              url = 'http://localhost:${backendPort}' + url;
            }
            return originalFetch(url, options);
          };
        `);
      });
    }, 2000);
  }

  mainWindow.on('closed', () => {
    mainWindow = null;
  });
}

app.whenReady().then(async () => {
  try {
    await startBackendServer();
    createWindow();
    
    app.on('activate', () => {
      if (BrowserWindow.getAllWindows().length === 0) {
        createWindow();
      }
    });
  } catch (error) {
    console.error('Failed to start backend server:', error);
    app.quit();
  }
});

app.on('window-all-closed', () => {
  if (backendServer) {
    backendServer.close();
  }
  app.quit();
});