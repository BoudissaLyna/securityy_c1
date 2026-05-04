// ============================================================
//  DNS TUNNEL SENTINEL — Electron Main Process
// ============================================================
const { app, BrowserWindow, Notification, ipcMain, Tray, Menu } = require('electron');
const path = require('path');
const { spawn } = require('child_process');

let mainWindow = null;
let pythonProcess = null;
let tray = null;

const isDev = !app.isPackaged;

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1440,
    height: 900,
    minWidth: 1100,
    minHeight: 700,
    backgroundColor: '#000000',
    title: 'DNS Tunnel Sentinel',
    icon: path.join(__dirname, '../public/icon.png'),
    webPreferences: {
      preload: path.join(__dirname, 'preload.cjs'),
      contextIsolation: true,
      nodeIntegration: false,
    },
    // Dark HUD aesthetic
    titleBarStyle: 'default',
    darkTheme: true,
    autoHideMenuBar: true,
  });

  // In dev, load from Vite dev server; in production, load built files
  if (isDev) {
    mainWindow.loadURL('http://localhost:5173');
    // Uncomment next line to open DevTools automatically
    // mainWindow.webContents.openDevTools();
  } else {
    mainWindow.loadFile(path.join(__dirname, '../dist/index.html'));
  }

  mainWindow.on('closed', () => {
    mainWindow = null;
  });
}

// ---- Spawn Python capture engine ----
function checkPortInUse(port, callback) {
  const net = require('net');
  const tester = net.createConnection({ port, host: '127.0.0.1' }, () => {
    tester.end();
    callback(true); // port open = engine already running
  });
  tester.on('error', () => callback(false));
}

function startPythonCapture() {
  const pythonScript = path.join(__dirname, '../python/capture_engine.py');
  const pythonCmd = process.platform === 'win32' ? 'python' : 'python3';

  // If port 8765 already taken, skip — external engine is running
  checkPortInUse(8765, (inUse) => {
    if (inUse) {
      console.log('[CAPTURE ENGINE] Port 8765 already in use — external engine detected, skipping spawn.');
      return;
    }

    pythonProcess = spawn(pythonCmd, [pythonScript], {
      stdio: ['ignore', 'pipe', 'pipe'],
    });

    pythonProcess.stdout.on('data', (data) => {
      console.log(`[CAPTURE ENGINE] ${data.toString().trim()}`);
    });

    pythonProcess.stderr.on('data', (data) => {
      console.error(`[CAPTURE ENGINE ERROR] ${data.toString().trim()}`);
    });

    pythonProcess.on('error', (err) => {
      console.error('[CAPTURE ENGINE] Failed to start Python:', err.message);
      console.log('[CAPTURE ENGINE] Falling back to simulation mode in UI.');
    });

    pythonProcess.on('close', (code) => {
      console.log(`[CAPTURE ENGINE] Process exited with code ${code}`);
      pythonProcess = null;
    });
  });
}

function stopPythonCapture() {
  if (pythonProcess) {
    pythonProcess.kill();
    pythonProcess = null;
  }
}

// ---- IPC Handlers ----
ipcMain.handle('show-notification', (event, { title, body, urgency }) => {
  if (Notification.isSupported()) {
    const notif = new Notification({
      title: title || 'DNS Sentinel',
      body: body || '',
      urgency: urgency || 'normal',
      silent: false,
    });
    notif.show();
  }
});

ipcMain.handle('get-platform', () => process.platform);

// ---- App lifecycle ----
app.whenReady().then(() => {
  createWindow();
  startPythonCapture();

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      createWindow();
    }
  });
});

app.on('window-all-closed', () => {
  stopPythonCapture();
  if (process.platform !== 'darwin') {
    app.quit();
  }
});

app.on('before-quit', () => {
  stopPythonCapture();
});
