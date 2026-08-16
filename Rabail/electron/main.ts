import { app, BrowserWindow, ipcMain, screen } from 'electron';
import path from 'path';
import { exec } from 'child_process';

let mainWindow: BrowserWindow | null = null;
let isGestureMode = false;

// ----- Mouse Control Functions -----
async function moveMouse(x: number, y: number) {
  try {
    const { width, height } = screen.getPrimaryDisplay().size;
    const targetX = Math.round((x / 100) * width);
    const targetY = Math.round((y / 100) * height);
    exec(`python -c "import pyautogui; pyautogui.moveTo(${targetX}, ${targetY})"`);
  } catch (error) {
    console.error('Move mouse error:', error);
  }
}

async function clickMouse() {
  try {
    exec(`python -c "import pyautogui; pyautogui.click()"`);
  } catch (error) {
    console.error('Click mouse error:', error);
  }
}

async function mouseDown() {
  try {
    exec(`python -c "import pyautogui; pyautogui.mouseDown()"`);
  } catch (error) {
    console.error('Mouse down error:', error);
  }
}

async function mouseUp() {
  try {
    exec(`python -c "import pyautogui; pyautogui.mouseUp()"`);
  } catch (error) {
    console.error('Mouse up error:', error);
  }
}

function minimizeAllWindows() {
  try {
    exec('powershell -command "(New-Object -ComObject Shell.Application).MinimizeAll()"');
  } catch (error) {
    console.error('Minimize all error:', error);
  }
}

function showDesktop() {
  try {
    exec('powershell -command "(New-Object -ComObject Shell.Application).ToggleDesktop()"');
  } catch (error) {
    console.error('Show desktop error:', error);
  }
}

function closeWindow() {
  try {
    exec('powershell -command "Add-Type -TypeDefinition \'using System;using System.Runtime.InteropServices;public class User32{[DllImport(\"user32.dll\")]public static extern IntPtr GetForegroundWindow();[DllImport(\"user32.dll\")]public static extern int SendMessage(IntPtr hWnd, int Msg, int wParam, int lParam);}\'; $hwnd = [User32]::GetForegroundWindow(); [User32]::SendMessage($hwnd, 0x0010, 0, 0)"');
  } catch (error) {
    console.error('Close window error:', error);
  }
}

function zoomIn() {
  try {
    exec('powershell -command "$wshell = New-Object -ComObject wscript.shell; $wshell.SendKeys(\'^+\')"');
  } catch (error) {
    console.error('Zoom in error:', error);
  }
}

function zoomOut() {
  try {
    exec('powershell -command "$wshell = New-Object -ComObject wscript.shell; $wshell.SendKeys(\'^-\')"');
  } catch (error) {
    console.error('Zoom out error:', error);
  }
}

function nextTab() {
  try {
    exec('powershell -command "$wshell = New-Object -ComObject wscript.shell; $wshell.SendKeys(\'^{TAB}\')"');
  } catch (error) {
    console.error('Next tab error:', error);
  }
}

function prevTab() {
  try {
    exec('powershell -command "$wshell = New-Object -ComObject wscript.shell; $wshell.SendKeys(\'^+{TAB}\')"');
  } catch (error) {
    console.error('Previous tab error:', error);
  }
}

// ----- IPC Handlers -----
ipcMain.on('window-minimize', () => {
  if (mainWindow) mainWindow.minimize();
});

ipcMain.on('window-maximize', () => {
  if (mainWindow) {
    if (mainWindow.isMaximized()) {
      mainWindow.unmaximize();
    } else {
      mainWindow.maximize();
    }
  }
});

ipcMain.on('window-close', () => {
  if (mainWindow) mainWindow.close();
});

ipcMain.on('toggle-gesture', (_, status: boolean) => {
  isGestureMode = status;
  console.log(`🖐️ Gesture mode: ${status ? 'ACTIVE' : 'PAUSED'}`);
});

ipcMain.on('gesture-move', async (_, { x, y, action }: { x: number; y: number; action: string }) => {
  if (!isGestureMode) return;

  try {
    console.log(`🎯 Action: ${action}, x: ${x.toFixed(1)}, y: ${y.toFixed(1)}`);
    
    switch (action) {
      case 'move':
        await moveMouse(x, y);
        break;
      case 'click':
        await moveMouse(x, y);
        await clickMouse();
        break;
      case 'drag':
        await moveMouse(x, y);
        break;
      case 'minimizeAll':
        minimizeAllWindows();
        break;
      case 'showDesktop':
        showDesktop();
        break;
      case 'closeWindow':
        closeWindow();
        break;
      case 'zoomIn':
        zoomIn();
        break;
      case 'zoomOut':
        zoomOut();
        break;
      case 'nextTab':
        nextTab();
        break;
      case 'prevTab':
        prevTab();
        break;
      default:
        await moveMouse(x, y);
    }
  } catch (error) {
    console.error('Gesture move error:', error);
  }
});

// ----- Create Window -----
function createWindow() {
  const indexPath = path.join(__dirname, '..', 'dist', 'index.html');
  console.log('📁 Loading index from:', indexPath);

  mainWindow = new BrowserWindow({
    width: 1200,
    height: 800,
    frame: true,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
    },
  });

  mainWindow.loadFile(indexPath).catch((err) => {
    console.error('❌ Failed to load index.html:', err);
  });

  // DevTools - comment out for production
  // mainWindow.webContents.openDevTools();

  // Even when minimized, gestures continue
  mainWindow.on('minimize', () => {
    console.log('🔄 App minimized, gestures still active');
  });

  mainWindow.on('closed', () => {
    mainWindow = null;
  });
}

// ----- App Lifecycle -----
app.whenReady().then(() => {
  createWindow();

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      createWindow();
    }
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit();
  }
});