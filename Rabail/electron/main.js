"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const electron_1 = require("electron");
const path_1 = __importDefault(require("path"));
const child_process_1 = require("child_process");
let mainWindow = null;
let isGestureMode = false;
// ----- Mouse Control Functions -----
async function moveMouse(x, y) {
    try {
        const { width, height } = electron_1.screen.getPrimaryDisplay().size;
        const targetX = Math.round((x / 100) * width);
        const targetY = Math.round((y / 100) * height);
        (0, child_process_1.exec)(`python -c "import pyautogui; pyautogui.moveTo(${targetX}, ${targetY})"`);
    }
    catch (error) {
        console.error('Move mouse error:', error);
    }
}
async function clickMouse() {
    try {
        (0, child_process_1.exec)(`python -c "import pyautogui; pyautogui.click()"`);
    }
    catch (error) {
        console.error('Click mouse error:', error);
    }
}
async function mouseDown() {
    try {
        (0, child_process_1.exec)(`python -c "import pyautogui; pyautogui.mouseDown()"`);
    }
    catch (error) {
        console.error('Mouse down error:', error);
    }
}
async function mouseUp() {
    try {
        (0, child_process_1.exec)(`python -c "import pyautogui; pyautogui.mouseUp()"`);
    }
    catch (error) {
        console.error('Mouse up error:', error);
    }
}
function minimizeAllWindows() {
    try {
        (0, child_process_1.exec)('powershell -command "(New-Object -ComObject Shell.Application).MinimizeAll()"');
    }
    catch (error) {
        console.error('Minimize all error:', error);
    }
}
function showDesktop() {
    try {
        (0, child_process_1.exec)('powershell -command "(New-Object -ComObject Shell.Application).ToggleDesktop()"');
    }
    catch (error) {
        console.error('Show desktop error:', error);
    }
}
function closeWindow() {
    try {
        (0, child_process_1.exec)('powershell -command "Add-Type -TypeDefinition \'using System;using System.Runtime.InteropServices;public class User32{[DllImport(\"user32.dll\")]public static extern IntPtr GetForegroundWindow();[DllImport(\"user32.dll\")]public static extern int SendMessage(IntPtr hWnd, int Msg, int wParam, int lParam);}\'; $hwnd = [User32]::GetForegroundWindow(); [User32]::SendMessage($hwnd, 0x0010, 0, 0)"');
    }
    catch (error) {
        console.error('Close window error:', error);
    }
}
function zoomIn() {
    try {
        (0, child_process_1.exec)('powershell -command "$wshell = New-Object -ComObject wscript.shell; $wshell.SendKeys(\'^+\')"');
    }
    catch (error) {
        console.error('Zoom in error:', error);
    }
}
function zoomOut() {
    try {
        (0, child_process_1.exec)('powershell -command "$wshell = New-Object -ComObject wscript.shell; $wshell.SendKeys(\'^-\')"');
    }
    catch (error) {
        console.error('Zoom out error:', error);
    }
}
function nextTab() {
    try {
        (0, child_process_1.exec)('powershell -command "$wshell = New-Object -ComObject wscript.shell; $wshell.SendKeys(\'^{TAB}\')"');
    }
    catch (error) {
        console.error('Next tab error:', error);
    }
}
function prevTab() {
    try {
        (0, child_process_1.exec)('powershell -command "$wshell = New-Object -ComObject wscript.shell; $wshell.SendKeys(\'^+{TAB}\')"');
    }
    catch (error) {
        console.error('Previous tab error:', error);
    }
}
// ----- IPC Handlers -----
electron_1.ipcMain.on('window-minimize', () => {
    if (mainWindow)
        mainWindow.minimize();
});
electron_1.ipcMain.on('window-maximize', () => {
    if (mainWindow) {
        if (mainWindow.isMaximized()) {
            mainWindow.unmaximize();
        }
        else {
            mainWindow.maximize();
        }
    }
});
electron_1.ipcMain.on('window-close', () => {
    if (mainWindow)
        mainWindow.close();
});
electron_1.ipcMain.on('toggle-gesture', (_, status) => {
    isGestureMode = status;
    console.log(`🖐️ Gesture mode: ${status ? 'ACTIVE' : 'PAUSED'}`);
});
electron_1.ipcMain.on('gesture-move', async (_, { x, y, action }) => {
    if (!isGestureMode)
        return;
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
    }
    catch (error) {
        console.error('Gesture move error:', error);
    }
});
// ----- Create Window -----
function createWindow() {
    const indexPath = path_1.default.join(__dirname, '..', 'dist', 'index.html');
    console.log('📁 Loading index from:', indexPath);
    mainWindow = new electron_1.BrowserWindow({
        width: 1200,
        height: 800,
        frame: true,
        webPreferences: {
            preload: path_1.default.join(__dirname, 'preload.js'),
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
electron_1.app.whenReady().then(() => {
    createWindow();
    electron_1.app.on('activate', () => {
        if (electron_1.BrowserWindow.getAllWindows().length === 0) {
            createWindow();
        }
    });
});
electron_1.app.on('window-all-closed', () => {
    if (process.platform !== 'darwin') {
        electron_1.app.quit();
    }
});
