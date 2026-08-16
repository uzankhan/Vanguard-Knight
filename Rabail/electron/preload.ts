const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('electronAPI', {
  toggleGesture: (status: boolean) => ipcRenderer.send('toggle-gesture', status),
  sendGesture: (data: { x: number; y: number; action: string }) => 
    ipcRenderer.send('gesture-move', data),
  minimizeWindow: () => ipcRenderer.send('window-minimize'),
  maximizeWindow: () => ipcRenderer.send('window-maximize'),
  closeWindow: () => ipcRenderer.send('window-close')
});