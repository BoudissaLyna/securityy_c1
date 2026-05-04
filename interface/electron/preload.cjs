// ============================================================
//  DNS TUNNEL SENTINEL — Preload (Context Bridge)
// ============================================================
const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('sentinel', {
  showNotification: (opts) => ipcRenderer.invoke('show-notification', opts),
  getPlatform: () => ipcRenderer.invoke('get-platform'),
  onCaptureStatus: (callback) => {
    ipcRenderer.on('capture-status', (_, data) => callback(data));
  },
});
