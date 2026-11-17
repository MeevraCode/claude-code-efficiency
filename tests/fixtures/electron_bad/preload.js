// Test fixture: the page chooses the channel, so it can call every handler.
const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('api', {
  invoke: (channel, ...args) => ipcRenderer.invoke(channel, ...args),
  openLink: (url) => ipcRenderer.send('link:open', url)
});
