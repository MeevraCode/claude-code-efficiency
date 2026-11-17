// Test fixture: one named method per channel, nothing generic.
const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('notes', {
  list: () => ipcRenderer.invoke('notes:list'),
  save: (note) => ipcRenderer.invoke('notes:save', note),
  remove: (id) => ipcRenderer.invoke('notes:remove', id)
});
