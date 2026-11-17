// Test fixture: an Electron main process with the usual mistakes. Never run.
const { app, BrowserWindow, ipcMain, shell } = require('electron');
const path = require('path');

function createWindow() {
  const win = new BrowserWindow({
    width: 900,
    height: 600,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      sandbox: false
    }
  });
  win.loadFile('index.html');
  win.webContents.on('will-navigate', (event, url) => {
    if (!url.startsWith('file:')) event.preventDefault();
  });
}

ipcMain.handle('notes:list', () => []);
ipcMain.handle('notes:save', (_event, note) => note);
ipcMain.on('link:open', (_event, url) => {
  shell.openExternal(url);
});

app.whenReady().then(createWindow);
