// Test fixture: one page, exact-URL navigation, every handler behind a sender check. Never run.
import { app, BrowserWindow, ipcMain } from 'electron';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

const APP_URL = pathToFileURL(join(__dirname, 'index.html')).href;
let win: BrowserWindow | null = null;

function isAppUrl(url: string): boolean {
  return url === APP_URL;
}

// Every channel goes through this wrapper, so no handler can skip the check.
const handle = (channel: string, listener: (...args: unknown[]) => unknown) =>
  ipcMain.handle(channel, (event, ...args) => {
    const frame = event.senderFrame;
    if (!frame || event.sender !== win?.webContents || !isAppUrl(frame.url)) {
      throw new Error('IPC call refused');
    }
    return listener(...args);
  });

handle('notes:list', () => []);
handle('notes:save', (note) => note);
handle('notes:remove', (id) => id);

function createWindow(): void {
  win = new BrowserWindow({
    width: 900,
    height: 600,
    webPreferences: {
      preload: join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true
    }
  });
  win.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));
  win.webContents.on('will-navigate', (event, url) => {
    if (!isAppUrl(url)) event.preventDefault();
  });
  void win.loadFile(join(__dirname, 'index.html'));
}

void app.whenReady().then(createWindow);
