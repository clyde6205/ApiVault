const { app, BrowserWindow } = require('electron');
function createWindow(){
  const win = new BrowserWindow({width:1280,height:800, titleBarStyle:'hiddenInset', title:'Universal API Vaultâ„¢ v4.2 - Licensed', backgroundColor:'#09090b'});
  win.loadFile('dist/index.html');
}
app.whenReady().then(createWindow);
