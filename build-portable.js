const fs = require('fs-extra');
const path = require('path');

const distDir = path.join(__dirname, 'release', 'portable');
const electronDir = path.join(__dirname, 'node_modules', 'electron', 'dist');

console.log('Building portable app...\n');

// Clean dist folder
if (fs.existsSync(distDir)) {
  console.log('Cleaning old build...');
  fs.removeSync(distDir);
}

// Copy Electron binaries
console.log('Copying Electron...');
fs.copySync(electronDir, distDir);

// Create resources/app folder
const appDir = path.join(distDir, 'resources', 'app');
fs.ensureDirSync(appDir);

// Copy main files
console.log('Copying app files...');
fs.copySync(path.join(__dirname, 'electron'), path.join(appDir, 'electron'));
fs.copySync(path.join(__dirname, 'package.json'), path.join(appDir, 'package.json'));

// Copy dependencies
console.log('Copying dependencies...');
const nodeModulesDir = path.join(appDir, 'node_modules');
const packageJson = require('./package.json');
const allDeps = { ...packageJson.dependencies };

function copyModuleWithDeps(moduleName, copied = new Set()) {
  if (copied.has(moduleName)) return;
  
  const srcPath = path.join(__dirname, 'node_modules', moduleName);
  if (!fs.existsSync(srcPath)) return;
  
  const destPath = path.join(nodeModulesDir, moduleName);
  fs.copySync(srcPath, destPath);
  copied.add(moduleName);
  
  const modulePackageJson = path.join(srcPath, 'package.json');
  if (fs.existsSync(modulePackageJson)) {
    try {
      const modPkg = require(modulePackageJson);
      if (modPkg.dependencies) {
        for (const dep of Object.keys(modPkg.dependencies)) {
          copyModuleWithDeps(dep, copied);
        }
      }
    } catch (e) {
      // Ignore unreadable package.json
    }
  }
}

const copiedModules = new Set();
for (const dep of Object.keys(allDeps)) {
  copyModuleWithDeps(dep, copiedModules);
}

// Copy frontend build
console.log('Copying frontend...');
fs.copySync(
  path.join(__dirname, 'display', 'dist'),
  path.join(appDir, 'electron', 'renderer')
);

// Create output directory
console.log('Creating output directory...');
const outputDir = path.join(distDir, 'resources', 'bin', 'output');
fs.ensureDirSync(outputDir);

// Copy resources
console.log('Copying resources...');
const resourcesDir = path.join(distDir, 'resources');

if (fs.existsSync(path.join(__dirname, 'simulator.exe'))) {
  fs.ensureDirSync(path.join(resourcesDir, 'bin'));
  fs.copySync(
    path.join(__dirname, 'simulator.exe'),
    path.join(resourcesDir, 'bin', 'simulator.exe')
  );
}

if (fs.existsSync(path.join(__dirname, 'archive'))) {
  fs.copySync(
    path.join(__dirname, 'archive'),
    path.join(resourcesDir, 'bin', 'archive')
  );
}

// Rename electron.exe
const electronExe = path.join(distDir, 'electron.exe');
const appExe = path.join(distDir, 'Suspicious Filename Detector.exe');
if (fs.existsSync(electronExe)) {
  fs.renameSync(electronExe, appExe);
  console.log('\nBuild complete!');
  console.log('Location:', distDir);
} else {
  console.error('Error: electron.exe not found');
}