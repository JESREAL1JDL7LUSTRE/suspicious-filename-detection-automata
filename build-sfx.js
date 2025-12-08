const fs = require('fs-extra');
const path = require('path');
const { execSync } = require('child_process');

console.log('Building Self-Extracting Portable EXE...\n');

const releaseDir = path.join(__dirname, 'release');
const portableDir = path.join(releaseDir, 'portable');
const sfxDir = path.join(releaseDir, 'sfx');
const sevenZipPath = 'C:\\Program Files\\7-Zip\\7z.exe';

// Check 7-Zip installation
if (!fs.existsSync(sevenZipPath)) {
  console.error('Error: 7-Zip not found at:', sevenZipPath);
  console.error('Please install 7-Zip or update the path in build-sfx.js');
  process.exit(1);
}

// Check portable build
if (!fs.existsSync(portableDir)) {
  console.error('Error: Portable build not found. Run "node build-portable.js" first.');
  process.exit(1);
}

fs.ensureDirSync(sfxDir);

const archivePath = path.join(sfxDir, 'app.7z');
const possibleSfxNames = ['7zSD.sfx', '7zS.sfx', '7z.sfx'];
let sfxModulePath = null;

for (const name of possibleSfxNames) {
  const testPath = path.join(path.dirname(sevenZipPath), name);
  if (fs.existsSync(testPath)) {
    sfxModulePath = testPath;
    console.log('Found SFX module:', name);
    break;
  }
}

if (!sfxModulePath) {
  console.error('Error: No SFX module found. Expected one of:', possibleSfxNames);
  console.error('Location checked:', path.dirname(sevenZipPath));
  console.error('\nDownload from: https://www.7-zip.org/a/7z2501-extra.7z');
  console.error('Extract 7zSD.sfx to your 7-Zip installation folder.');
  process.exit(1);
}

const configPath = path.join(sfxDir, 'config.txt');
const outputExePath = path.join(sfxDir, 'Suspicious Filename Detector (INSTALLER).exe');

// Create 7z archive
console.log('Creating 7z archive...');
try {
  execSync(`"${sevenZipPath}" a -t7z -mx9 "${archivePath}" "${portableDir}\\*"`, {
    stdio: 'inherit'
  });
} catch (err) {
  console.error('Error: Failed to create archive:', err.message);
  process.exit(1);
}

// Create SFX config
console.log('Creating SFX config...');
const config = `;!@Install@!UTF-8!
Title="Suspicious Filename Detector"
BeginPrompt="Extract and run Suspicious Filename Detector?\\n\\nFiles will be extracted to a new folder."
ExtractDialogText="Extracting files, please wait..."
ExtractPathText="Suspicious Filename Detector"
RunProgram="portable\\Suspicious Filename Detector.exe"
;!@InstallEnd@!`;

fs.writeFileSync(configPath, config, 'utf8');

// Build self-extracting executable
console.log('Building self-extracting executable...');
try {
  fs.copyFileSync(sfxModulePath, outputExePath);
  fs.appendFileSync(outputExePath, fs.readFileSync(configPath));
  fs.appendFileSync(outputExePath, fs.readFileSync(archivePath));
} catch (err) {
  console.error('Error: Failed to build SFX:', err.message);
  process.exit(1);
}

// Cleanup
console.log('Cleaning up...');
fs.removeSync(archivePath);
fs.removeSync(configPath);

console.log('\nBuild complete!');
console.log('Location:', outputExePath);
console.log('Size:', (fs.statSync(outputExePath).size / 1024 / 1024).toFixed(2), 'MB');