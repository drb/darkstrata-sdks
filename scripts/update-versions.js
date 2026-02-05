#!/usr/bin/env node

/**
 * Update version across all SDK package files.
 *
 * Usage: node scripts/update-versions.js <version>
 *
 * Updates:
 * - sdks/node/package.json
 * - sdks/python/pyproject.toml
 * - sdks/rust/Cargo.toml
 * - sdks/rust/Cargo.lock
 */

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

const version = process.argv[2];

if (!version) {
  console.error('Usage: node scripts/update-versions.js <version>');
  process.exit(1);
}

// Validate semver format
if (!/^\d+\.\d+\.\d+(-[\w.]+)?$/.test(version)) {
  console.error(`Invalid version format: ${version}`);
  process.exit(1);
}

const rootDir = path.resolve(__dirname, '..');

console.log(`Updating all SDKs to version ${version}...`);

// Update Node.js package.json
const nodePackagePath = path.join(rootDir, 'sdks', 'node', 'package.json');
const nodePackage = JSON.parse(fs.readFileSync(nodePackagePath, 'utf8'));
nodePackage.version = version;
fs.writeFileSync(nodePackagePath, JSON.stringify(nodePackage, null, 2) + '\n');
console.log(`  Updated sdks/node/package.json`);

// Update Python pyproject.toml
const pythonPath = path.join(rootDir, 'sdks', 'python', 'pyproject.toml');
let pythonContent = fs.readFileSync(pythonPath, 'utf8');
pythonContent = pythonContent.replace(
  /^version\s*=\s*"[^"]+"/m,
  `version = "${version}"`
);
// Also update SDK_VERSION constant if it exists
pythonContent = pythonContent.replace(
  /SDK_VERSION\s*=\s*"[^"]+"/,
  `SDK_VERSION = "${version}"`
);
fs.writeFileSync(pythonPath, pythonContent);
console.log(`  Updated sdks/python/pyproject.toml`);

// Update Python constants.py SDK_VERSION
const pythonConstantsPath = path.join(rootDir, 'sdks', 'python', 'src', 'darkstrata_credential_check', 'constants.py');
if (fs.existsSync(pythonConstantsPath)) {
  let constantsContent = fs.readFileSync(pythonConstantsPath, 'utf8');
  constantsContent = constantsContent.replace(
    /SDK_VERSION\s*=\s*"[^"]+"/,
    `SDK_VERSION = "${version}"`
  );
  fs.writeFileSync(pythonConstantsPath, constantsContent);
  console.log(`  Updated sdks/python/src/darkstrata_credential_check/constants.py`);
}

// Update Rust Cargo.toml
const rustPath = path.join(rootDir, 'sdks', 'rust', 'Cargo.toml');
let rustContent = fs.readFileSync(rustPath, 'utf8');
// Update the version in the [package] section (first occurrence)
rustContent = rustContent.replace(
  /^version\s*=\s*"[^"]+"/m,
  `version = "${version}"`
);
fs.writeFileSync(rustPath, rustContent);
console.log(`  Updated sdks/rust/Cargo.toml`);

// Update Rust Cargo.lock by running cargo check
try {
  console.log(`  Updating sdks/rust/Cargo.lock...`);
  execSync('cargo check', {
    cwd: path.join(rootDir, 'sdks', 'rust'),
    stdio: 'inherit',
  });
  console.log(`  Updated sdks/rust/Cargo.lock`);
} catch (error) {
  console.warn(`  Warning: Failed to update Cargo.lock: ${error.message}`);
}

// Update C# .csproj
const csharpPath = path.join(rootDir, 'sdks', 'csharp', 'src', 'DarkStrata.CredentialCheck', 'DarkStrata.CredentialCheck.csproj');
if (fs.existsSync(csharpPath)) {
  let csharpContent = fs.readFileSync(csharpPath, 'utf8');
  csharpContent = csharpContent.replace(
    /<Version>[^<]+<\/Version>/,
    `<Version>${version}</Version>`
  );
  fs.writeFileSync(csharpPath, csharpContent);
  console.log(`  Updated sdks/csharp/src/DarkStrata.CredentialCheck/DarkStrata.CredentialCheck.csproj`);
}

// Update C# Constants.cs SDK_VERSION
const csharpConstantsPath = path.join(rootDir, 'sdks', 'csharp', 'src', 'DarkStrata.CredentialCheck', 'Constants.cs');
if (fs.existsSync(csharpConstantsPath)) {
  let constantsContent = fs.readFileSync(csharpConstantsPath, 'utf8');
  constantsContent = constantsContent.replace(
    /SdkVersion\s*=\s*"[^"]+"/,
    `SdkVersion = "${version}"`
  );
  fs.writeFileSync(csharpConstantsPath, constantsContent);
  console.log(`  Updated sdks/csharp/src/DarkStrata.CredentialCheck/Constants.cs`);
}

console.log(`\nAll SDKs updated to version ${version}`);
