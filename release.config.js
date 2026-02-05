/**
 * Semantic Release Configuration
 *
 * This configuration handles synchronized versioning across all SDKs:
 * - Node.js (@darkstrata/credential-check)
 * - Python (darkstrata-credential-check)
 * - Rust (darkstrata-credential-check)
 */

module.exports = {
  branches: ['main'],
  plugins: [
    // Analyze commits to determine version bump
    ['@semantic-release/commit-analyzer', {
      preset: 'angular',
      releaseRules: [
        { type: 'feat', release: 'minor' },
        { type: 'fix', release: 'patch' },
        { type: 'perf', release: 'patch' },
        { type: 'refactor', release: 'patch' },
        { type: 'docs', release: false },
        { type: 'style', release: false },
        { type: 'chore', release: false },
        { breaking: true, release: 'major' },
      ],
    }],

    // Generate release notes
    '@semantic-release/release-notes-generator',

    // Generate/update CHANGELOG.md
    ['@semantic-release/changelog', {
      changelogFile: 'CHANGELOG.md',
    }],

    // Update version in all SDK package files
    ['@semantic-release/exec', {
      prepareCmd: 'node scripts/update-versions.js ${nextRelease.version}',
    }],

    // Commit the version changes
    ['@semantic-release/git', {
      assets: [
        'CHANGELOG.md',
        'sdks/node/package.json',
        'sdks/python/pyproject.toml',
        'sdks/rust/Cargo.toml',
        'sdks/rust/Cargo.lock',
        'sdks/csharp/src/DarkStrata.CredentialCheck/DarkStrata.CredentialCheck.csproj',
      ],
      message: 'chore(release): ${nextRelease.version} [skip ci]\n\n${nextRelease.notes}',
    }],

    // Create GitHub release (this triggers the publish workflows)
    '@semantic-release/github',
  ],
};
