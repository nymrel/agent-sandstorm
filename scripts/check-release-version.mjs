/** Ensure one release tag matches both package ecosystems before publishing. */

import assert from 'node:assert/strict';
import fs from 'node:fs';

const releaseTag = process.env.RELEASE_TAG;
assert.match(releaseTag ?? '', /^v\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/, 'RELEASE_TAG must be a semantic version tag');

const packageJson = JSON.parse(fs.readFileSync('package.json', 'utf8'));
const pyproject = fs.readFileSync('pyproject.toml', 'utf8');
const pythonVersion = pyproject.match(/^version\s*=\s*"([^"]+)"/m)?.[1];

assert.equal(packageJson.version, pythonVersion, 'Node and Python package versions must match');
assert.equal(releaseTag, `v${packageJson.version}`, 'Release tag must match package versions');

console.log(`Release version contract verified (${releaseTag}).`);
