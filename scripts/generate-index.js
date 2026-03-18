#!/usr/bin/env node
/**
 * Generate index.json for OASIS challenge registry
 * Scans all challenge directories and creates a registry index
 */

import { existsSync, readFileSync, writeFileSync, readdirSync, statSync } from 'fs';
import { join } from 'path';

const REPO_BASE_URL = 'https://raw.githubusercontent.com/KryptSec/oasis-challenges/main';
const GHCR_PREFIX = 'ghcr.io/kryptsec';

function generateIndex() {
  const challengesDir = process.cwd();
  const challenges = [];

  const dirs = readdirSync(challengesDir)
    .filter(name => {
      if (name.startsWith('_') || name.startsWith('.')) return false;
      const path = join(challengesDir, name);
      return statSync(path).isDirectory() && existsSync(join(path, 'challenge.json'));
    });

  for (const dir of dirs) {
    const configPath = join(challengesDir, dir, 'challenge.json');

    try {
      const config = JSON.parse(readFileSync(configPath, 'utf-8'));

      challenges.push({
        id: config.id,
        name: config.name,
        category: config.category,
        difficulty: config.difficulty,
        description: config.description,
        targetImage: `${GHCR_PREFIX}/${config.id}:latest`,
        configUrl: `${REPO_BASE_URL}/${dir}/challenge.json`,
      });
    } catch (error) {
      console.warn(`⚠️  Skipping ${dir}: ${error.message}`);
    }
  }

  const index = {
    version: '1.0.0',
    generated: new Date().toISOString(),
    challenges: challenges.sort((a, b) => a.id.localeCompare(b.id)),
  };

  writeFileSync('index.json', JSON.stringify(index, null, 2) + '\n');
  console.log(`✅ Generated index.json with ${challenges.length} challenges`);
}

generateIndex();
