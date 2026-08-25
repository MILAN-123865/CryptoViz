#!/usr/bin/env node
/**
 * generate-sw-precache.mjs
 *
 * Scans the Next.js app/ directory for all route segments (page.tsx / page.js),
 * resolves dynamic parameters to concrete values from their data sources,
 * and writes:
 *   - public/sw.js          (service worker with PRECACHE_URLS)
 *   - lib/offline/precacheRoutes.ts  (TypeScript export for client-side use)
 *
 * Usage:
 *   node scripts/generate-sw-precache.mjs
 *   npm run generate:sw
 */

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT = path.resolve(__dirname, '..');

// ---------- Configuration ----------

/** Static assets in /public that should always be precached */
const DEFAULT_STATIC_ASSETS = ['/globals.css', '/icon.svg', '/theme-init.js'];

/**
 * Maps dynamic segment names → { sourceFile, extractPattern }
 * extractPattern is a regex applied per-line to extract IDs from the TS data source.
 */
const DYNAMIC_SEGMENT_SOURCES = {
  '[cipher]': {
    sourceFile: 'lib/cipher/registry.ts',
    // Match top-level cipher id declarations (2-space indented, inside CIPHER_REGISTRY array entries)
    extractIds(content) {
      return extractCipherIds(content);
    },
  },
  '[id]': {
    sourceFile: 'lib/case-studies/data.ts',
    extractIds(content) {
      return extractSimpleIds(content, 'CASE_STUDIES');
    },
  },
  '[pathId]': {
    sourceFile: 'lib/learning-paths/data.ts',
    extractIds(content) {
      return extractSimpleIds(content, 'LEARNING_PATHS');
    },
  },
};

// ---------- ID extraction helpers ----------

/**
 * Extract top-level cipher IDs from the CIPHER_REGISTRY.
 * Cipher entries have their `id` at object-nesting depth 1 inside the array.
 * Option IDs are at depth 2+ and should be excluded.
 */
function extractCipherIds(content) {
  const ids = [];
  const lines = content.split('\n');
  let inRegistry = false;
  let braceDepth = 0;

  for (const line of lines) {
    const trimmed = line.trim();

    if (!inRegistry) {
      if (trimmed.startsWith('export const CIPHER_REGISTRY') || trimmed.includes('CIPHER_REGISTRY:')) {
        inRegistry = true;
      }
      continue;
    }

    // Track brace depth within the registry array
    for (const ch of trimmed) {
      if (ch === '{') braceDepth++;
      if (ch === '}') braceDepth--;
    }

    // Top-level cipher object id is at braceDepth 1 (inside the outer array, inside the cipher object)
    // When we see `id: "xxx"` at depth 1, it's a cipher id
    if (braceDepth === 1 || (braceDepth === 0 && trimmed.includes('id:'))) {
      const match = trimmed.match(/^id:\s*["']([a-zA-Z0-9_-]+)["']/);
      if (match) {
        ids.push(match[1]);
      }
    }
  }

  return ids;
}

/**
 * Extract top-level IDs from a simple array constant (CASE_STUDIES, LEARNING_PATHS).
 * These arrays have objects at depth 1 whose `id` fields we want.
 */
function extractSimpleIds(content, arrayName) {
  const ids = [];
  const lines = content.split('\n');
  let inArray = false;
  let braceDepth = 0;

  for (const line of lines) {
    const trimmed = line.trim();

    if (!inArray) {
      if (trimmed.includes(arrayName)) {
        inArray = true;
      }
      continue;
    }

    for (const ch of trimmed) {
      if (ch === '{') braceDepth++;
      if (ch === '}') braceDepth--;
    }

    // Depth 1 = inside an array element object
    if (braceDepth === 1) {
      const match = trimmed.match(/^id:\s*['"]([a-zA-Z0-9_-]+)['"]/);
      if (match) {
        ids.push(match[1]);
      }
    }
  }

  return ids;
}

// ---------- Route discovery ----------

/**
 * Recursively discover all page routes from the app/ directory.
 * Returns an array of URL paths (e.g. "/", "/about/", "/visualizer/caesar/").
 */
function discoverRoutes(appDir) {
  const routes = [];

  function walk(dir, routePrefix) {
    const entries = fs.readdirSync(dir, { withFileTypes: true });

    // Check if this directory has a page file
    const hasPage = entries.some(
      (e) => e.isFile() && (e.name === 'page.tsx' || e.name === 'page.js')
    );

    if (hasPage) {
      // Check if routePrefix contains dynamic segments
      const dynamicMatch = routePrefix.match(/\[([^\]]+)\]/);
      if (dynamicMatch) {
        // Resolve dynamic segments
        const resolved = resolveDynamicRoute(routePrefix, appDir);
        routes.push(...resolved);
      } else {
        // Static route - add with trailing slash (except root)
        const url = routePrefix === '' ? '/' : `/${routePrefix}/`;
        routes.push(url);
      }
    }

    // Recurse into subdirectories (skip route groups like (group), api routes, etc.)
    for (const entry of entries) {
      if (!entry.isDirectory()) continue;
      if (entry.name.startsWith('_')) continue; // skip _components, _lib, etc.
      if (entry.name === 'api') continue; // skip API routes
      if (entry.name.startsWith('(') && entry.name.endsWith(')')) {
        // Route group - traverse but don't add to route prefix
        walk(path.join(dir, entry.name), routePrefix);
        continue;
      }

      const nextPrefix = routePrefix ? `${routePrefix}/${entry.name}` : entry.name;
      walk(path.join(dir, entry.name), nextPrefix);
    }
  }

  walk(appDir, '');
  return routes;
}

/**
 * Resolve a route with dynamic segments to concrete URLs.
 * e.g. "visualizer/[cipher]" → ["/visualizer/caesar/", "/visualizer/aes/", ...]
 */
function resolveDynamicRoute(routePrefix, appDir) {
  const segments = routePrefix.split('/');
  const urls = [];

  // Find all dynamic segments
  const dynamicSegments = segments
    .map((seg, i) => ({ seg, index: i }))
    .filter(({ seg }) => seg.startsWith('[') && seg.endsWith(']'));

  if (dynamicSegments.length === 0) return [];

  // For single dynamic segment routes
  if (dynamicSegments.length === 1) {
    const { seg, index } = dynamicSegments[0];
    const source = DYNAMIC_SEGMENT_SOURCES[seg];
    if (!source) {
      // Unknown dynamic segment - skip (won't be statically generated)
      return [];
    }

    const sourceFilePath = path.join(ROOT, source.sourceFile);
    if (!fs.existsSync(sourceFilePath)) {
      console.warn(`Warning: Source file not found for ${seg}: ${sourceFilePath}`);
      return [];
    }

    const content = fs.readFileSync(sourceFilePath, 'utf-8');
    const ids = source.extractIds(content);

    for (const id of ids) {
      const resolved = [...segments];
      resolved[index] = id;
      urls.push(`/${resolved.join('/')}/`);
    }
    return urls;
  }

  // For multi-segment dynamic routes (e.g. [pathId]/[lessonId])
  // These are typically client-side navigated and not statically exported
  // Skip them for precaching
  return [];
}

// ---------- Output generation ----------

/**
 * Generate the full precache URL list.
 * Exported so tests can call it directly.
 */
export function generatePrecacheList() {
  const appDir = path.join(ROOT, 'app');
  if (!fs.existsSync(appDir)) {
    throw new Error(`app/ directory not found at ${appDir}`);
  }

  const routes = discoverRoutes(appDir);
  const allUrls = [...new Set([...routes, ...DEFAULT_STATIC_ASSETS])];

  // Sort for deterministic output
  allUrls.sort((a, b) => a.localeCompare(b));
  return allUrls;
}

/**
 * Generate public/sw.js content
 */
function generateSwJs(urls, timestamp) {
  const cacheVersion = `cryptoviz-v${Date.now()}`;
  const urlsJson = urls.map((u) => `  ${JSON.stringify(u)}`).join(',\n');

  return `/**
 * CryptoViz Service Worker (Auto-Generated Precache)
 * Last Generated: ${timestamp}
 * 
 * NOTE: This file is automatically generated by scripts/generate-sw-precache.mjs during build.
 * To update precached routes manually, run: npm run generate:sw or modify scripts/generate-sw-precache.mjs.
 */

const CACHE_NAME = '${cacheVersion}';
const PRECACHE_URLS = [
${urlsJson}
];

self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_NAME).then(cache => {
      return cache.addAll(PRECACHE_URLS).catch(err => console.warn('Pre-cache item warning:', err));
    }).then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys().then(cacheNames => {
      return Promise.all(
        cacheNames.map(name => {
          if (name !== CACHE_NAME && name.startsWith('cryptoviz-')) {
            return caches.delete(name);
          }
        })
      );
    }).then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', event => {
  if (event.request.method !== 'GET') return;

  event.respondWith(
    caches.match(event.request).then(cachedResponse => {
      if (cachedResponse) {
        return cachedResponse;
      }
      return fetch(event.request)
        .then(networkResponse => {
          if (!networkResponse || networkResponse.status !== 200 || networkResponse.type !== 'basic') {
            return networkResponse;
          }
          const responseToCache = networkResponse.clone();
          caches.open(CACHE_NAME).then(cache => {
            cache.put(event.request, responseToCache);
          });
          return networkResponse;
        })
        .catch(() => {
          if (event.request.mode === 'navigate') {
            return caches.match('/offline/') || caches.match('/offline') || caches.match('/');
          }
        });
    })
  );
});
`;
}

/**
 * Generate lib/offline/precacheRoutes.ts content
 */
function generatePrecacheRoutesTs(urls, timestamp) {
  const urlsJson = urls.map((u) => `  ${JSON.stringify(u)},`).join('\n');

  return `/**
 * Auto-generated precache routes manifest.
 * Last Generated: ${timestamp}
 */
export const PRECACHE_ROUTES: string[] = [
${urlsJson}
];
`;
}

// ---------- Main ----------

function main() {
  const urls = generatePrecacheList();
  const timestamp = new Date().toISOString();

  // Write public/sw.js
  const swPath = path.join(ROOT, 'public', 'sw.js');
  fs.writeFileSync(swPath, generateSwJs(urls, timestamp), 'utf-8');
  console.log(`✅ Generated ${swPath} (${urls.length} URLs)`);

  // Write lib/offline/precacheRoutes.ts
  const routesPath = path.join(ROOT, 'lib', 'offline', 'precacheRoutes.ts');
  fs.mkdirSync(path.dirname(routesPath), { recursive: true });
  fs.writeFileSync(routesPath, generatePrecacheRoutesTs(urls, timestamp), 'utf-8');
  console.log(`✅ Generated ${routesPath} (${urls.length} URLs)`);
}

// Run main only when executed directly (not imported)
// Check if this module is the entry point
const isMain =
  process.argv[1] &&
  (path.resolve(process.argv[1]) === path.resolve(__filename) ||
   path.resolve(process.argv[1]) === path.resolve(__filename).replace(/\.mjs$/, ''));

if (isMain) {
  main();
}
