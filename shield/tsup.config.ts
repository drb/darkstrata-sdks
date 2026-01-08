import { defineConfig } from 'tsup';

export default defineConfig([
  // ESM and CJS builds for bundlers
  {
    entry: ['src/index.ts'],
    format: ['esm', 'cjs'],
    dts: true,
    clean: true,
    sourcemap: true,
    treeshake: true,
    minify: false,
    splitting: false,
  },
  // Global/IIFE build for <script> tag usage
  {
    entry: ['src/index.ts'],
    format: ['iife'],
    globalName: 'DarkStrataShield',
    outExtension: () => ({ js: '.global.js' }),
    minify: true,
    sourcemap: true,
    treeshake: true,
    platform: 'browser',
  },
]);
