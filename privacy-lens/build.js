import * as esbuild from 'esbuild';

const isWatch = process.argv.includes('--watch');

const buildOptions = [
  {
    entryPoints: ['fingerprint/main-world.js'],
    bundle: true,
    format: 'iife',
    outfile: 'dist/main-world.bundle.js',
    sourcemap: true,
    target: ['chrome111']
  },
  {
    entryPoints: ['content/content-bridge.js'],
    bundle: true,
    format: 'iife',
    outfile: 'dist/content-bridge.bundle.js',
    sourcemap: true,
    target: ['chrome111']
  },
  {
    entryPoints: ['background.js'],
    bundle: true,
    format: 'iife',
    outfile: 'dist/background.bundle.js',
    sourcemap: true,
    target: ['chrome111']
  }
];

async function buildAll() {
  try {
    for (const opt of buildOptions) {
      if (isWatch) {
        const ctx = await esbuild.context(opt);
        await ctx.watch();
        console.log(`Watching ${opt.entryPoints[0]} -> ${opt.outfile}`);
      } else {
        await esbuild.build(opt);
        console.log(`Built ${opt.entryPoints[0]} -> ${opt.outfile}`);
      }
    }
  } catch (err) {
    console.error('Build failed:', err);
    process.exit(1);
  }
}

buildAll();
