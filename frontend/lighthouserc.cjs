const preset = process.env.LHCI_PRESET === 'desktop' ? 'desktop' : 'mobile';

module.exports = {
  ci: {
    collect: {
      numberOfRuns: 3,
      startServerCommand: 'npm run preview -- --host 127.0.0.1 --port 4173 --strictPort',
      startServerReadyPattern: 'http://127.0.0.1:4173',
      startServerReadyTimeout: 30000,
      url: ['http://127.0.0.1:4173/login'],
      settings: {
        preset,
        chromeFlags: '--no-sandbox --disable-dev-shm-usage',
      },
    },
    assert: {
      assertions: {
        'categories:performance': ['warn', { minScore: 0.70 }],
        'categories:accessibility': ['warn', { minScore: 0.90 }],
        'categories:best-practices': ['warn', { minScore: 0.90 }],
        'first-contentful-paint': ['warn', { maxNumericValue: 2500 }],
        'largest-contentful-paint': ['warn', { maxNumericValue: 4000 }],
        'cumulative-layout-shift': ['warn', { maxNumericValue: 0.10 }],
        'total-blocking-time': ['warn', { maxNumericValue: 400 }],
        'speed-index': ['warn', { maxNumericValue: 4500 }],
      },
    },
    upload: {
      target: 'filesystem',
      outputDir: '.lighthouseci',
    },
  },
};
