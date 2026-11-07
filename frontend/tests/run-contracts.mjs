import { createServer } from 'vite';
const server = await createServer({ server: { middlewareMode: true }, appType: 'custom', optimizeDeps: { noDiscovery: true, include: [] } });
try { (await server.ssrLoadModule('/tests/contracts.jsx')).checkContracts(); }
finally { await server.close(); }
