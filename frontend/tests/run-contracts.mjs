import { createServer } from 'vite';
const server = await createServer({ server: { middlewareMode: true }, appType: 'custom' });
try { (await server.ssrLoadModule('/tests/contracts.jsx')).checkContracts(); }
finally { await server.close(); }
