import { createServer } from 'node:http';

const pages = new Map([
  ['/', '<main><h1>Accessibility Regression example</h1><p>A small local page used to exercise the comparison workflow.</p><a href="/pricing">View pricing</a></main>'],
  ['/pricing', '<main><h1>Pricing</h1><p>This page is served by the deterministic example fixture.</p><a href="/">Back home</a></main>'],
]);

const server = createServer((request, response) => {
  const pathname = new URL(request.url ?? '/', 'http://127.0.0.1').pathname;
  const page = pages.get(pathname);
  if (!page) {
    response.writeHead(404, { 'content-type': 'text/plain; charset=utf-8' });
    response.end('Not found');
    return;
  }
  response.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
  response.end(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>${pathname === '/' ? 'Example' : 'Pricing'}</title></head><body>${page}</body></html>`);
});

const port = Number(process.env.PORT ?? 3000);
server.listen(port, '0.0.0.0');
