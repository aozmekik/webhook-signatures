/** `npm run build && GITHUB_WEBHOOK_SECRET=... node examples/express/server.ts` */
import { createApp } from './app.ts';

const secret = process.env['GITHUB_WEBHOOK_SECRET'];
if (secret === undefined || secret === '') {
  throw new Error('Set GITHUB_WEBHOOK_SECRET');
}
createApp(secret).listen(3000, () => {
  console.log('Express example listening on http://localhost:3000/webhooks/github');
});
