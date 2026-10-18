/** Cross-validation against the official @shopify/shopify-api library (web-api adapter). */
import '@shopify/shopify-api/adapters/web-api';
import { ApiVersion, LogSeverity, shopifyApi } from '@shopify/shopify-api';
import { describe, expect, it } from 'vitest';
import { verifyShopify } from 'webhook-signatures';
import { signShopify } from 'webhook-signatures/testing';
import { expectCode } from '../support/assertions.js';

const apiSecretKey = 'shpss_interop_client_secret';
const shopify = shopifyApi({
  apiKey: 'interop-api-key',
  apiSecretKey,
  hostName: 'app.example.com',
  apiVersion: ApiVersion.January25,
  isEmbeddedApp: false,
  logger: { level: LogSeverity.Error, log: () => Promise.resolve() },
});
const payload = JSON.stringify({
  id: 820982911946154500,
  email: 'jön@example.com',
  total_price: '10.00',
});

async function shopifyValidates(body: string, hmac: string): Promise<boolean> {
  const rawRequest = new Request('https://app.example.com/webhooks', {
    method: 'POST',
    body,
    headers: {
      'X-Shopify-Hmac-Sha256': hmac,
      'X-Shopify-Topic': 'orders/create',
      'X-Shopify-Shop-Domain': 'example.myshopify.com',
      'X-Shopify-API-Version': ApiVersion.January25,
      'X-Shopify-Webhook-Id': 'b54557e4-bdd9-4b37-8a5f-bf7d70bcd043',
    },
  });
  const result = await shopify.webhooks.validate({ rawBody: body, rawRequest });
  return result.valid;
}

describe('@shopify/shopify-api interop', () => {
  it('shopify.webhooks.validate accepts signShopify output', async () => {
    const hmac = (await signShopify({ payload, secret: apiSecretKey }))['x-shopify-hmac-sha256'];
    expect(await shopifyValidates(payload, hmac)).toBe(true);
  });

  it('both reject a tampered body', async () => {
    const hmac = (await signShopify({ payload, secret: apiSecretKey }))['x-shopify-hmac-sha256'];
    const tampered = payload.replace('10.00', '0.01');
    expect(await shopifyValidates(tampered, hmac)).toBe(false);
    await expectCode(
      verifyShopify({
        payload: tampered,
        headers: { 'x-shopify-hmac-sha256': hmac },
        secret: apiSecretKey,
      }),
      'signature_mismatch',
    );
  });
});
