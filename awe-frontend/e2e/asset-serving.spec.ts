import { expect, test } from '@playwright/test'

test('the app shell references real bundles and missing assets do not return HTML', async ({ request }) => {
  const shell = await request.get('/')
  expect(shell.status()).toBe(200)
  expect(shell.headers()['cache-control']).toContain('no-store')

  const html = await shell.text()
  const script = html.match(/src="(\/assets\/[^\"]+\.js)"/)?.[1]
  const stylesheet = html.match(/href="(\/assets\/[^\"]+\.css)"/)?.[1]
  expect(script).toBeTruthy()
  expect(stylesheet).toBeTruthy()

  const js = await request.get(script!)
  const css = await request.get(stylesheet!)
  expect(js.status()).toBe(200)
  expect(css.status()).toBe(200)
  expect(js.headers()['content-type']).toContain('javascript')
  expect(css.headers()['content-type']).toContain('text/css')

  const missing = await request.get('/assets/index-missing-build.css')
  expect(missing.status()).toBe(404)
})
