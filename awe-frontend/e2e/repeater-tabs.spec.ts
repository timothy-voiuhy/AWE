import { expect, test } from '@playwright/test'

test('repeater creates tabs from the tab strip menu and context menu', async ({ page }) => {
  const username = process.env.E2E_USERNAME
  const password = process.env.E2E_PASSWORD
  if (!username || !password) throw new Error('Set E2E_USERNAME and E2E_PASSWORD in .env.e2e.local')

  await page.goto('/projects')
  await page.getByLabel('Username').fill(username)
  await page.locator('input[autocomplete="current-password"]').fill(password)
  await page.getByRole('button', { name: 'Sign in' }).click()
  await expect(page.getByRole('heading', { name: 'Operations dashboard' })).toBeVisible()
  const projects = await page.request.get('/api/v1/projects')
  const projectId = (await projects.json())[0]?.id
  expect(projectId).toBeTruthy()

  await page.goto(`/projects/${projectId}/repeater`)
  await expect(page.getByRole('heading', { name: 'Repeater' })).toHaveCount(0)
  await expect(page.getByText('Manual testing')).toHaveCount(0)
  const tabs = page.locator('.repeater-tabs > button')
  await expect(tabs).toHaveCount(1)

  await page.getByLabel('Tab options').click()
  await page.getByRole('button', { name: 'New tab' }).click()
  await expect(tabs).toHaveCount(2)
  await expect(tabs.nth(1)).toHaveClass(/selected/)

  await tabs.nth(1).click({ button: 'right' })
  await expect(page.getByRole('button', { name: 'New tab' })).toBeVisible()
  await page.getByRole('button', { name: 'New tab' }).click()
  await expect(tabs).toHaveCount(3)
  await expect(page.getByText('Request', { exact: true })).toBeVisible()

  await page.getByLabel('Tab options').click()
  await expect(page.getByRole('button', { name: 'Duplicate tab' })).toBeVisible()
  await expect(page.getByRole('button', { name: 'Send to Intruder' })).toBeVisible()
  await expect(page.getByRole('button', { name: 'Copy request' })).toBeVisible()
  await page.getByLabel('Tab options').click()

  await page.route(`**/api/v1/projects/${projectId}/repeater/send`, route => route.fulfill({ json: {
    status_code: 200, reason: 'OK', headers: { 'content-type': 'text/plain' },
    body: Array.from({ length: 100 }, (_, index) => `line ${index}`).join('\n'), elapsed_ms: 7, body_truncated: false,
  } }))
  await page.getByPlaceholder('https://target.example/api').fill('https://example.test/path')
  await page.getByRole('button', { name: 'Send request' }).click()
  await expect(page.getByText('200 OK · 7 ms')).toBeVisible()
  const response = page.locator('.response-pane .http-code')
  await expect(response).toContainText('line 99')
  expect(await response.evaluate(element => element.scrollHeight > element.clientHeight)).toBeTruthy()
  expect(await page.locator('.repeater-workbench').evaluate(element => element.clientHeight)).toBeLessThanOrEqual(560)
  await page.locator('.repeater-pane').first().getByRole('button', { name: 'Raw' }).click()
  await expect(page.locator('.raw-http-editor')).toBeVisible()
  await page.locator('.response-pane').getByRole('button', { name: 'Render' }).click()
  await expect(page.getByText('Rendering is available for HTML responses.')).toBeVisible()

  await page.setViewportSize({ width: 390, height: 844 })
  await expect(page.getByText('Response', { exact: true })).toBeVisible()
  expect(await page.locator('main').evaluate(element => element.scrollWidth - element.clientWidth)).toBeLessThanOrEqual(1)
})
