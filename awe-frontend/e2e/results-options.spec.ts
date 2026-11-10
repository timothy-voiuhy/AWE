import { expect, test } from '@playwright/test'

test('results actions work from the options menu and import opens a dialog', async ({ page }) => {
  const username = process.env.E2E_USERNAME
  const password = process.env.E2E_PASSWORD
  if (!username || !password) throw new Error('Set E2E_USERNAME and E2E_PASSWORD in .env.e2e.local')

  await page.goto('/projects')
  await page.getByLabel('Username').fill(username)
  await page.locator('input[autocomplete="current-password"]').fill(password)
  await page.getByRole('button', { name: 'Sign in' }).click()
  await expect(page.getByRole('heading', { name: 'Start an engagement' })).toBeVisible()
  const projects = await page.request.get('/api/v1/projects')
  expect(projects.ok()).toBeTruthy()
  const projectId = (await projects.json())[0]?.id
  expect(projectId).toBeTruthy()

  await page.route(`**/api/v1/projects/${projectId}/results`, route => route.fulfill({ json: [{
    id: 'result-1', session_id: 'session-1', tool_run_id: 'run-1', category: 'subdomain',
    result_key: 'example.test', data: { domain: 'example.test' }, sources: ['subfinder'], created_at: new Date().toISOString(),
  }] }))
  await page.route(`**/api/v1/projects/${projectId}/results/import-subdomains`, route => route.fulfill({ json: {
    session_id: 'session-1', imported: 1, duplicates: 0, graph_entities: 1, evidence_id: 'evidence-1', values: ['example.test'],
  } }))

  await page.goto(`/projects/${projectId}/results`)
  await expect(page.getByText('example.test').first()).toBeVisible()
  await expect(page.getByLabel('Search results')).toBeVisible()
  await expect(page.getByLabel('Subdomain file')).not.toBeVisible()

  await page.getByLabel('Results options').click()
  const downloadPromise = page.waitForEvent('download')
  await page.getByRole('button', { name: 'Export CSV' }).click()
  expect((await downloadPromise).suggestedFilename()).toBe('awe-subdomain-results.csv')

  await page.getByLabel('Results options').click()
  await page.getByRole('button', { name: 'Import subdomains' }).click()
  const dialog = page.getByRole('dialog', { name: 'Subdomains' })
  await expect(dialog).toBeVisible()
  await dialog.getByLabel('Subdomain file').setInputFiles({ name: 'hosts.txt', mimeType: 'text/plain', buffer: Buffer.from('example.test\n') })
  await expect(dialog.getByText(/Imported 1 subdomains/)).toBeVisible()
  await dialog.getByRole('button', { name: 'Close import dialog' }).click()
  await expect(dialog).not.toBeVisible()
})

test('scrolling tabbed results leaves categories in place', async ({ page }) => {
  const username = process.env.E2E_USERNAME
  const password = process.env.E2E_PASSWORD
  if (!username || !password) throw new Error('Set E2E_USERNAME and E2E_PASSWORD in .env.e2e.local')

  await page.goto('/projects')
  await page.getByLabel('Username').fill(username)
  await page.locator('input[autocomplete="current-password"]').fill(password)
  await page.getByRole('button', { name: 'Sign in' }).click()
  await expect(page.getByRole('heading', { name: 'Start an engagement' })).toBeVisible()
  const projects = await page.request.get('/api/v1/projects')
  const projectId = (await projects.json())[0]?.id
  expect(projectId).toBeTruthy()

  await page.route(`**/api/v1/projects/${projectId}/results`, route => route.fulfill({ json: Array.from({ length: 80 }, (_, index) => ({
    id: `result-${index}`, session_id: 'session-1', tool_run_id: 'run-1', category: 'subdomain',
    result_key: `host-${index}.example.test`, data: { domain: `host-${index}.example.test` },
    sources: ['subfinder'], created_at: new Date().toISOString(),
  })) }))

  for (const viewport of [{ width: 1440, height: 900 }, { width: 390, height: 844 }]) {
    await page.setViewportSize(viewport)
    await page.goto(`/projects/${projectId}/results`)
    const table = page.locator('.result-data-table')
    await expect(table.locator('tbody tr')).toHaveCount(80)
    expect((await page.locator('.result-source-tabs').boundingBox())?.height).toBeGreaterThan(30)
    const categories = page.locator('.result-categories')
    const before = await categories.boundingBox()
    const pageScroll = await page.evaluate(() => window.scrollY)
    await table.hover()
    await page.mouse.wheel(0, 500)
    await expect.poll(() => table.evaluate(element => element.scrollTop)).toBeGreaterThan(0)
    const after = await categories.boundingBox()
    expect(Math.abs((after?.y ?? 0) - (before?.y ?? 0))).toBeLessThan(2)
    expect(await page.evaluate(() => window.scrollY)).toBe(pageScroll)
  }
})
