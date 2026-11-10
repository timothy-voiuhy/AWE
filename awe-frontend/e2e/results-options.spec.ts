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
    result_key: 'example.test', data: { domain: 'example.test' }, sources: ['subfinder'], created_at: new Date().toISOString(), reviewed: false,
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

test('each result can be opened, reviewed, and removed from its actions dialog', async ({ page }) => {
  const username = process.env.E2E_USERNAME
  const password = process.env.E2E_PASSWORD
  if (!username || !password) throw new Error('Set E2E_USERNAME and E2E_PASSWORD in .env.e2e.local')

  await page.goto('/projects')
  await page.getByLabel('Username').fill(username)
  await page.locator('input[autocomplete="current-password"]').fill(password)
  await page.getByRole('button', { name: 'Sign in' }).click()
  await expect(page.getByRole('heading', { name: 'Start an engagement' })).toBeVisible()
  const projectId = (await (await page.request.get('/api/v1/projects')).json())[0]?.id
  expect(projectId).toBeTruthy()

  let reviewed = false
  let removed = false
  await page.route(`**/api/v1/projects/${projectId}/results`, async route => {
    if (route.request().method() === 'DELETE') {
      removed = true
      await route.fulfill({ json: { category: 'http', result_key: 'https://example.test/path', deleted_count: 1 } })
      return
    }
    await route.fulfill({ json: removed ? [] : [{
      id: 'result-1', session_id: 'session-1', tool_run_id: 'run-1', category: 'http',
      result_key: 'https://example.test/path', data: { url: 'https://example.test/path', status_code: 200 },
      sources: ['httpx'], created_at: new Date().toISOString(), reviewed,
    }] })
  })
  await page.route(`**/api/v1/projects/${projectId}/results/reviewed`, async route => {
    reviewed = (await route.request().postDataJSON()).reviewed
    await route.fulfill({ json: { category: 'http', result_key: 'https://example.test/path', reviewed } })
  })
  await page.route(`**/api/v1/projects/${projectId}/browser/sessions`, async route => {
    if (route.request().method() === 'POST') {
      await route.fulfill({ status: 201, json: { id: 'browser-1', project_id: projectId, url: 'about:blank', title: 'New tab', viewport_width: 1280, viewport_height: 720, created_at: new Date().toISOString(), updated_at: new Date().toISOString() } })
      return
    }
    await route.fulfill({ json: [{ id: 'browser-1', project_id: projectId, url: 'https://example.test/path', title: 'Example', viewport_width: 1280, viewport_height: 720, created_at: new Date().toISOString(), updated_at: new Date().toISOString() }] })
  })
  await page.route(`**/api/v1/projects/${projectId}/browser/sessions/browser-1/navigate`, route => route.fulfill({ json: { id: 'browser-1', project_id: projectId, url: 'https://example.test/path', title: 'Example', viewport_width: 1280, viewport_height: 720, created_at: new Date().toISOString(), updated_at: new Date().toISOString() } }))

  await page.goto(`/projects/${projectId}/results`)
  await page.getByLabel('Actions for https://example.test/path').click()
  const dialog = page.getByRole('dialog', { name: 'Result actions' })
  await expect(dialog).toBeVisible()
  await expect(dialog.getByRole('link', { name: /Open in this browser/ })).toHaveAttribute('href', 'https://example.test/path')
  await expect(dialog.getByRole('link', { name: /Open in this browser/ })).toHaveAttribute('target', '_blank')

  await dialog.getByRole('button', { name: 'Mark as reviewed' }).click()
  await expect(dialog.getByRole('button', { name: 'Mark as not reviewed' })).toBeVisible()
  await expect(page.locator('.result-row-actions > span')).toHaveAttribute('title', 'Reviewed')

  await dialog.getByRole('button', { name: 'Open in AWE Browser' }).click()
  await expect(page).toHaveURL(new RegExp(`/projects/${projectId}/browser\\?session=browser-1$`))

  await page.goto(`/projects/${projectId}/results`)
  await page.getByLabel('Actions for https://example.test/path').click()
  page.once('dialog', confirmation => confirmation.accept())
  await page.getByRole('dialog', { name: 'Result actions' }).getByRole('button', { name: 'Remove result' }).click()
  await expect(page.getByText('No results match this view.')).toBeVisible()
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
    const workbench = await page.locator('.results-browser').boundingBox()
    expect(Math.abs((workbench?.y ?? 0) + (workbench?.height ?? 0) - viewport.height)).toBeLessThan(2)
    const categories = page.locator('.result-categories')
    if (viewport.width > 850) {
      const rail = await categories.boundingBox()
      expect(Math.abs((rail?.y ?? 0) + (rail?.height ?? 0) - viewport.height)).toBeLessThan(2)
    }
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
