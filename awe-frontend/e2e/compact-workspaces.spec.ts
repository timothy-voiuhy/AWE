import { devices, expect, test } from '@playwright/test'

test('compact workspaces keep secondary actions available', async ({ page }) => {
  const username = process.env.E2E_USERNAME
  const password = process.env.E2E_PASSWORD
  if (!username || !password) throw new Error('Set E2E_USERNAME and E2E_PASSWORD in .env.e2e.local')

  await page.goto('/projects')
  await page.getByLabel('Username').fill(username)
  await page.locator('input[autocomplete="current-password"]').fill(password)
  await page.getByRole('button', { name: 'Sign in' }).click()
  await expect(page.getByRole('heading', { name: 'Start an engagement' })).toBeVisible()
  const projects = await page.request.get('/api/v1/projects')
  const projectId = (await projects.json())[0]?.id as string
  expect(projectId).toBeTruthy()

  await page.goto(`/projects/${projectId}/browser`)
  await expect(page.getByRole('heading', { name: 'Browser', exact: true })).not.toBeVisible()
  await expect(page.locator('.browser-toolbar .page-options')).toHaveCount(1)
  await page.getByLabel('Browser options').click()
  await expect(page.locator('.page-options-panel').getByRole('button', { name: 'New session' })).toBeVisible()

  await page.goto(`/projects/${projectId}/pipeline`)
  await expect(page.getByRole('heading', { name: 'Pipeline', exact: true })).not.toBeVisible()
  await expect(page.locator('.pipeline-commandbar .page-options')).toHaveCount(1)
  await page.getByLabel('Pipeline options').click()
  await expect(page.getByRole('link', { name: 'View results' })).toBeVisible()

  await page.goto(`/projects/${projectId}/ai`)
  await expect(page.getByRole('heading', { name: 'AWE Intelligence' })).not.toBeVisible()
  await expect(page.locator('.ai-sidebar > header .page-options')).toHaveCount(1)
  await page.getByLabel('AI chat options').click()
  await expect(page.locator('.page-options-panel').getByRole('button', { name: 'New chat' })).toBeVisible()

  await page.goto('/database')
  await expect(page.getByRole('heading', { name: 'Database', exact: true })).not.toBeVisible()
  await expect(page.locator('.database-metrics .page-options')).toHaveCount(1)
  await page.getByLabel('Database options').click()
  await expect(page.getByRole('button', { name: 'Refresh' })).toBeVisible()

  await page.goto(`/projects/${projectId}/history`)
  await expect(page.getByRole('button', { name: /Scope:/ })).toHaveCount(0)
  await page.getByLabel('History options').click()
  await expect(page.getByLabel('History options')).toHaveCSS('background-color', 'rgba(0, 0, 0, 0)')
  await expect(page.getByRole('button', { name: 'Show all requests' })).toBeVisible()
  await page.getByRole('button', { name: 'Show filters' }).click()
  await expect(page.getByPlaceholder('Search URL, headers, or body…')).toBeVisible()

  await page.goto(`/projects/${projectId}/intercept`)
  await expect(page.locator('.intercept-toolbar')).toHaveCount(0)
  await expect(page.locator('.intercept-queue > header').getByRole('button', { name: 'Enable intercept' })).toBeVisible()
  await page.getByLabel('Intercept options').click()
  await page.getByRole('button', { name: 'Configure host patterns' }).click()
  const patternDialog = page.getByRole('dialog', { name: 'Host patterns' })
  await expect(patternDialog).toBeVisible()
  await patternDialog.getByRole('button', { name: 'Close host patterns' }).click()
  await expect(patternDialog).not.toBeVisible()

  await page.goto(`/projects/${projectId}/sitemap`)
  await page.getByLabel('Site map options').click()
  await expect(page.getByRole('button', { name: 'Sync to Results' })).toBeVisible()

  await page.goto(`/projects/${projectId}/jwt`)
  await page.getByLabel('JWT options').click()
  await expect(page.getByRole('button', { name: 'Copy token' })).toBeVisible()

  await page.goto(`/projects/${projectId}/graphql`)
  await page.getByLabel('Query templates').click()
  await page.getByRole('button', { name: 'Probe', exact: true }).click()
  await expect(page.locator('.graphql-editor textarea')).toHaveValue('{ __schema { queryType { name } } }')

  await page.goto(`/projects/${projectId}/network/evidence`)
  await expect(page.locator('main .page-options')).toHaveCount(1)
  await page.getByLabel('Evidence options').click()
  await expect(page.getByRole('button', { name: 'Refresh' })).toBeVisible()
  await expect(page.getByRole('link', { name: 'Transform logs' })).toBeVisible()

  await page.goto(`/projects/${projectId}/network/logs`)
  await expect(page.locator('main .page-options')).toHaveCount(1)
  await page.getByLabel('Transform log options').click()
  await expect(page.getByRole('button', { name: 'Refresh' })).toBeVisible()
  await expect(page.locator('.page-options-panel').getByRole('link', { name: 'Graph tools' })).toBeVisible()

  await page.goto(`/projects/${projectId}/docker`)
  await expect(page.locator('.docker-tabbar .page-options')).toHaveCount(1)
  await page.getByRole('tab', { name: 'Images' }).click()
  await page.getByLabel('Docker options').click()
  await expect(page.getByRole('button', { name: 'Build all local' })).toBeVisible()
  await page.goto(`/projects/${projectId}/terminal`)
  await expect(page.locator('.terminal-profile-picker > header .page-options')).toHaveCount(1)
  await page.getByLabel('Terminal options').click()
  await expect(page.locator('.page-options-panel').getByRole('link', { name: 'Manage profiles' })).toBeVisible()
})

test('vault collection actions open a note composer dialog', async ({ page }) => {
  const username = process.env.E2E_USERNAME
  const password = process.env.E2E_PASSWORD
  if (!username || !password) throw new Error('Set E2E_USERNAME and E2E_PASSWORD in .env.e2e.local')

  await page.goto('/projects')
  await page.getByLabel('Username').fill(username)
  await page.locator('input[autocomplete="current-password"]').fill(password)
  await page.getByRole('button', { name: 'Sign in' }).click()
  await expect(page.getByRole('heading', { name: 'Start an engagement' })).toBeVisible()
  await page.route('**/api/v1/vault/categories', route => route.fulfill({ json: [{ id: 'test-collection', name: 'Research', accent: '#89b4fa' }] }))
  let savedNote = ''
  await page.route('**/api/v1/vault/categories/test-collection/items', async route => {
    if (route.request().method() === 'POST') {
      savedNote = (route.request().postDataJSON() as { text: string }).text
      await route.fulfill({ json: { id: 'saved-note', type: 'note', title: 'Test note', text: savedNote, lang: 'txt' } })
    } else await route.fulfill({ json: [] })
  })

  await page.goto('/vault')
  await expect(page.getByRole('heading', { name: 'Research' })).toBeVisible()
  await page.getByLabel('Vault collection options').click()
  await page.getByRole('button', { name: 'Add note' }).click()
  const dialog = page.locator('dialog.vault-composer-dialog')
  await expect(dialog).toBeVisible()
  await expect(dialog.getByPlaceholder('Write or paste your note here…')).toBeVisible()
  await dialog.getByRole('button', { name: 'Cancel' }).click()
  await expect(dialog).not.toBeVisible()
  await page.getByLabel('Vault collection options').click()
  await page.getByRole('button', { name: 'Add note' }).click()
  await dialog.getByPlaceholder('Write or paste your note here…').fill('The dialog saved this note.')
  await dialog.getByRole('button', { name: 'Save note' }).click()
  await expect(dialog).not.toBeVisible()
  expect(savedNote).toBe('The dialog saved this note.')
})

test('secondary workspace pages start at their working controls', async ({ page }) => {
  const username = process.env.E2E_USERNAME
  const password = process.env.E2E_PASSWORD
  if (!username || !password) throw new Error('Set E2E_USERNAME and E2E_PASSWORD in .env.e2e.local')

  await page.goto('/projects')
  await page.getByLabel('Username').fill(username)
  await page.locator('input[autocomplete="current-password"]').fill(password)
  await page.getByRole('button', { name: 'Sign in' }).click()
  await expect(page.getByRole('heading', { name: 'Start an engagement' })).toBeVisible()
  const projects = await page.request.get('/api/v1/projects')
  const projectId = (await projects.json())[0]?.id as string
  expect(projectId).toBeTruthy()

  for (const viewport of [{ width: 1440, height: 900 }, { width: 390, height: 844 }]) {
    await page.setViewportSize(viewport)
    for (const route of ['history', 'sitemap', 'reports', 'decoder', 'comparer', 'jwt', 'graphql', 'settings', 'network/docs']) {
      await page.goto(`/projects/${projectId}/${route}`)
      await expect(page.locator('main > .page-header h1')).not.toBeVisible()
      await expect(page.locator('main')).toBeVisible()
    }
  }
})

test('page options share the first control row on narrow desktop', async ({ page }) => {
  const username = process.env.E2E_USERNAME
  const password = process.env.E2E_PASSWORD
  if (!username || !password) throw new Error('Set E2E_USERNAME and E2E_PASSWORD in .env.e2e.local')

  await page.setViewportSize({ width: 390, height: 844 })
  await page.goto('/projects')
  await page.getByLabel('Username').fill(username)
  await page.locator('input[autocomplete="current-password"]').fill(password)
  await page.getByRole('button', { name: 'Sign in' }).click()
  await expect(page.getByRole('heading', { name: 'Start an engagement' })).toBeVisible()
  const projectId = (await (await page.request.get('/api/v1/projects')).json())[0]?.id as string
  expect(projectId).toBeTruthy()
  await expect(page.getByRole('button', { name: 'Open navigation sidebar' })).toBeVisible()

  for (const [route, row] of [
    ['browser', '.browser-toolbar > select'],
    ['pipeline', '.pipeline-commandbar > button:first-child'],
    ['ai', '.ai-sidebar > header'],
    ['results', '.results-toolbar > select'],
    ['network/evidence', '.evidence-toolbar > div:first-child'],
    ['network/logs', '.network-log-summary > div:first-child'],
    ['network/tools', '.graph-tool-catalog > header'],
    ['network/transforms', '.transform-catalog > header'],
    ['terminal', '.terminal-profile-picker > header'],
    ['docker', '.docker-tabs'],
  ]) {
    await page.goto(`/projects/${projectId}/${route}`)
    await expect(page.locator('main .page-options')).toHaveCount(1)
    await expect(page.locator(row)).toBeVisible()
    const offset = await page.evaluate(selector => {
      const menu = document.querySelector('main .page-options')!.getBoundingClientRect()
      const control = document.querySelector(selector)!.getBoundingClientRect()
      return Math.abs((menu.top + menu.bottom) / 2 - (control.top + control.bottom) / 2)
    }, row)
    expect(offset, route).toBeLessThanOrEqual(24)
    expect(await page.locator('main').evaluate(element => element.scrollWidth - element.clientWidth), route).toBeLessThanOrEqual(1)
  }
})

test('touch mobile uses the edge swipe zone without a top navigation button', async ({ browser }) => {
  const username = process.env.E2E_USERNAME
  const password = process.env.E2E_PASSWORD
  if (!username || !password) throw new Error('Set E2E_USERNAME and E2E_PASSWORD in .env.e2e.local')

  const context = await browser.newContext({ ...devices['Pixel 5'] })
  const page = await context.newPage()
  try {
    await page.goto('/projects')
    await page.getByLabel('Username').fill(username)
    await page.locator('input[autocomplete="current-password"]').fill(password)
    await page.getByRole('button', { name: 'Sign in' }).click()
    await expect(page.getByRole('heading', { name: 'Start an engagement' })).toBeVisible()

    await expect(page.getByRole('button', { name: 'Open navigation sidebar' })).not.toBeVisible()
    await expect(page.locator('.sidebar-swipe-zone')).toBeVisible()
    expect(await page.locator('main').evaluate(element => parseFloat(getComputedStyle(element).paddingTop))).toBeLessThanOrEqual(10)
  } finally {
    await context.close()
  }
})
