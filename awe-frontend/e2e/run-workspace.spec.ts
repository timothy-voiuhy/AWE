import { expect, test, type Page } from '@playwright/test'

async function login(page: Page) {
  await page.goto('/projects')
  await page.getByLabel('Username').fill(process.env.E2E_USERNAME!)
  await page.locator('input[autocomplete="current-password"]').fill(process.env.E2E_PASSWORD!)
  await page.getByRole('button', { name: 'Sign in' }).click()
  await expect(page.getByLabel('Dashboard options')).toBeVisible()
  return (await (await page.request.get('/api/v1/projects')).json())[0].id as string
}

test('legacy tool links open the unified transforms workspace and shared actions', async ({ page }) => {
  const projectId = await login(page)
  for (const path of ['network/tools', 'graph-tools']) {
    await page.goto(`/projects/${projectId}/${path}`)
    await expect(page).toHaveURL(new RegExp(`/projects/${projectId}/network/transforms\\?view=tools$`))
    await expect(page.getByRole('button', { name: /^Tools \d/ })).toHaveAttribute('aria-pressed', 'true')
    await expect(page.locator('.graph-tool-catalog')).toBeVisible()
  }
  await expect(page.locator('.sidebar').getByRole('link', { name: 'Graph Tools', exact: true })).toHaveCount(0)
  await page.getByRole('button', { name: /^Transforms \d/ }).click()
  await expect(page.locator('.transform-catalog')).toBeVisible()
  await page.getByLabel('Transform options').click()
  for (const name of ['Create custom graph tool', 'Register PoC', 'Create composite transform', 'View running transforms']) {
    await expect(page.getByRole('button', { name, exact: true })).toBeVisible()
  }
  await expect(page.getByRole('link', { name: 'Tool runs', exact: true }).last()).toBeVisible()
  await expect(page.locator('main .page-options')).toHaveCount(1)
})

test('run history filters, output inspection, and evidence reset work on desktop and mobile', async ({ page }) => {
  const projectId = await login(page)
  const fixtures = [
    { id: 'review_complete', kind: 'tool.fixture', tool_key: 'fixture', status: 'completed', created_at: '2026-11-11T08:00:00Z', message: 'Report ready for review', exit_code: 0, last_sequence: 2, output_channels: ['logs', 'artifacts'], execution_kind: 'batch' },
    { id: 'review_active', kind: 'tool.fixture', tool_key: 'fixture', status: 'running', created_at: '2026-11-11T07:00:00Z', message: 'Collecting output', output_channels: ['logs'], execution_kind: 'interactive' },
    { id: 'review_failed', kind: 'poc.build.fixture', status: 'failed', created_at: '2026-11-11T06:00:00Z', message: 'Build interrupted', exit_code: 1 },
  ]
  await page.route('**/api/v1/docker/tools', route => route.fulfill({ json: [{ key: 'fixture', display_name: 'Research console' }] }))
  await page.route(new RegExp(`/api/v1/projects/${projectId}/runs(?:/[^?]*)?(?:\\?.*)?$`), async route => {
    const url = new URL(route.request().url())
    const [id, resource] = url.pathname.split('/runs/')[1]?.split('/') || []
    if (!id) return route.fulfill({ json: fixtures })
    if (resource === 'artifacts') return route.fulfill({ json: id === 'review_complete' ? [{ id: 'report', name: 'report.txt', size: 2048, mime_type: 'text/plain', sha256: 'abc123' }] : [] })
    if (resource === 'events') {
      const after = Number(url.searchParams.get('after') || 0)
      const sequence = after + 1
      return route.fulfill({ json: { events: [{ sequence, timestamp: '2026-11-11T08:00:00Z', stream: 'stdout', stage: '', data: `${id} output ${sequence}` }], cursor: sequence, truncated: false } })
    }
    return route.fulfill({ json: fixtures.find(item => item.id === id) })
  })

  await page.setViewportSize({ width: 1440, height: 1000 })
  await page.goto(`/projects/${projectId}/runs`)
  const history = page.getByRole('navigation', { name: 'Tool run selection' })
  await expect(history.getByRole('link')).toHaveCount(3)
  await page.getByRole('button', { name: 'active 1', exact: true }).click()
  await expect(history.getByRole('link')).toHaveCount(1)
  await expect(history).toContainText('Collecting output')
  await page.getByRole('button', { name: 'All runs 3', exact: true }).click()
  await page.getByLabel('Search tool runs').fill('interrupted')
  await expect(history.getByRole('link')).toHaveCount(1)
  await expect(history).toContainText('Build interrupted')
  await page.getByLabel('Search tool runs').fill('no matching output')
  await expect(history).toContainText('No matching runs')
  await page.getByRole('button', { name: 'Clear filters' }).click()
  await history.locator('a[href$="/review_complete"]').click()
  await expect(page.locator('.run-detail-heading h1')).toHaveText('Research console')
  await page.getByRole('tab', { name: 'Logs', exact: true }).click()
  await expect(page.locator('.runtime-log')).toContainText('review_complete output 1')
  await page.getByLabel('Search run output').fill('review_complete')
  await page.getByRole('button', { name: 'Load next output' }).click()
  await expect(page.locator('.runtime-log')).toContainText('review_complete output 2')
  await page.getByRole('tab', { name: /^Artifacts/ }).click()
  await expect(page.getByRole('link', { name: 'report.txt', exact: true })).toBeVisible()
  await expect(page.locator('.runtime-artifact')).toContainText('2.0 KB')
  await page.getByRole('button', { name: 'Use as evidence' }).click()
  await page.getByLabel('Researcher interpretation').fill('Draft for the first run')
  await expect(page.getByLabel('Evidence title')).toHaveValue('report.txt')
  await history.locator('a[href$="/review_active"]').click()
  await expect(page.getByRole('tab', { name: 'Overview', exact: true })).toHaveAttribute('aria-selected', 'true')
  await page.getByRole('tab', { name: 'Evidence', exact: true }).click()
  await expect(page.getByLabel('Evidence title')).toHaveValue('Tool output')
  await expect(page.getByLabel('Researcher interpretation')).toHaveValue('')
  await expect(page.getByLabel('First event')).toBeVisible()
  await page.getByRole('tab', { name: 'Logs', exact: true }).click()
  await expect(page.getByLabel('Search run output')).toHaveValue('')
  await expect(page.locator('.runtime-log')).toContainText('review_active output 1')
  await expect(page.locator('.runtime-log')).not.toContainText('review_complete')
  await page.screenshot({ path: '/tmp/awe-tool-runs-desktop.png', fullPage: true })
  await page.setViewportSize({ width: 390, height: 844 })
  await expect(page.locator('.runtime-detail')).toBeVisible()
  await expect(page.getByRole('tab', { name: 'Logs', exact: true })).toBeVisible()
  expect(await page.locator('main').evaluate(element => element.scrollWidth - element.clientWidth)).toBeLessThanOrEqual(1)
  await page.screenshot({ path: '/tmp/awe-tool-runs-mobile.png', fullPage: true })
})
