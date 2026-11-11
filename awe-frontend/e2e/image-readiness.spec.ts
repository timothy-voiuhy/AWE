import { expect, test, type Page } from '@playwright/test'

async function login(page: Page) {
  await page.goto('/projects')
  await page.getByLabel('Username').fill(process.env.E2E_USERNAME!)
  await page.locator('input[autocomplete="current-password"]').fill(process.env.E2E_PASSWORD!)
  await page.getByRole('button', { name: 'Sign in' }).click()
  await expect(page.getByLabel('Dashboard options')).toBeVisible()
  const projectId = (await (await page.request.get('/api/v1/projects')).json())[0].id as string
  const csrf = (await page.context().cookies()).find(cookie => cookie.name === 'awe_csrf')!.value
  return { projectId, headers: { 'X-AWE-CSRF': decodeURIComponent(csrf) } }
}

test('compact image filters count shared references and refresh checked update status', async ({ page }) => {
  const { projectId } = await login(page)
  let checked = false
  const tool = (key: string, image: string, present: boolean, status = 'unchecked') => ({ key, image, display_name: key, category: 'Fixtures', description: '', source: 'hub', image_present: present, update_status: status, update_message: 'Fixture update status', param_specs: [], output_channels: ['logs'] })
  await page.route('**/api/v1/docker/tools', route => route.fulfill({ json: [tool('Installed fixture', 'fixture/current', true, 'current'), tool('Shared fixture', 'fixture/current:latest', true, 'current'), tool('Missing fixture', 'fixture/missing:1', false), tool('Changed fixture', 'fixture/changed:1', true, checked ? 'outdated' : 'unchecked')] }))
  await page.route('**/api/v1/docker/images', route => route.fulfill({ json: [{ id: 'current', tags: ['docker.io/fixture/current:latest'], size_mb: 1 }, { id: 'changed', tags: ['fixture/changed:1'], size_mb: 1 }] }))
  await page.route('**/api/v1/docker/images/check-updates', route => { checked = true; return route.fulfill({ json: [] }) })
  await page.goto(`/projects/${projectId}/docker`)
  await page.getByRole('tab', { name: 'Images', exact: true }).click()
  const filters = page.getByRole('group', { name: 'Filter images' })
  await expect(filters.getByRole('button', { name: 'All 3', exact: true })).toHaveAttribute('aria-pressed', 'true')
  await filters.getByRole('button', { name: 'Installed 2', exact: true }).click()
  await page.locator('.docker-tool-categories').getByRole('button', { name: /Fixtures/ }).click()
  await expect(page.locator('.docker-tool-grid article')).toHaveCount(3)
  await expect(page.getByRole('region', { name: 'Installed tool images' })).toContainText('docker.io/fixture/current:latest')
  await filters.getByRole('button', { name: 'Uninstalled 1', exact: true }).click()
  await expect(page.getByRole('region', { name: 'Installed tool images' })).not.toBeVisible()
  await expect(page.locator('.docker-tool-grid article')).toHaveCount(1)
  await expect(page.locator('.docker-tool-grid')).toContainText('Missing fixture')
  await page.getByRole('button', { name: 'Check updates', exact: true }).click()
  await filters.getByRole('button', { name: 'Outdated 1', exact: true }).click()
  await expect(page.locator('.docker-tool-grid article')).toHaveCount(1)
  await expect(page.locator('.docker-tool-grid')).toContainText('Changed fixture')
  await expect(page.getByRole('region', { name: 'Installed tool images' })).toContainText('fixture/changed:1')
  await expect(page.getByRole('region', { name: 'Installed tool images' })).not.toContainText('fixture/current:1')
  await page.setViewportSize({ width: 390, height: 844 })
  expect(await page.locator('.image-filter-toolbar').evaluate(element => element.scrollWidth - element.clientWidth)).toBeLessThanOrEqual(1)
  await page.screenshot({ path: '/tmp/awe-image-filters-mobile.png', fullPage: true })
})

test('run dialog offers image setup and parser repair and enables execution after recheck', async ({ page }) => {
  const { projectId } = await login(page)
  const now = new Date().toISOString()
  const investigation = { id: 'readiness-investigation', project_id: projectId, name: 'Readiness fixture', created_at: now, updated_at: now, preferences: {} }
  const manifest = { id: 'docker:fixture', tool_key: 'fixture', display_name: 'Readiness fixture', category: 'Fixtures', input_types: ['target'], output_types: ['url'], relationship_types: [], parameters: [], stages: [], mode: 'passive', requires_approval: false }
  let imageReady = false
  let parserReady = false
  let started = false
  await page.route(`**/api/v1/projects/${projectId}/catalog/organization`, route => route.fulfill({ json: { categories: [{ id: 'fixtures', name: 'Fixtures', parent_id: null }], assignments: { 'tool:fixture': 'fixtures' }, defaults: {} } }))
  await page.route(`**/api/v1/projects/${projectId}/investigations`, route => route.fulfill({ json: [investigation] }))
  await page.route(`**/api/v1/projects/${projectId}/investigations/readiness-investigation/graph?*`, route => route.fulfill({ json: { investigation, entities: [{ id: 'target', kind: 'target', label: 'example.invalid', value: 'example.invalid', data: {}, provenance: [] }], relationships: [] } }))
  await page.route(`**/api/v1/projects/${projectId}/transforms/jobs`, route => route.fulfill({ json: [] }))
  await page.route(`**/api/v1/projects/${projectId}/transform-preflight?*`, route => route.fulfill({ json: { ready: imageReady && parserReady, tools: [{ tool_key: 'fixture', image: 'awe/fixture:1', ready: imageReady && parserReady, issues: [...(!imageReady ? [{ code: 'image_missing', message: 'Required image is not installed. Build it before running.', action: 'build' }] : []), ...(!parserReady ? [{ code: 'parser_missing', message: 'Structured output requires a registered parser. Repair parser.py.', action: 'edit' }] : [])] }] } }))
  await page.route('**/api/v1/docker/tools/fixture/image/build', route => { imageReady = true; return route.fulfill({ json: { id: 'image-setup', status: 'queued', kind: 'build', logs: [] } }) })
  await page.route('**/api/v1/docker/operations/image-setup', route => route.fulfill({ json: { id: 'image-setup', status: 'completed', kind: 'build', logs: ['Built fixture image'] } }))
  await page.route(`**/api/v1/projects/${projectId}/transforms`, route => {
    if (route.request().method() === 'GET') return route.fulfill({ json: [manifest] })
    started = true
    return route.fulfill({ status: 409, json: { detail: 'Fixture run reached backend preflight' } })
  })
  await page.goto(`/projects/${projectId}/network/transforms`)
  await page.locator('.transform-catalog').getByRole('button', { name: /Fixtures/ }).click()
  await page.getByRole('button', { name: 'Run', exact: true }).click()
  const dialog = page.getByRole('dialog', { name: 'Run Readiness fixture' })
  const run = dialog.getByRole('button', { name: 'Run with 1 input', exact: true })
  await expect(run).toBeDisabled()
  await expect(dialog.getByRole('link', { name: 'Manage tool definition' })).toBeVisible()
  await dialog.getByRole('button', { name: 'Build image', exact: true }).click()
  await expect(dialog).toContainText('Built fixture image')
  await expect(dialog.getByRole('button', { name: 'Build image', exact: true })).not.toBeVisible()
  await expect(run).toBeDisabled()
  parserReady = true
  await dialog.getByRole('button', { name: 'Recheck', exact: true }).click()
  await expect(run).toBeEnabled()
  await run.click()
  await expect(dialog.getByRole('alert')).toContainText('Fixture run reached backend preflight')
  expect(started).toBe(true)
})

test('real backend preflight blocks direct tool and transform execution with missing images', async ({ page }) => {
  const { projectId, headers } = await login(page)
  const key = `readiness_e2e_${Date.now()}`
  const created = await page.request.post('/api/v1/docker/tools', { headers, data: { key, display_name: 'Missing image readiness fixture', category: 'Fixtures', image: `awe/${key}:missing`, command_template: 'fixture', input_types: ['target'], output_types: [], relationship_types: [], output_channels: ['logs'], parser: '', dockerfile: 'FROM scratch\n' } })
  expect(created.ok(), await created.text()).toBeTruthy()
  try {
    const preflight = await (await page.request.get(`/api/v1/docker/tools/${key}/preflight`)).json()
    expect(preflight.ready).toBe(false)
    expect(preflight.tools[0].issues).toContainEqual(expect.objectContaining({ code: 'image_missing', action: 'build' }))
    expect(preflight.tools[0].issues.some((issue: { code: string }) => issue.code === 'parser_missing')).toBe(false)
    const direct = await page.request.post(`/api/v1/projects/${projectId}/docker/tools/${key}/runs`, { headers, data: { params: {}, output_subdir: 'readiness-test' } })
    expect(direct.status()).toBe(409)
    expect((await direct.json()).detail).toContain('Preflight failed')
    const report = await page.request.get(`/api/v1/projects/${projectId}/transform-preflight?transform_id=docker:${key}`)
    expect(report.ok()).toBeTruthy()
    expect((await report.json()).ready).toBe(false)
    const investigations = await (await page.request.get(`/api/v1/projects/${projectId}/investigations`)).json()
    const graph = await (await page.request.get(`/api/v1/projects/${projectId}/investigations/${investigations[0].id}/graph`)).json()
    const target = graph.entities.find((entity: { kind: string }) => entity.kind === 'target')
    const transform = await page.request.post(`/api/v1/projects/${projectId}/transforms`, { headers, data: { transform_id: `docker:${key}`, entity_ids: [target.id], investigation_id: investigations[0].id } })
    expect(transform.status()).toBe(409)
    expect((await transform.json()).detail).toContain('Preflight failed')
  } finally {
    await page.request.delete(`/api/v1/docker/tools/${key}`, { headers })
  }
})
