import { expect, test } from '@playwright/test'

test('dragging a graph node does not rebuild the graph on save or refresh', async ({ page }) => {
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

  const investigationId = 'e2e-graph-drag'
  let revision = 1
  let graphFetches = 0
  let savedPositions = 0
  const investigation = () => ({
    id: investigationId, project_id: projectId, name: 'Drag test', revision,
    created_at: new Date().toISOString(), updated_at: new Date().toISOString(),
    root_ids: ['target:example.com'], entity_ids: ['subdomain:app.example.com'],
    relationship_ids: ['test-edge'], preferences: {},
  })
  await page.route(`**/api/v1/projects/${projectId}/investigations`, route => route.fulfill({ json: [investigation()] }))
  await page.route(`**/api/v1/projects/${projectId}/investigations/${investigationId}/graph*`, route => {
    graphFetches += 1
    return route.fulfill({ json: {
      investigation: investigation(), revision,
      entities: [
        { id: 'target:example.com', kind: 'target', label: 'example.com', value: 'example.com', data: {}, source: 'derived', confidence: 1, provenance: [] },
        { id: 'subdomain:app.example.com', kind: 'subdomain', label: 'app.example.com', value: 'app.example.com', data: {}, source: 'derived', confidence: 1, provenance: [] },
      ],
      relationships: [{ id: 'test-edge', source_id: 'target:example.com', target_id: 'subdomain:app.example.com', kind: 'has_subdomain', source: 'derived' }],
    } })
  })
  await page.route(`**/api/v1/projects/${projectId}/investigations/${investigationId}/preferences`, async route => {
    const payload = route.request().postDataJSON()
    if (payload.preferences?.positions) savedPositions += 1
    revision += 1
    await route.fulfill({ json: { ...investigation(), preferences: payload.preferences } })
  })

  await page.goto(`/projects/${projectId}/network`)
  await expect(page.locator('.cytoscape-host canvas')).toHaveCount(3)
  await expect(page.locator('.graph-icon-actions, .graph-secondary-toolbar')).toHaveCount(0)
  await page.getByLabel('Network options').click()
  const options = page.locator('.graph-control-panel .page-options-panel')
  await expect(options.getByRole('button', { name: 'New investigation' })).toBeVisible()
  await options.getByLabel('Edge density').selectOption('pairs')
  await expect(page.locator('.graph-control-panel .page-options')).toHaveAttribute('open', '')
  await options.getByRole('button', { name: 'Display & relationships' }).click()
  await expect(page.locator('.graph-display-popover')).toBeVisible()
  await page.getByRole('button', { name: 'Close display controls' }).click()
  const point = await page.evaluate(() => {
    const canvases = [...document.querySelectorAll<HTMLCanvasElement>('.cytoscape-host canvas')]
    for (const canvas of canvases) {
      const pixels = canvas.getContext('2d')!.getImageData(0, 0, canvas.width, canvas.height).data
      let count = 0; let sumX = 0; let sumY = 0
      for (let y = 0; y < canvas.height; y += 1) for (let x = 0; x < canvas.width; x += 1) {
        const index = (y * canvas.width + x) * 4
        if (pixels[index] === 116 && pixels[index + 1] === 199 && pixels[index + 2] === 236 && pixels[index + 3] > 200) {
          count += 1; sumX += x; sumY += y
        }
      }
      if (count > 100) {
        const bounds = canvas.getBoundingClientRect()
        return { x: bounds.left + sumX / count * bounds.width / canvas.width, y: bounds.top + sumY / count * bounds.height / canvas.height }
      }
    }
    return null
  })
  expect(point).not.toBeNull()
  await page.evaluate(() => {
    const host = document.querySelector('.cytoscape-host')!
    const state = window as typeof window & { __graphRebuilds?: number }
    state.__graphRebuilds = 0
    new MutationObserver(records => { state.__graphRebuilds! += records.filter(record => record.target === host && record.type === 'childList').length }).observe(host, { childList: true })
  })

  await page.mouse.move(point!.x, point!.y)
  await page.mouse.down()
  await page.mouse.move(point!.x + 80, point!.y + 40, { steps: 12 })
  await page.mouse.up()
  await expect.poll(() => savedPositions).toBeGreaterThan(0)
  await expect.poll(() => graphFetches, { timeout: 10_000 }).toBeGreaterThan(1)
  expect(await page.evaluate(() => (window as typeof window & { __graphRebuilds?: number }).__graphRebuilds)).toBe(0)
})
