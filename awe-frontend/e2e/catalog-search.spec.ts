import { expect, test } from '@playwright/test'

test('catalog search reveals collapsed matches and follows the active catalog', async ({ page }) => {
  await page.goto('/projects')
  await page.getByLabel('Username').fill(process.env.E2E_USERNAME!)
  await page.locator('input[autocomplete="current-password"]').fill(process.env.E2E_PASSWORD!)
  await page.getByRole('button', { name: 'Sign in' }).click()
  await expect(page.getByLabel('Dashboard options')).toBeVisible()
  const projectId = (await (await page.request.get('/api/v1/projects')).json())[0].id
  const common = { category: 'vuln', input_types: ['url'], output_types: [], relationship_types: [], output_channels: ['logs'], execution_kind: 'batch', description: '', parameters: [], requires_approval: false, mode: 'passive', stages: [] }
  await page.route(`**/api/v1/projects/${projectId}/catalog/organization`, route => route.fulfill({ json: { categories: [{ id: 'vuln', name: 'vuln', parent_id: null }], assignments: {}, defaults: { vuln: 'vuln' } } }))
  await page.route(`**/api/v1/projects/${projectId}/transforms`, route => route.fulfill({ json: [
    { ...common, id: 'docker:nginx_rift', tool_key: 'nginx_rift', display_name: 'Nginx Rift' },
    { ...common, id: 'docker:php2shell', tool_key: 'php2shell', display_name: 'php2shell' },
  ] }))
  await page.route('**/api/v1/docker/tools', route => route.fulfill({ json: [
    { ...common, key: 'nginx_rift', display_name: 'Nginx Rift', image: 'awe/poc-nginx_rift:revision', graph_enabled: true, status: 'ok', execution_mode: 'passive', source: 'build' },
    { ...common, key: 'php2shell', display_name: 'php2shell', image: 'awe/poc-php2shell:revision', graph_enabled: true, status: 'ok', execution_mode: 'passive', source: 'build' },
  ] }))

  for (const viewport of [{ width: 1440, height: 900 }, { width: 390, height: 844 }]) {
    await page.setViewportSize(viewport)
    await page.goto(`/projects/${projectId}/network/transforms`)
    await expect(page.locator('.catalog-category-toggle')).toHaveAttribute('aria-expanded', 'false')
    const toggle = page.getByRole('button', { name: 'Search transforms', exact: true })
    const menu = page.getByLabel('Transform options')
    const toggleBox = await toggle.boundingBox()
    const menuBox = await menu.boundingBox()
    expect(Math.abs(toggleBox!.y - menuBox!.y)).toBeLessThan(10)
    expect(menuBox!.x - (toggleBox!.x + toggleBox!.width)).toBeLessThan(20)
    await toggle.click()
    const input = page.getByRole('searchbox', { name: 'Search transforms catalog' })
    await expect(input).toBeFocused()
    expect((await input.boundingBox())!.y).toBeLessThan(220)
    await input.fill('  RiFt VULN  ')
    await expect(page.locator('.transform-catalog-grid > article')).toHaveCount(1)
    await expect(page.locator('.transform-catalog-grid')).toContainText('Nginx Rift')
    await expect(page.locator('.catalog-category-toggle')).toHaveAttribute('aria-expanded', 'true')
    await page.getByRole('button', { name: /^Tools \d/ }).click()
    const toolInput = page.getByRole('searchbox', { name: 'Search tools catalog' })
    await expect(toolInput).toHaveValue('  RiFt VULN  ')
    await expect(page.locator('.graph-catalog-row')).toHaveCount(1)
    await toolInput.fill('awe/poc-php2shell')
    await expect(page.locator('.graph-catalog-row')).toContainText('php2shell')
    await page.getByRole('button', { name: /^Transforms \d/ }).click()
    await expect(page.getByText('No transforms match your search.', { exact: true })).toBeVisible()
    await page.getByRole('button', { name: 'Clear', exact: true }).click()
    await expect(page.getByRole('searchbox')).toBeFocused()
    await expect(page.locator('.catalog-category-toggle')).toHaveAttribute('aria-expanded', 'false')
    await page.getByRole('searchbox').fill('no matching tool')
    await page.getByRole('searchbox').press('Escape')
    await expect(page.getByRole('searchbox')).toHaveCount(0)
    await expect(toggle).toBeFocused()
    await toggle.click()
    await expect(input).toHaveValue('')
    await input.fill('php2shell')
    await expect(page.locator('.transform-catalog-grid')).toContainText('php2shell')
    await page.getByRole('button', { name: 'Close catalog search' }).click()
    await expect(page.locator('.catalog-category-toggle')).toHaveAttribute('aria-expanded', 'false')
    expect(await page.locator('main').evaluate(element => element.scrollWidth - element.clientWidth)).toBeLessThanOrEqual(1)
  }
})
