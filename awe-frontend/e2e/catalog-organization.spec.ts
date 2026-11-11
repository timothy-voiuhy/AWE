import { expect, test } from '@playwright/test'

test('saved transform placement is visible while Docker inventory is still loading', async ({ page }) => {
  await page.goto('/projects')
  await page.getByLabel('Username').fill(process.env.E2E_USERNAME!)
  await page.locator('input[autocomplete="current-password"]').fill(process.env.E2E_PASSWORD!)
  await page.getByRole('button', { name: 'Sign in' }).click()
  await expect(page.getByLabel('Dashboard options')).toBeVisible()
  const projectId = (await (await page.request.get('/api/v1/projects')).json())[0].id
  let releaseInventory: () => void = () => {}
  const inventoryReady = new Promise<void>(resolve => { releaseInventory = resolve })
  await page.route('**/api/v1/docker/tools', async route => { await inventoryReady; await route.fulfill({ json: [] }) })
  await page.route(`**/api/v1/projects/${projectId}/catalog/organization`, route => route.fulfill({ json: { categories: [{ id: 'research', name: 'Research', parent_id: null }, { id: 'nested', name: 'Saved placement', parent_id: 'research' }], defaults: {}, assignments: {}, placements: { 'tool:fixture': 'nested' } } }))
  await page.route(`**/api/v1/projects/${projectId}/transforms`, route => route.fulfill({ json: [{ id: 'docker:fixture', tool_key: 'fixture', display_name: 'Saved tool transform', category: 'vuln', description: '', mode: 'passive', input_types: ['url'], output_types: [], output_channels: ['logs'], relationship_types: [], parameters: [], stages: [] }] }))
  try {
    await page.goto(`/projects/${projectId}/network/transforms`)
    await page.locator('.catalog-category-toggle').filter({ hasText: 'Research' }).click()
    await page.locator('.catalog-category-toggle').filter({ hasText: 'Saved placement' }).click()
    await expect(page.locator('.transform-catalog-grid')).toContainText('Saved tool transform')
  } finally {
    const response = page.waitForResponse('**/api/v1/docker/tools')
    releaseInventory()
    await response
  }
})

test('categories nest, rename, move, and persist shared tool/transform placement', async ({ page }) => {
  test.setTimeout(60000)
  await page.goto('/projects')
  await page.getByLabel('Username').fill(process.env.E2E_USERNAME!)
  await page.locator('input[autocomplete="current-password"]').fill(process.env.E2E_PASSWORD!)
  await page.getByRole('button', { name: 'Sign in' }).click()
  await expect(page.getByLabel('Dashboard options')).toBeVisible()
  const projectId = (await (await page.request.get('/api/v1/projects')).json())[0].id
  const csrf = (await page.context().cookies()).find(cookie => cookie.name === 'awe_csrf')!.value
  const headers = { 'X-AWE-CSRF': decodeURIComponent(csrf) }
  const key = `e2e_categories_${Date.now()}`
  const name = `Catalog fixture ${Date.now()}`
  const rootName = `E2E research ${Date.now()}`
  const base = `/api/v1/projects/${projectId}/catalog`
  const createdCategories: string[] = []
  const state = async () => (await page.request.get(`${base}/organization`)).json()
  const findCategory = async (label: string, parent: string | null) => (await state()).categories.find((item: { name: string; parent_id: string | null }) => item.name === label && item.parent_id === parent).id as string
  const created = await page.request.post('/api/v1/docker/tools', { headers, data: { key, display_name: name, category: 'vuln', image: 'nginx:1.27-alpine', command_template: 'printf fixture', dockerfile: 'FROM nginx:1.27-alpine', parser: '', input_types: ['url'], output_types: [], relationship_types: [], execution_mode: 'passive', output_channels: ['logs'] } })
  expect(created.ok()).toBeTruthy()
  try {
    await page.goto(`/projects/${projectId}/network/transforms?view=tools`)
    await page.getByLabel('Transform options').click()
    await page.getByRole('button', { name: 'Manage categories', exact: true }).click()
    const dialog = page.getByRole('dialog', { name: 'Manage categories', exact: true })
    await dialog.getByLabel('Category name', { exact: true }).fill(rootName)
    await dialog.getByRole('button', { name: 'Create category', exact: true }).click()
    await expect(dialog.getByRole('status')).toContainText('saved')
    const root = await findCategory(rootName, null); createdCategories.push(root)
    await dialog.getByLabel('Parent category', { exact: true }).selectOption(root)
    await dialog.getByLabel('Category name', { exact: true }).fill('Web')
    await dialog.getByRole('button', { name: 'Create category', exact: true }).click()
    await expect(dialog.getByLabel('Category name', { exact: true })).toHaveValue('')
    const web = await findCategory('Web', root); createdCategories.push(web)
    await dialog.getByLabel('Parent category', { exact: true }).selectOption(web)
    await dialog.getByLabel('Category name', { exact: true }).fill('PHP')
    await dialog.getByRole('button', { name: 'Create category', exact: true }).click()
    await expect(dialog.getByLabel('Category name', { exact: true })).toHaveValue('')
    const php = await findCategory('PHP', web); createdCategories.push(php)
    await dialog.getByRole('button', { name: 'Close category manager' }).click()
    await page.getByRole('button', { name: 'Search tools', exact: true }).click()
    await page.getByRole('searchbox').fill(name)
    await page.getByRole('button', { name: `Move ${name} to category`, exact: true }).click()
    await expect(dialog.getByRole('checkbox', { name: new RegExp(name) })).toBeChecked()
    await dialog.getByLabel('Destination category', { exact: true }).selectOption(php)
    await dialog.getByRole('button', { name: 'Move selected (1)', exact: true }).click()
    await expect(dialog.getByRole('status')).toContainText('saved')
    await dialog.getByRole('button', { name: 'Close category manager' }).click()
    await expect(page.locator('.graph-catalog-row')).toContainText(`${rootName} / Web / PHP`)
    expect((await state()).assignments[`tool:${key}`]).toBe(php)
    await page.getByRole('button', { name: /^Transforms \d/ }).click()
    await expect(page.locator('.transform-catalog-grid')).toContainText(name)
    await expect(page.locator('.catalog-category-toggle').filter({ hasText: rootName })).toHaveAttribute('aria-expanded', 'true')
    await page.reload()
    const rootToggle = page.locator('.catalog-category-toggle').filter({ hasText: rootName })
    await expect(rootToggle).toHaveAttribute('aria-expanded', 'false')
    await rootToggle.click()
    await page.locator('.catalog-category-toggle').filter({ hasText: 'Web' }).click()
    await page.locator('.catalog-category-toggle').filter({ hasText: 'PHP' }).click()
    await expect(page.locator('.transform-catalog-grid').filter({ hasText: name })).toBeVisible()

    await page.getByLabel('Transform options').click()
    await page.getByRole('button', { name: 'Manage categories', exact: true }).click()
    await dialog.getByLabel('Category to edit', { exact: true }).selectOption(web)
    await dialog.getByLabel('Category name', { exact: true }).fill('Applications')
    const exploits = (await state()).defaults.Exploits
    await dialog.getByLabel('Parent category', { exact: true }).selectOption(exploits)
    await dialog.getByRole('button', { name: 'Save category', exact: true }).click()
    await expect(dialog.getByRole('status')).toContainText('saved')
    await dialog.getByRole('button', { name: 'Close category manager' }).click()
    await page.getByRole('button', { name: 'Search transforms', exact: true }).click()
    await page.getByRole('searchbox').fill('Applications PHP')
    await expect(page.locator('.transform-catalog-grid')).toContainText(name)
    await expect(page.locator('.catalog-category-toggle').filter({ hasText: 'Applications' })).toHaveAttribute('aria-expanded', 'true')
    await page.setViewportSize({ width: 390, height: 844 })
    await page.getByRole('button', { name: `Move ${name} to category`, exact: true }).click()
    await expect(dialog.getByRole('checkbox', { name: new RegExp(name) })).toBeVisible()
    await expect(dialog.getByRole('button', { name: 'Move selected (1)', exact: true })).toBeVisible()
    expect(await dialog.evaluate(element => element.scrollWidth - element.clientWidth)).toBeLessThanOrEqual(1)
    await page.screenshot({ path: '/tmp/awe-category-manager-mobile.png', fullPage: true })
  } finally {
    await page.request.delete(`/api/v1/docker/tools/${key}`, { headers })
    for (const categoryId of createdCategories.reverse()) await page.request.delete(`${base}/categories/${categoryId}`, { headers })
  }
})
