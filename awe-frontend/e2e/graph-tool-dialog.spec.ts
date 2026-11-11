import { expect, test } from '@playwright/test'

test('custom graph tool is created from the options dialog', async ({ page }) => {
  const username = process.env.E2E_USERNAME
  const password = process.env.E2E_PASSWORD
  if (!username || !password) throw new Error('Set E2E_USERNAME and E2E_PASSWORD in .env.e2e.local')

  await page.goto('/projects')
  await page.getByLabel('Username').fill(username)
  await page.locator('input[autocomplete="current-password"]').fill(password)
  await page.getByRole('button', { name: 'Sign in' }).click()
  await expect(page.getByLabel('Dashboard options')).toBeVisible()
  const projects = await page.request.get('/api/v1/projects')
  expect(projects.ok()).toBeTruthy()
  const projectId = (await projects.json())[0]?.id
  expect(projectId).toBeTruthy()

  let submitted: Record<string, unknown> | undefined
  await page.route('**/api/v1/docker/tools', async route => {
    if (route.request().method() !== 'POST') return route.continue()
    submitted = route.request().postDataJSON()
    await route.fulfill({ json: { display_name: 'Example scanner' } })
  })

  await page.goto(`/projects/${projectId}/network/transforms`)
  const dialog = page.getByRole('dialog', { name: 'Create custom graph tool' })
  await expect(dialog).not.toBeVisible()
  await page.getByLabel('Transform options').click()
  await page.getByRole('button', { name: 'Create custom graph tool' }).click()
  await expect(dialog).toBeVisible()

  await dialog.getByLabel('Key').fill('example_scanner')
  await dialog.getByLabel('Display name').fill('Example scanner')
  await dialog.getByLabel('Image').fill('awe/custom_example_scanner')
  await dialog.getByLabel('Command template').fill('scanner -o /output/results.json')
  await dialog.getByLabel('Parameters JSON').fill('{invalid')
  await dialog.getByRole('button', { name: 'Create graph tool' }).click()
  await expect(dialog.getByRole('alert')).toHaveText('Parameters JSON must be a valid array.')

  await dialog.getByLabel('Parameters JSON').fill('[]')
  await dialog.getByRole('button', { name: 'Create graph tool' }).click()
  await expect(dialog).not.toBeVisible()
  await expect(page.getByText('Created Example scanner as a graph tool.')).toBeVisible()
  expect(submitted?.key).toBe('example_scanner')
  expect(submitted?.param_specs).toEqual([])
})
