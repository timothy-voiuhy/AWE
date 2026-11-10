import { expect, test } from '@playwright/test'

test('test account signs in, creates projects from the dashboard menu, and can access database', async ({ page }) => {
  const username = process.env.E2E_USERNAME
  const password = process.env.E2E_PASSWORD
  if (!username || !password) {
    throw new Error('Set E2E_USERNAME and E2E_PASSWORD in .env.e2e.local')
  }

  await page.goto('/projects')
  await expect(page.getByRole('heading', { name: 'Sign in to AWE' })).toBeVisible()
  await page.getByLabel('Username').fill(username)
  await page.locator('input[autocomplete="current-password"]').fill(password)
  await page.getByRole('button', { name: 'Sign in' }).click()

  await expect(page.getByLabel('Dashboard options')).toBeVisible()
  await expect(page.getByRole('region', { name: 'Workspace metrics' })).toBeVisible()
  const session = await page.request.get('/api/v1/auth/session')
  expect(session.ok()).toBeTruthy()
  expect((await session.json()).username).toBe(username)

  let submittedProject: unknown
  await page.route('**/api/v1/projects', async route => {
    if (route.request().method() !== 'POST') return route.continue()
    submittedProject = route.request().postDataJSON()
    return route.fulfill({
      status: 201,
      contentType: 'application/json',
      body: JSON.stringify({
        id: 'dashboard-e2e-project',
        name: 'Dashboard E2E project',
        target: 'https://dashboard.example',
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
      }),
    })
  })
  await page.getByLabel('Dashboard options').click()
  await page.getByRole('button', { name: 'New project' }).click()
  const createDialog = page.getByRole('dialog', { name: 'Create an engagement' })
  await expect(createDialog).toBeVisible()
  await createDialog.getByLabel('Project name').fill('Dashboard E2E project')
  await createDialog.getByLabel('Initial target').fill('https://dashboard.example')
  await createDialog.getByRole('button', { name: 'Create project' }).click()
  await expect(createDialog).not.toBeVisible()
  await expect(page.getByText('Created Dashboard E2E project.')).toBeVisible()
  expect(submittedProject).toEqual({ name: 'Dashboard E2E project', target: 'https://dashboard.example' })

  await page.getByRole('link', { name: 'Database' }).click()
  await expect(page).toHaveURL(/\/database$/)
  await expect(page.getByRole('heading', { name: 'Collections' })).toBeVisible()
})
