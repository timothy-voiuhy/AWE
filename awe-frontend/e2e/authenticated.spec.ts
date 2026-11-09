import { expect, test } from '@playwright/test'

test('test account signs in and can access projects and database', async ({ page }) => {
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

  await expect(page.getByRole('heading', { name: 'Start an engagement' })).toBeVisible()
  const session = await page.request.get('/api/v1/auth/session')
  expect(session.ok()).toBeTruthy()
  expect((await session.json()).username).toBe(username)

  await page.locator('a[href="/database"]').click()
  await expect(page).toHaveURL(/\/database$/)
  await expect(page.getByRole('heading', { name: 'Collections' })).toBeVisible()
})
