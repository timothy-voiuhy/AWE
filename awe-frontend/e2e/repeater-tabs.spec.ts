import { expect, test } from '@playwright/test'

test('repeater creates tabs from the tab strip menu and context menu', async ({ page }) => {
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

  await page.goto(`/projects/${projectId}/repeater`)
  await expect(page.getByRole('heading', { name: 'Repeater' })).toHaveCount(0)
  await expect(page.getByText('Manual testing')).toHaveCount(0)
  const tabs = page.locator('.repeater-tabs > button')
  await expect(tabs).toHaveCount(1)

  await page.getByLabel('Tab options').click()
  await page.getByRole('button', { name: 'New tab' }).click()
  await expect(tabs).toHaveCount(2)
  await expect(tabs.nth(1)).toHaveClass(/selected/)

  await tabs.nth(1).click({ button: 'right' })
  await expect(page.getByRole('button', { name: 'New tab' })).toBeVisible()
  await page.getByRole('button', { name: 'New tab' }).click()
  await expect(tabs).toHaveCount(3)
  await expect(page.getByText('Request', { exact: true })).toBeVisible()
})
