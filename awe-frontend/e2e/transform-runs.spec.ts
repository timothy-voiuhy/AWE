import { expect, test, type Page } from '@playwright/test'

async function signInAndGetProject(page: Page) {
  const username = process.env.E2E_USERNAME
  const password = process.env.E2E_PASSWORD
  if (!username || !password) throw new Error('Set E2E_USERNAME and E2E_PASSWORD in .env.e2e.local')

  await page.goto('/projects')
  await page.getByLabel('Username').fill(username)
  await page.locator('input[autocomplete="current-password"]').fill(password)
  await page.getByRole('button', { name: 'Sign in' }).click()
  await expect(page.getByRole('heading', { name: 'Start an engagement' })).toBeVisible()

  const projects = await page.request.get('/api/v1/projects')
  expect(projects.ok()).toBeTruthy()
  const project = (await projects.json())[0]
  expect(project?.id).toBeTruthy()
  return project.id as string
}

test('transform runs dialog shows live status changes', async ({ page }) => {
  const projectId = await signInAndGetProject(page)

  let requests = 0
  await page.route(`**/api/v1/projects/${projectId}/transforms/jobs`, async route => {
    requests += 1
    const status = requests === 1 ? 'running' : 'completed'
    await route.fulfill({ json: [{
      id: 'e2e-transform-run', project_id: projectId, investigation_id: 'e2e-investigation',
      transform_id: 'e2e-transform', status, entity_ids: [], operation_id: 'e2e-operation',
      parameters: {}, message: status === 'running' ? 'Processing input' : 'Completed',
      created_at: new Date().toISOString(), completed_at: status === 'completed' ? new Date().toISOString() : null,
      progress_completed: status === 'running' ? 1 : 2, progress_total: 2,
      logs: ['Started transform'],
    }] })
  })

  await page.goto(`/projects/${projectId}/network/transforms`)
  await page.getByLabel('Transform options').click()
  await page.getByRole('button', { name: 'View running transforms' }).click()
  const dialog = page.getByRole('dialog', { name: 'Transform runs' })
  await expect(dialog).toBeVisible()
  await expect(dialog.locator('.transform-run-status')).toHaveText('running')
  await expect(dialog.getByRole('progressbar')).toHaveAttribute('aria-valuenow', '50')
  await expect(dialog.locator('.transform-run-status')).toHaveText('completed')
  await expect(dialog.getByRole('heading', { name: 'Recent results' })).toBeVisible()
  await dialog.getByRole('button', { name: 'Close dialog' }).click()
  await expect(dialog).not.toBeVisible()
})

test('unfinished transform can be resumed from the dialog', async ({ page }) => {
  const projectId = await signInAndGetProject(page)
  let status = 'failed'
  let resumeBody: unknown
  const job = () => ({
    id: 'e2e-failed-run', project_id: projectId, investigation_id: 'e2e-investigation',
    transform_id: 'e2e-transform', status, entity_ids: [], operation_id: 'e2e-operation',
    parameters: {}, message: status === 'failed' ? 'Interrupted by backend restart' : 'Resuming transform',
    created_at: new Date().toISOString(), completed_at: status === 'failed' ? new Date().toISOString() : null,
    progress_completed: 0, progress_total: 2, logs: ['Interrupted'],
  })
  await page.route(`**/api/v1/projects/${projectId}/transforms/jobs`, route => route.fulfill({ json: [job()] }))
  await page.route(`**/api/v1/projects/${projectId}/transforms/e2e-failed-run`, route => route.fulfill({ json: job() }))
  await page.route(`**/api/v1/projects/${projectId}/transforms/e2e-failed-run/resume`, async route => {
    resumeBody = route.request().postDataJSON()
    status = 'queued'
    await route.fulfill({ status: 202, json: job() })
  })

  await page.goto(`/projects/${projectId}/network/transforms`)
  await page.getByLabel('Transform options').click()
  await page.getByRole('button', { name: 'View running transforms' }).click()
  const dialog = page.getByRole('dialog', { name: 'Transform runs' })
  await expect(dialog.getByRole('heading', { name: /Unfinished/ })).toBeVisible()
  await dialog.getByRole('button', { name: 'Resume transform' }).click()
  await expect(dialog.locator('.transform-run-status')).toHaveText('queued')
  expect(resumeBody).toEqual({ parameters: {}, approved: false })
})
