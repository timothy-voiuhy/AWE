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

test('a transform can run with all compatible output from a previous transform', async ({ page }) => {
  const projectId = await signInAndGetProject(page)
  const investigationId = 'e2e-investigation'
  let startBody: Record<string, unknown> | undefined
  const now = new Date().toISOString()
  const investigation = { id: investigationId, project_id: projectId, name: 'E2E investigation', revision: 1, created_at: now, updated_at: now, root_ids: [], entity_ids: ['sub-1', 'sub-2'], relationship_ids: [], preferences: {} }
  const manifest = { id: 'httpx', tool_key: 'httpx', display_name: 'Probe live hosts', category: 'HTTP', description: 'Probe subdomains with httpx.', input_types: ['subdomain'], output_types: ['url'], relationship_types: ['resolves_to'], mode: 'safe_active', requires_approval: false, scope_required: true, parameters: [], stages: [] }
  const previousJob = { id: 'enumerate-job', project_id: projectId, investigation_id: investigationId, transform_id: 'enumerate-subdomains', status: 'completed', entity_ids: ['target-1'], operation_id: 'operation-1', parameters: {}, message: 'Completed', created_at: now, completed_at: now, outputs_ingested: true, progress_completed: 1, progress_total: 1, logs: [] }
  const entity = (id: string, value: string) => ({ id, kind: 'subdomain', label: value, value, data: {}, source: 'transform', confidence: 1, severity: '', scope: 'in', pinned: false, bookmarked: false, x: 0, y: 0, provenance: [{ transform_job_id: previousJob.id, tool_key: 'subfinder' }] })
  const target = { id: 'target-1', kind: 'target', label: 'example.com', value: 'example.com', data: {}, source: 'derived', confidence: 1, severity: '', scope: 'in', pinned: false, bookmarked: false, x: 0, y: 0, provenance: [] }

  await page.route(`**/api/v1/projects/${projectId}/investigations`, route => route.fulfill({ json: [investigation] }))
  await page.route(`**/api/v1/projects/${projectId}/investigations/${investigationId}/graph?*`, route => route.fulfill({ json: { investigation, entities: [target, entity('sub-1', 'one.example.com'), entity('sub-2', 'two.example.com')], relationships: [], revision: 1 } }))
  await page.route(`**/api/v1/projects/${projectId}/evidence?*`, route => route.fulfill({ json: [] }))
  await page.route(`**/api/v1/projects/${projectId}/transforms/jobs`, route => route.fulfill({ json: [previousJob] }))
  await page.route(`**/api/v1/projects/${projectId}/transforms/httpx-job`, route => route.fulfill({ json: { ...previousJob, id: 'httpx-job', transform_id: manifest.id, status: 'queued', source_job_id: previousJob.id, entity_ids: ['sub-1', 'sub-2'], operation_id: 'operation-2', completed_at: null, outputs_ingested: false, progress_completed: 0 } }))
  await page.route(`**/api/v1/projects/${projectId}/transforms`, async route => {
    if (route.request().method() === 'GET') return route.fulfill({ json: [manifest] })
    startBody = route.request().postDataJSON() as Record<string, unknown>
    return route.fulfill({ status: 202, json: { ...previousJob, id: 'httpx-job', transform_id: manifest.id, status: 'queued', source_job_id: previousJob.id, entity_ids: ['sub-1', 'sub-2'], operation_id: 'operation-2', completed_at: null, outputs_ingested: false, progress_completed: 0 } })
  })

  await page.goto(`/projects/${projectId}/network/transforms`)
  await page.getByRole('button', { name: /HTTP/ }).click()
  await page.getByRole('button', { name: 'Run', exact: true }).click()
  const dialog = page.getByRole('dialog', { name: 'Run Probe live hosts' })
  await expect(dialog).toBeVisible()
  await expect(dialog.getByLabel('Transform input source')).toHaveValue('job:enumerate-job')
  await expect(dialog.getByLabel('Transform input source').locator('option:checked')).toContainText('2 compatible entities')
  await dialog.getByRole('button', { name: 'Run with 2 inputs' }).click()

  await expect.poll(() => startBody).toBeTruthy()
  expect(startBody).toMatchObject({
    transform_id: 'httpx',
    entity_ids: ['sub-1', 'sub-2'],
    source_job_id: 'enumerate-job',
    investigation_id: investigationId,
  })
  await expect(dialog.getByText('queued', { exact: true })).toBeVisible()

  startBody = undefined
  await page.goto(`/projects/${projectId}/network`)
  await page.locator('.graph-actions select').selectOption('httpx')
  await expect(page.getByLabel('Graph transform input source')).toHaveValue('job:enumerate-job')
  await page.locator('.graph-actions').getByRole('button', { name: 'Run' }).click()
  await expect.poll(() => startBody).toBeTruthy()
  expect(startBody).toMatchObject({ entity_ids: ['sub-1', 'sub-2'], source_job_id: 'enumerate-job' })
})
