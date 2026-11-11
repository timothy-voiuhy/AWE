import { execFileSync } from 'node:child_process'
import { expect, test, type Page } from '@playwright/test'

async function login(page: Page) {
  await page.goto('/projects')
  await page.getByLabel('Username').fill(process.env.E2E_USERNAME!)
  await page.locator('input[autocomplete="current-password"]').fill(process.env.E2E_PASSWORD!)
  await page.getByRole('button', { name: 'Sign in' }).click()
  await expect(page.getByLabel('Dashboard options')).toBeVisible()
  const projects = await (await page.request.get('/api/v1/projects')).json()
  const csrf = (await page.context().cookies()).find(cookie => cookie.name === 'awe_csrf')!.value
  return { projectId: projects[0].id as string, headers: { 'X-AWE-CSRF': decodeURIComponent(csrf) } }
}

test('coverage distinguishes tested profiles, adapters, and gaps and links into catalog search', async ({ page }) => {
  const { projectId } = await login(page)
  await page.goto(`/projects/${projectId}/network/transforms`)
  await page.getByLabel('Transform options').click()
  await page.getByRole('link', { name: 'Coverage matrix', exact: true }).click()
  await expect(page.getByText('29 native validation transforms', { exact: false })).toBeVisible()
  await expect(page.getByRole('button', { name: 'Fixture tested 29', exact: true })).toBeVisible()
  await page.getByRole('button', { name: /^Manual \/ partial/ }).click()
  await page.getByLabel('Search coverage').fill('smuggling')
  await expect(page.locator('.coverage-table tbody tr')).toHaveCount(1)
  await expect(page.locator('.coverage-table tbody')).toContainText('not a raw multi-hop protocol tester')
  await page.getByRole('button', { name: /^All areas/ }).click()
  await page.getByLabel('Search coverage').fill('awe_cors')
  await page.getByRole('link', { name: 'awe_cors', exact: true }).click()
  await expect(page.getByRole('searchbox', { name: 'Search transforms catalog' })).toHaveValue('awe_cors')
  await expect(page.locator('.transform-catalog-grid > article')).toHaveCount(1)
  await expect(page.locator('.transform-catalog-grid')).toContainText('Validate credentialed CORS policy')
  await page.getByLabel('Transform options').click()
  await page.getByRole('link', { name: 'Validation guide', exact: true }).click()
  await expect(page.getByRole('heading', { name: 'Native vulnerability validation transforms', exact: true })).toBeVisible()
  await page.setViewportSize({ width: 390, height: 844 })
  await page.goto(`/projects/${projectId}/network/coverage`)
  await expect(page.getByLabel('Search coverage')).toBeVisible()
  expect(await page.locator('main').evaluate(element => element.scrollWidth - element.clientWidth)).toBeLessThanOrEqual(1)
  await page.screenshot({ path: '/tmp/awe-coverage-mobile.png', fullPage: true })
})

test('native graph validation executes in Docker with redacted evidence and honest negative/error outcomes', async ({ page }) => {
  test.setTimeout(90000)
  const { headers } = await login(page)
  const labName = `awe_validation_e2e_${Date.now()}`
  const source = `from http.server import BaseHTTPRequestHandler,HTTPServer
class Handler(BaseHTTPRequestHandler):
 def log_message(self,*args): pass
 def do_GET(self):
  self.send_response(200)
  self.send_header('Content-Type','text/html')
  self.send_header('Access-Control-Allow-Credentials','true')
  self.send_header('Access-Control-Allow-Origin',self.headers.get('Origin','https://trusted.invalid') if self.path.startswith('/vulnerable') else 'https://trusted.invalid')
  self.end_headers()
  self.wfile.write(b'controlled private fixture' if self.headers.get('Authorization')=='Bearer E2E-validation-secret' else b'public fixture')
server=HTTPServer(('0.0.0.0',8000),Handler)
print('fixture-ready',flush=True)
server.serve_forever()`
  execFileSync('docker', ['run', '-d', '--rm', '--name', labName, '--network', 'bridge', '--entrypoint', 'python', 'python:3.12-slim', '-u', '-c', source], { timeout: 30000 })
  try {
    await expect.poll(() => execFileSync('docker', ['logs', labName], { encoding: 'utf8' })).toContain('fixture-ready')
    const inspected = JSON.parse(execFileSync('docker', ['inspect', labName], { encoding: 'utf8' }))
    const ip = inspected[0].NetworkSettings.Networks.bridge.IPAddress as string
    expect(ip).toMatch(/^\d+\.\d+\.\d+\.\d+$/)
    const target = `http://${ip}:8000/vulnerable`
    const projects = await (await page.request.get('/api/v1/projects')).json()
    let project = projects.find((item: { name: string }) => item.name === 'Native validation fixtures (E2E)')
    if (!project) project = await (await page.request.post('/api/v1/projects', { headers, data: { name: 'Native validation fixtures (E2E)', target } })).json()
    else await page.request.patch(`/api/v1/projects/${project.id}`, { headers, data: { target } })
    const p = project.id as string
    const invocation = { params: { url: target }, ingest_to_graph: false }
    expect((await page.request.post(`/api/v1/projects/${p}/docker/tools/awe_cors/runs`, { headers, data: invocation })).status()).toBe(409)
    const investigation = await (await page.request.post(`/api/v1/projects/${p}/investigations`, { headers, data: { name: `Controlled CORS fixture ${Date.now()}` } })).json()
    const entity = await page.request.post(`/api/v1/projects/${p}/investigations/${investigation.id}/entities`, { headers, data: { kind: 'url', label: target, value: target } })
    expect(entity.ok()).toBeTruthy()
    await page.goto(`/projects/${p}/network/transforms?find=awe_cors`)
    await page.locator('.transform-catalog-grid').getByRole('button', { name: 'Run', exact: true }).click()
    const dialog = page.getByRole('dialog', { name: 'Run Validate credentialed CORS policy', exact: true })
    await dialog.getByRole('combobox', { name: 'Investigation', exact: true }).selectOption(investigation.id)
    const secret = JSON.stringify({ headers: { Authorization: 'Bearer E2E-validation-secret' } })
    await dialog.getByLabel('Primary request context (secret JSON)', { exact: true }).fill(secret)
    page.once('dialog', prompt => prompt.accept())
    const queuedResponse = page.waitForResponse(response => response.request().method() === 'POST' && response.url().endsWith(`/api/v1/projects/${p}/transforms`))
    await dialog.getByRole('button', { name: 'Run with 1 input', exact: true }).click()
    const queued = await (await queuedResponse).json()
    expect(queued.id).toBeTruthy()
    let job: { status: string; operation_id?: string; message?: string } = { status: 'queued' }
    await expect.poll(async () => { job = await (await page.request.get(`/api/v1/projects/${p}/transforms/${queued.id}`)).json(); return job.status }, { timeout: 30000 }).toBe('completed')
    expect(job.operation_id).toBeTruthy()
    const runId = job.operation_id!
    const run = await (await page.request.get(`/api/v1/projects/${p}/runs/${runId}`)).json()
    expect(run.parameters.request_context).toBe('[redacted]')
    expect(run.parameters.url).toBe('[redacted]')
    const graph = await (await page.request.get(`/api/v1/projects/${p}/investigations/${investigation.id}/graph`)).json()
    const findings = graph.entities.filter((item: { kind: string }) => item.kind === 'vuln')
    expect(findings).toHaveLength(2)
    expect(findings.every((item: { data: { verification: string } }) => item.data.verification === 'verified_behavior')).toBeTruthy()
    expect(new Set(findings.map((item: { value: string }) => item.value)).size).toBe(2)
    await page.goto(`/projects/${p}/runs/${runId}`)
    await page.getByRole('tab', { name: 'Logs', exact: true }).click()
    await expect(page.locator('.runtime-log')).toContainText('awe_cors: findings')
    await expect(page.locator('.runtime-log')).not.toContainText('E2E-validation-secret')
    await page.getByRole('tab', { name: /^Artifacts/ }).click()
    const reportCard = page.locator('.runtime-artifact').filter({ has: page.getByRole('link', { name: 'validation-report.json', exact: true }) })
    await expect(reportCard).toBeVisible()
    const reportLink = await reportCard.getByRole('link', { name: 'validation-report.json', exact: true }).getAttribute('href')
    const report = await (await page.request.get(reportLink!)).json()
    expect(report.outcome).toBe('findings')
    expect(JSON.stringify(report)).not.toContain('E2E-validation-secret')
    await reportCard.getByRole('button', { name: 'Use as evidence' }).click()
    await page.getByLabel('Researcher interpretation').fill('Controlled fixture: credentialed CORS policy behavior verified; no public target was tested.')
    await page.getByRole('button', { name: 'Save evidence', exact: true }).click()
    await expect(page.getByRole('status')).toContainText('Evidence saved')

    for (const [key, path, expectedStatus, expectedOutcome] of [['awe_cors', '/protected', 'completed', 'no_findings'], ['awe_open_redirect', '/protected', 'failed', 'inconclusive']]) {
      const response = await page.request.post(`/api/v1/projects/${p}/docker/tools/${key}/runs`, { headers, data: { params: { url: `http://${ip}:8000${path}` }, ingest_to_graph: false, approved: true } })
      expect(response.ok()).toBeTruthy()
      const operation = await response.json()
      await expect.poll(async () => (await (await page.request.get(`/api/v1/projects/${p}/runs/${operation.id}`)).json()).status, { timeout: 20000 }).toBe(expectedStatus)
      const artifacts = await (await page.request.get(`/api/v1/projects/${p}/runs/${operation.id}/artifacts`)).json()
      const artifact = artifacts.find((item: { name: string }) => item.name === 'validation-report.json')
      expect(artifact).toBeTruthy()
      const result = await (await page.request.get(`/api/v1/projects/${p}/runs/${operation.id}/artifacts/${artifact.id}`)).json()
      expect(result.outcome).toBe(expectedOutcome)
      expect(result.findings).toHaveLength(0)
    }
  } finally { execFileSync('docker', ['rm', '-f', labName], { timeout: 10000 }) }
})
