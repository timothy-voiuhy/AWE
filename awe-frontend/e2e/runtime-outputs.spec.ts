import { expect, test, type Page } from '@playwright/test'

async function login(page: Page) {
  await page.goto('/projects')
  await page.getByLabel('Username').fill(process.env.E2E_USERNAME!)
  await page.locator('input[autocomplete="current-password"]').fill(process.env.E2E_PASSWORD!)
  await page.getByRole('button', { name: 'Sign in' }).click()
  await expect(page.getByLabel('Dashboard options')).toBeVisible()
  const projects = await (await page.request.get('/api/v1/projects')).json()
  const csrf = (await page.context().cookies()).find(c => c.name === 'awe_csrf')!.value
  return { projectId: projects[0].id as string, headers: { 'X-AWE-CSRF': decodeURIComponent(csrf) } }
}

test('logs-only runs retain artifacts and interactive consoles detach without exiting', async ({ page }) => {
  const { projectId, headers } = await login(page)
  const key = `e2e_runtime_${Date.now()}`
  const tool = { key, display_name: 'E2E runtime fixture', category: 'vuln', image: 'nginx:1.27-alpine', command_template: "printf 'fixture-out\\n'; printf 'fixture-error\\n' >&2; printf 'saved report' > /output/report.txt", dockerfile: 'FROM nginx:1.27-alpine', parser: '', input_types: ['domain'], output_types: [], relationship_types: [], execution_mode: 'passive', output_channels: ['logs', 'artifacts'] }
  expect((await page.request.post('/api/v1/docker/tools', { headers, data: tool })).ok()).toBeTruthy()
  let sid = ''
  try {
    const response = await page.request.post(`/api/v1/projects/${projectId}/docker/tools/${key}/runs`, { headers, data: { params: {}, ingest_to_graph: false, output_subdir: 'e2e-runtime' } })
    expect(response.ok()).toBeTruthy()
    const operation = await response.json()
    await expect.poll(async () => (await (await page.request.get(`/api/v1/projects/${projectId}/runs/${operation.id}`)).json()).status).toBe('completed')
    await page.goto(`/projects/${projectId}/runs/${operation.id}`)
    await page.getByRole('tab', { name: 'Logs', exact: true }).click()
    await expect(page.locator('.runtime-log')).toContainText('fixture-out')
    await expect(page.locator('.runtime-log')).toContainText('fixture-error')
    await page.getByRole('tab', { name: /^Artifacts/ }).click()
    await expect(page.getByRole('link', { name: 'report.txt', exact: true })).toBeVisible()
    await page.getByRole('button', { name: 'Use as evidence' }).click()
    await page.getByLabel('Researcher interpretation').fill('Harmless fixture reviewed by test researcher.')
    await page.getByRole('button', { name: 'Save evidence', exact: true }).click()
    await expect(page.getByText('Evidence saved with source provenance.')).toBeVisible()

    expect((await page.request.put(`/api/v1/docker/tools/${key}`, { headers, data: { ...tool, command_template: 'sh', execution_kind: 'interactive', output_channels: ['logs', 'session'] } })).ok()).toBeTruthy()
    const launched = await (await page.request.post(`/api/v1/projects/${projectId}/docker/tools/${key}/runs`, { headers, data: { params: {}, ingest_to_graph: false, output_subdir: 'e2e-runtime-console' } })).json()
    await expect.poll(async () => {
      const run = await (await page.request.get(`/api/v1/projects/${projectId}/runs/${launched.id}`)).json()
      sid = run.session_id || ''; return !!sid
    }).toBeTruthy()
    await page.goto(`/projects/${projectId}/terminal/sessions?session=${sid}`)
    await expect(page.getByText('You have control')).toBeVisible()
    await page.locator('.managed-terminal').click()
    await page.keyboard.type('echo e2e-console-output')
    await page.keyboard.press('Enter')
    await expect.poll(async () => {
      const result = await (await page.request.get(`/api/v1/projects/${projectId}/runs/${launched.id}/events`)).json()
      return result.events.map((e: { data: string }) => e.data).join('')
    }, { timeout: 15000 }).toContain('e2e-console-output')
    await page.getByRole('button', { name: 'Detach', exact: true }).click()
    await expect.poll(async () => (await (await page.request.get(`/api/v1/projects/${projectId}/sessions/interactive/${sid}`)).json()).status).toBe('active')
    await page.goto(`/projects/${projectId}/terminal/sessions?session=${sid}`)
    await expect(page.getByText('You have control')).toBeVisible()
  } finally {
    if (sid) await page.request.delete(`/api/v1/projects/${projectId}/sessions/interactive/${sid}`, { headers })
    await page.request.delete(`/api/v1/docker/tools/${key}`, { headers })
  }
})

function sourceTar() {
  const content = Buffer.from('harmless PoC source fixture\n')
  const header = Buffer.alloc(512)
  header.write('message.txt', 0); header.write('0000644\0', 100); header.write('0000000\0', 108); header.write('0000000\0', 116)
  header.write(content.length.toString(8).padStart(11, '0') + '\0', 124)
  header.write('00000000000\0', 136); header.fill(32, 148, 156); header[156] = 48
  header.write([...header].reduce((a, b) => a + b, 0).toString(8).padStart(6, '0') + '\0 ', 148)
  return Buffer.concat([header, content, Buffer.alloc(512 - content.length), Buffer.alloc(1024)])
}

test('PoC source archives build and register a pinned tool through the dialog', async ({ page }) => {
  const { projectId, headers } = await login(page)
  const key = `e2e_poc_${Date.now()}`
  await page.goto(`/projects/${projectId}/network/transforms`)
  await page.getByLabel('Transform options').click()
  await page.getByRole('button', { name: 'Register PoC', exact: true }).click()
  const dialog = page.getByRole('dialog', { name: 'Register a PoC' })
  await dialog.getByLabel('Tool key').fill(key)
  await dialog.getByLabel('Display name', { exact: true }).fill('E2E PoC fixture')
  await dialog.getByRole('combobox', { name: 'Source', exact: true }).selectOption('archive')
  await dialog.getByLabel('Source archive', { exact: true }).setInputFiles({ name: 'source.tar', mimeType: 'application/x-tar', buffer: sourceTar() })
  await dialog.getByLabel('Command', { exact: true }).fill('cat /poc/message.txt')
  await dialog.getByRole('textbox', { name: 'Dockerfile', exact: true }).fill('FROM nginx:1.27-alpine\nCOPY . /poc\n')
  await dialog.getByRole('button', { name: 'Build and register PoC' }).click()
  await dialog.getByRole('link', { name: 'Open build logs and status' }).click()
  try {
    await expect.poll(async () => {
      const tools = await (await page.request.get('/api/v1/docker/tools')).json()
      return tools.find((t: { key: string }) => t.key === key)?.source_metadata?.kind
    }, { timeout: 25000 }).toBe('archive')
    const registered = (await (await page.request.get('/api/v1/docker/tools')).json()).find((item: { key: string }) => item.key === key)
    expect(registered.image_present).toBe(true)
    expect(registered.update_status).toBe('current')
    await expect(page.locator('.runtime-detail')).toContainText('completed', { timeout: 10000 })
  } finally {
    await page.request.delete(`/api/v1/docker/tools/${key}`, { headers })
  }
})
