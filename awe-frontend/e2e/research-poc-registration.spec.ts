import { readFileSync } from 'node:fs'
import { execFileSync } from 'node:child_process'
import { expect, test } from '@playwright/test'

// Explicit opt-in: this builds third-party sources and retains two global tools.
test.skip(process.env.AWE_REGISTER_RESEARCH_POCS !== '1', 'Set AWE_REGISTER_RESEARCH_POCS=1 to register the research PoCs')

test('register pinned research PoCs through the dialog and validate offline CLI help', async ({ page }) => {
  test.setTimeout(600_000)
  await page.goto('/projects')
  await page.getByLabel('Username').fill(process.env.E2E_USERNAME!)
  await page.locator('input[autocomplete="current-password"]').fill(process.env.E2E_PASSWORD!)
  await page.getByRole('button', { name: 'Sign in' }).click()
  await expect(page.getByLabel('Dashboard options')).toBeVisible()
  const csrf = (await page.context().cookies()).find(c => c.name === 'awe_csrf')!.value
  const headers = { 'X-AWE-CSRF': decodeURIComponent(csrf) }
  const projects = await (await page.request.get('/api/v1/projects')).json()
  let projectId = process.env.AWE_POC_PROJECT_ID || projects.find((p: { name: string }) => p.name === 'PoC registrations')?.id
  if (!projectId) {
    const created = await page.request.post('/api/v1/projects', { headers, data: { name: 'PoC registrations', target: '' } })
    expect(created.ok()).toBeTruthy()
    projectId = (await created.json()).id
  }

  for (const name of ['nginx_rift', 'php2shell']) {
    const definition = JSON.parse(readFileSync(new URL(`../../examples/pocs/${name}.json`, import.meta.url), 'utf8'))
    await page.goto(`/projects/${projectId}/network/transforms?view=tools`)
    await page.getByLabel('Transform options').click()
    await page.getByRole('button', { name: 'Register PoC', exact: true }).click()
    const dialog = page.getByRole('dialog', { name: 'Register a PoC' })
    await dialog.getByLabel('Tool key').fill(definition.key)
    await dialog.getByLabel('Display name', { exact: true }).fill(definition.display_name)
    await dialog.getByLabel('Repository URL').fill(definition.repository)
    await dialog.getByLabel('Revision', { exact: true }).fill(definition.revision)
    await dialog.getByLabel('Command', { exact: true }).fill(definition.command_template)
    await dialog.getByRole('textbox', { name: 'Dockerfile', exact: true }).fill(definition.dockerfile)
    await dialog.getByRole('textbox', { name: 'Parameters JSON', exact: true }).fill(JSON.stringify(definition.param_specs))
    await dialog.getByRole('combobox', { name: 'Execution kind', exact: true }).selectOption(definition.execution_kind)
    for (const channel of ['logs', 'structured', 'artifacts', 'session']) {
      await dialog.getByRole('checkbox', { name: channel, exact: true }).setChecked(definition.output_channels.includes(channel))
    }
    await dialog.getByRole('button', { name: 'Build and register PoC' }).click()
    await dialog.getByRole('link', { name: 'Open build logs and status' }).click()
    const runId = new URL(page.url()).pathname.split('/').pop()
    let run: { status?: string; message?: string } = {}
    await expect.poll(async () => {
      const response = await page.request.get(`/api/v1/projects/${projectId}/runs/${runId}`)
      expect(response.ok()).toBeTruthy()
      run = await response.json()
      return run.status
    }, { timeout: 240_000, intervals: [1000, 2000, 5000] }).not.toBe('running')
    expect(run.status, run.message).toBe('completed')
    await expect(page.locator('.runtime-detail')).toContainText('completed', { timeout: 10000 })
    const tools = await (await page.request.get('/api/v1/docker/tools')).json()
    const registered = tools.find((tool: { key: string }) => tool.key === name)
    expect(registered.source_metadata).toEqual({ kind: 'git', repository: definition.repository, revision: definition.revision })
    expect(registered.execution_kind).toBe(definition.execution_kind)
    expect(registered.output_channels).toEqual(definition.output_channels)
    expect(registered.execution_mode).toBe('high_risk')
    expect(registered.param_specs).toEqual(definition.param_specs)
    await page.goto(`/projects/${projectId}/network/transforms?view=tools`)
    await page.getByRole('button', { name: 'Search tools', exact: true }).click()
    await page.getByRole('searchbox', { name: 'Search tools catalog' }).fill(definition.key)
    const catalogEntry = page.locator('.graph-catalog-row').filter({ has: page.getByText(definition.display_name, { exact: true }) })
    await expect(catalogEntry).toContainText('Graph enabled')
    await expect(catalogEntry).toContainText(definition.execution_kind)

    const scripts = name === 'nginx_rift' ? ['/poc/Nginx-Rift/poc.py'] : ['/poc/poc/exploit_chain_a.py', '/poc/poc/exploit_chain_c.py']
    for (const script of scripts) {
      const help = execFileSync('docker', ['run', '--rm', '--network', 'none', '--read-only', registered.image, 'python', script, '--help'], { timeout: 30000, encoding: 'utf8' })
      expect(help).toContain('usage:')
    }
    console.log(`${definition.display_name}: registered ${definition.revision} in project ${projectId}; ${scripts.length} offline help checks passed`)
  }
})
