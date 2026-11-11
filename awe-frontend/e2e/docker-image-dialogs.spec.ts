import { expect, test } from '@playwright/test'

test('image pull and inline build actions open dialogs with local errors and build output', async ({ page }) => {
  await page.goto('/projects')
  await page.getByLabel('Username').fill(process.env.E2E_USERNAME!)
  await page.locator('input[autocomplete="current-password"]').fill(process.env.E2E_PASSWORD!)
  await page.getByRole('button', { name: 'Sign in' }).click()
  await expect(page.getByLabel('Dashboard options')).toBeVisible()
  const projectId = (await (await page.request.get('/api/v1/projects')).json())[0].id
  let pulls = 0
  let builds = 0
  let toolReads = 0
  let pullPayload: unknown
  let buildPayload: unknown
  await page.route('**/api/v1/docker/tools', route => { toolReads += 1; return route.fulfill({ json: [] }) })
  await page.route('**/api/v1/docker/images', route => route.fulfill({ json: [{ id: 'sha256:fixture', tags: ['awe/validation:1'], size_mb: 12.3 }] }))
  await page.route('**/api/v1/docker/images/pull', async route => {
    pulls += 1; pullPayload = route.request().postDataJSON()
    return pulls === 1 ? route.fulfill({ status: 400, json: { detail: 'Registry rejected this test reference' } }) : route.fulfill({ json: { id: 'sha256:pulled', tags: ['example/fixture:1'] } })
  })
  await page.route('**/api/v1/docker/images/build', async route => {
    builds += 1; buildPayload = route.request().postDataJSON()
    return builds === 1 ? route.fulfill({ status: 400, json: { detail: 'Invalid test Dockerfile' } }) : route.fulfill({ json: { id: 'sha256:built', tags: ['awe/dialog-fixture:1'], logs: ['Step 1: FROM scratch', 'Successfully built fixture'] } })
  })
  await page.goto(`/projects/${projectId}/docker`)
  await page.getByRole('tab', { name: 'Images', exact: true }).click()
  await expect(page.getByLabel('Image reference', { exact: true })).not.toBeVisible()
  await expect(page.getByLabel('Image tag', { exact: true })).not.toBeVisible()
  await expect(page.locator('.docker-action-form')).toHaveCount(0)
  await expect(page.getByRole('region', { name: 'Installed tool images' })).toContainText('Shared images appear once')
  await expect(page.getByRole('button', { name: 'Remove local image', exact: true })).toBeVisible()
  await page.getByLabel('Docker options').click()
  await page.getByRole('button', { name: 'Pull another image', exact: true }).click()
  const pull = page.getByRole('dialog', { name: 'Pull another image', exact: true })
  await expect(pull).toBeVisible()
  await pull.getByLabel('Image reference').fill('example/fixture:1')
  await pull.getByRole('button', { name: 'Pull image', exact: true }).click()
  await expect(pull.getByRole('alert')).toContainText('Registry rejected')
  await pull.getByRole('button', { name: 'Pull image', exact: true }).click()
  await expect(pull.getByRole('status')).toContainText('Pulled example/fixture:1')
  expect(pullPayload).toEqual({ image: 'example/fixture:1' })
  await expect.poll(() => toolReads).toBeGreaterThan(1)
  await page.keyboard.press('Escape')
  await expect(pull).not.toBeVisible()
  await page.getByLabel('Docker options').click()
  await page.getByRole('button', { name: 'Build an inline Dockerfile', exact: true }).click()
  const build = page.getByRole('dialog', { name: 'Build an inline Dockerfile', exact: true })
  await build.getByLabel('Image tag').fill('awe/dialog-fixture:1')
  const dockerfile = 'FROM scratch\nLABEL fixture="dialog"\n'
  await build.getByRole('textbox', { name: 'Dockerfile', exact: true }).fill(dockerfile)
  await build.getByRole('button', { name: 'Build image', exact: true }).click()
  await expect(build.getByRole('alert')).toContainText('Invalid test Dockerfile')
  await build.getByRole('button', { name: 'Build image', exact: true }).click()
  await expect(build.getByRole('status')).toContainText('Built awe/dialog-fixture:1')
  await expect(build.locator('pre')).toContainText('Successfully built fixture')
  expect(buildPayload).toEqual({ tag: 'awe/dialog-fixture:1', dockerfile })
  await page.setViewportSize({ width: 390, height: 844 })
  expect(await build.evaluate(element => element.scrollWidth - element.clientWidth)).toBeLessThanOrEqual(1)
  await build.getByRole('button', { name: 'Close build image dialog' }).click()
  await expect(build).not.toBeVisible()
})
