import { FormEvent, useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'

import { api } from '../../api/client'

export function SetupPage() {
  const queryClient = useQueryClient()
  const [username, setUsername] = useState('admin')
  const [password, setPassword] = useState('')
  const [confirmation, setConfirmation] = useState('')
  const mismatch = Boolean(confirmation) && password !== confirmation
  const setup = useMutation({
    mutationFn: () => api.setupAccount(username.trim(), password),
    onSuccess: (session) => {
      queryClient.setQueryData(['auth', 'session'], session)
      queryClient.setQueryData(['auth', 'setup-status'], { configured: true })
    },
  })

  function submit(event: FormEvent) {
    event.preventDefault()
    if (password.length >= 12 && password === confirmation && username.trim()) setup.mutate()
  }

  return (
    <main className="login-page">
      <section className="login-card setup-card">
        <div className="login-brand"><span>AW</span></div>
        <p className="eyebrow">First-run setup</p>
        <h1>Create your local account</h1>
        <p className="muted">This account protects projects, proxy traffic, credentials, and tool execution. Its password hash stays on this AWE host.</p>
        <form onSubmit={submit}>
          <label>Username<input autoComplete="username" value={username} onChange={(event) => setUsername(event.target.value)} required /></label>
          <label>Password<input autoComplete="new-password" type="password" minLength={12} value={password} onChange={(event) => setPassword(event.target.value)} required /><small>Use at least 12 characters.</small></label>
          <label>Confirm password<input autoComplete="new-password" type="password" minLength={12} value={confirmation} onChange={(event) => setConfirmation(event.target.value)} required /></label>
          <button disabled={setup.isPending || mismatch || password.length < 12}>{setup.isPending ? 'Creating account…' : 'Create account'}</button>
        </form>
        {mismatch && <p className="error">Passwords do not match.</p>}
        {setup.isError && <p className="error">{setup.error.message}</p>}
      </section>
    </main>
  )
}
