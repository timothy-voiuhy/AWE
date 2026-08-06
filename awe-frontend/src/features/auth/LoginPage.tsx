import { FormEvent, useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'

import { api } from '../../api/client'

export function LoginPage() {
  const queryClient = useQueryClient()
  const [username, setUsername] = useState('admin')
  const [password, setPassword] = useState('')
  const login = useMutation({
    mutationFn: () => api.login(username, password),
    onSuccess: (session) => queryClient.setQueryData(['auth', 'session'], session),
  })

  function submit(event: FormEvent) {
    event.preventDefault()
    login.mutate()
  }

  return (
    <main className="login-page">
      <section className="login-card">
        <div className="login-brand"><span>AW</span></div>
        <p className="eyebrow">Attack Workspace Environment</p>
        <h1>Sign in to AWE</h1>
        <p className="muted">Authentication is required before accessing targets, traffic, or tools.</p>
        <form onSubmit={submit}>
          <label>Username<input autoComplete="username" value={username} onChange={(event) => setUsername(event.target.value)} /></label>
          <label>Password<input autoComplete="current-password" type="password" value={password} onChange={(event) => setPassword(event.target.value)} autoFocus /></label>
          <button disabled={login.isPending}>{login.isPending ? 'Signing in…' : 'Sign in'}</button>
        </form>
        {login.isError && <p className="error">{login.error.message}</p>}
      </section>
    </main>
  )
}
