import { FormEvent, useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'

import { api } from '../../api/client'

export function LoginPage() {
  const queryClient = useQueryClient()
  const [username, setUsername] = useState('admin')
  const [password, setPassword] = useState('')
  const [showPassword, setShowPassword] = useState(false)
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
          <label>Password<span className="password-field"><input autoComplete="current-password" type={showPassword ? 'text' : 'password'} value={password} onChange={(event) => setPassword(event.target.value)} autoFocus /><button type="button" aria-label={showPassword ? 'Hide password' : 'Show password'} aria-pressed={showPassword} onClick={() => setShowPassword((value) => !value)}>{showPassword ? <svg viewBox="0 0 24 24" aria-hidden="true"><path d="m3 3 18 18" /><path d="M10.6 10.6a2 2 0 0 0 2.8 2.8" /><path d="M9.9 5.1A10.4 10.4 0 0 1 12 5c5.5 0 9 5 9 7a8.7 8.7 0 0 1-2.1 3.2" /><path d="M6.6 6.7C4.3 8.1 3 10.5 3 12c0 2 3.5 7 9 7a10 10 0 0 0 4.1-.9" /></svg> : <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M2.5 12S6 5 12 5s9.5 7 9.5 7S18 19 12 19s-9.5-7-9.5-7Z" /><circle cx="12" cy="12" r="3" /></svg>}</button></span></label>
          <button disabled={login.isPending}>{login.isPending ? 'Signing in…' : 'Sign in'}</button>
        </form>
        {login.isError && <p className="error">{login.error.message}</p>}
      </section>
    </main>
  )
}
