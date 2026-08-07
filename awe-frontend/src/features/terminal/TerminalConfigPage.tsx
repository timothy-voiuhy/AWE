import { ChangeEvent, FormEvent, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, TerminalProfile } from '../../api/client'

const rejectedKeyExtensions = new Set([
  '7z', 'avi', 'bmp', 'doc', 'docx', 'exe', 'gif', 'gz', 'jpeg', 'jpg', 'mov',
  'mp3', 'mp4', 'pdf', 'png', 'ppt', 'pptx', 'rar', 'svg', 'tar', 'webp', 'xls',
  'xlsx', 'zip',
])

export function TerminalConfigPage() {
  const { projectId = '' } = useParams()
  const qc = useQueryClient()
  const profiles = useQuery({ queryKey: ['terminal-profiles', projectId], queryFn: () => api.listTerminalProfiles(projectId) })
  const [editingId, setEditingId] = useState<string | null>(null)
  const [name, setName] = useState('')
  const [host, setHost] = useState('')
  const [port, setPort] = useState(22)
  const [username, setUsername] = useState('')
  const [privateKey, setPrivateKey] = useState('')
  const [passphrase, setPassphrase] = useState('')
  const [notice, setNotice] = useState('')

  const keyStorage = (profileId: string) => `awe-terminal-key-${projectId}-${profileId}`
  const passphraseStorage = (profileId: string) => `awe-terminal-pass-${projectId}-${profileId}`

  function resetForm() {
    setEditingId(null); setName(''); setHost(''); setPort(22); setUsername(''); setPrivateKey(''); setPassphrase('')
  }

  function retainLocalCredentials(profile: TerminalProfile) {
    if (privateKey) {
      sessionStorage.setItem(keyStorage(profile.id), privateKey)
      sessionStorage.setItem(passphraseStorage(profile.id), passphrase)
    } else {
      sessionStorage.removeItem(keyStorage(profile.id))
      sessionStorage.removeItem(passphraseStorage(profile.id))
    }
  }

  const save = useMutation({
    mutationFn: () => {
      const data = { name: name || host, host, port, username }
      return editingId ? api.updateTerminalProfile(projectId, editingId, data) : api.createTerminalProfile(projectId, data)
    },
    onSuccess: profile => {
      const wasEditing = Boolean(editingId)
      retainLocalCredentials(profile)
      resetForm()
      setNotice(`Profile ${wasEditing ? 'updated' : 'saved'}. Private keys remain only on this device.`)
      void qc.invalidateQueries({ queryKey: ['terminal-profiles', projectId] })
    },
  })

  const remove = useMutation({
    mutationFn: (id: string) => api.deleteTerminalProfile(projectId, id),
    onSuccess: (_, id) => {
      sessionStorage.removeItem(keyStorage(id)); sessionStorage.removeItem(passphraseStorage(id))
      if (editingId === id) resetForm()
      void qc.invalidateQueries({ queryKey: ['terminal-profiles', projectId] })
    },
  })

  function edit(profile: TerminalProfile) {
    setEditingId(profile.id); setName(profile.name); setHost(profile.host); setPort(profile.port); setUsername(profile.username)
    setPrivateKey(sessionStorage.getItem(keyStorage(profile.id)) || '')
    setPassphrase(sessionStorage.getItem(passphraseStorage(profile.id)) || '')
    setNotice('')
  }

  function readKey(e: ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0]
    if (!file) return
    e.target.value = ''
    if (file.size > 100_000) { setNotice('Private keys are limited to 100 KB.'); return }
    const extension = file.name.includes('.') ? file.name.split('.').pop()!.toLowerCase() : ''
    if (rejectedKeyExtensions.has(extension) || /^(image|audio|video)\//.test(file.type)) {
      setNotice('That file type is not suitable for an SSH private key.'); return
    }
    const reader = new FileReader()
    reader.onload = () => { setPrivateKey(String(reader.result || '')); setNotice('Private key loaded on this device.') }
    reader.readAsText(file)
  }

  function submit(e: FormEvent) { e.preventDefault(); save.mutate() }

  return <main className="page feature-page terminal-config-page">
    <Link className="back-link" to={`/projects/${projectId}/terminal`}>← Terminal</Link>
    <header className="page-header"><div><p className="eyebrow">Remote operations</p><h1>Terminal configuration</h1><p className="muted">Profiles sync across devices. Private keys remain session-only on the device where they are loaded.</p></div></header>
    <section className="terminal-config-grid">
      <form className="panel terminal-profile-form" onSubmit={submit}>
        <h3>{editingId ? 'Edit connection profile' : 'New connection profile'}</h3>
        <input value={name} onChange={e => setName(e.target.value)} placeholder="Profile name (optional)" />
        <div className="inline-fields"><input value={host} onChange={e => setHost(e.target.value)} placeholder="Host or IP" required /><input type="number" value={port} onChange={e => setPort(Number(e.target.value))} min="1" max="65535" /></div>
        <input value={username} onChange={e => setUsername(e.target.value)} placeholder="Username" required />
        <div className="key-dropzone"><span className="key-icon">⌁</span><b>{privateKey ? 'Private key loaded' : 'Choose or paste a private key'}</b><small>{privateKey ? 'Ready for the next terminal session' : 'Extensionless, PEM, OpenSSH, and other text key files are supported'}</small><label className="file-button">Choose key file<input type="file" onChange={readKey} /></label><textarea value={privateKey} onChange={e => setPrivateKey(e.target.value)} placeholder="Paste private SSH key here" /></div>
        <input type="password" value={passphrase} onChange={e => setPassphrase(e.target.value)} placeholder="Key passphrase (optional)" disabled={!privateKey} />
        <div className="terminal-form-actions"><button disabled={!host || !username || save.isPending}>{save.isPending ? 'Saving…' : editingId ? 'Update profile' : 'Save profile'}</button>{editingId && <button type="button" className="subtle" onClick={resetForm}>Cancel</button>}</div>
        {notice && <p className="success">{notice}</p>}{save.isError && <p className="error">{(save.error as Error).message}</p>}
      </form>
      <section className="panel terminal-profile-list">
        <header><h3>Saved profiles</h3><span>{profiles.data?.length ?? 0}</span></header>
        {profiles.data?.map(profile => <article key={profile.id}><div><b>{profile.name}</b><span>{profile.username}@{profile.host}:{profile.port}</span></div><footer><button onClick={() => edit(profile)}>Edit</button><button className="danger" onClick={() => remove.mutate(profile.id)}>Remove</button></footer></article>)}
        {!profiles.data?.length && <div className="empty">No connection profiles yet.</div>}
      </section>
    </section>
  </main>
}
