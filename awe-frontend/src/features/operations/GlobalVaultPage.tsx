import { useEffect, useRef, useState, type ChangeEvent, type DragEvent, type FormEvent } from 'react'
import { Link } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, type VaultCategory, type VaultItemRecord } from '../../api/client'

const noteLanguages = ['txt', 'md', 'json', 'js', 'py', 'html', 'css', 'sql', 'yaml', 'xml', 'sh', 'http', 'c', 'cpp', 'go', 'rust', 'php', 'ruby']
const fileUrl = (id: string) => `/api/v1/vault/items/${encodeURIComponent(id)}/file`

function itemSubtitle(item: VaultItemRecord) {
  if (item.type === 'link') {
    try { return new URL(item.url || '').host.toUpperCase() || 'LINK' } catch { return 'LINK' }
  }
  if (item.type === 'note') return item.lang && item.lang !== 'txt' ? `NOTE · ${item.lang.toUpperCase()}` : 'NOTE'
  return item.type.toUpperCase()
}

export function GlobalVaultPage() {
  const qc = useQueryClient()
  const [cid, setCid] = useState('')
  const [name, setName] = useState('')
  const [accent, setAccent] = useState('#89b4fa')
  const [composer, setComposer] = useState<'link' | 'note' | null>(null)
  const [title, setTitle] = useState('')
  const [url, setUrl] = useState('')
  const [text, setText] = useState('')
  const [lang, setLang] = useState('txt')
  const fileInput = useRef<HTMLInputElement>(null)
  const categories = useQuery({ queryKey: ['vault', 'categories'], queryFn: api.listVaultCategories })
  const items = useQuery({ queryKey: ['vault', 'items', cid], queryFn: () => api.listVaultItems(cid), enabled: !!cid })
  useEffect(() => { if (!cid && categories.data?.[0]) setCid(categories.data[0].id) }, [cid, categories.data])

  const createCategory = useMutation({
    mutationFn: () => api.createVaultCategory({ name: name.trim(), accent }),
    onSuccess: category => { setName(''); setCid(category.id); void qc.invalidateQueries({ queryKey: ['vault', 'categories'] }) },
  })
  const updateCategory = useMutation({
    mutationFn: (category: VaultCategory) => api.updateVaultCategory(category.id, { name: category.name, accent: category.accent }),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ['vault', 'categories'] }),
  })
  const deleteCategory = useMutation({
    mutationFn: (id: string) => api.deleteVaultCategory(id),
    onSuccess: (_, id) => { if (id === cid) setCid(''); void qc.invalidateQueries({ queryKey: ['vault', 'categories'] }) },
  })
  const createItem = useMutation({
    mutationFn: () => composer === 'link'
      ? api.createVaultLink(cid, { type: 'link', title: title.trim(), url: url.trim() })
      : api.createVaultNote(cid, { type: 'note', title: title.trim(), text, lang }),
    onSuccess: () => { setTitle(''); setUrl(''); setText(''); setComposer(null); void qc.invalidateQueries({ queryKey: ['vault', 'items', cid] }) },
  })
  const upload = useMutation({
    mutationFn: (file: File) => api.uploadVaultFile(cid, file),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ['vault', 'items', cid] }),
  })
  const updateItem = useMutation({
    mutationFn: ({ item, next }: { item: VaultItemRecord; next: { title: string; text?: string; lang?: string } }) =>
      api.updateVaultItem(item.id, { type: item.type === 'note' ? 'note' : 'link', title: next.title, text: next.text, lang: next.lang, url: item.url }),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ['vault', 'items', cid] }),
  })
  const deleteItem = useMutation({ mutationFn: api.deleteVaultItem, onSuccess: () => void qc.invalidateQueries({ queryKey: ['vault', 'items', cid] }) })

  function resetComposer() { setComposer(null); setTitle(''); setUrl(''); setText(''); setLang('txt') }
  function submitCategory(event: FormEvent) { event.preventDefault(); if (name.trim()) createCategory.mutate() }
  function submitItem(event: FormEvent) { event.preventDefault(); if (cid && composer && (composer === 'link' ? url.trim() : text.trim())) createItem.mutate() }
  function addFiles(files: FileList | File[]) { if (!cid) return; Array.from(files).forEach(file => upload.mutate(file)) }
  function onDrop(event: DragEvent<HTMLElement>) { event.preventDefault(); addFiles(event.dataTransfer.files) }
  function onFileChange(event: ChangeEvent<HTMLInputElement>) { if (event.target.files) addFiles(event.target.files); event.target.value = '' }
  async function pasteClipboard() {
    if (!cid) return
    try {
      const clipboard = await navigator.clipboard.readText()
      if (!clipboard.trim()) return
      if (/^(https?:\/\/|www\.)\S+$/i.test(clipboard.trim())) api.createVaultLink(cid, { type: 'link', title: '', url: clipboard.trim() }).then(() => qc.invalidateQueries({ queryKey: ['vault', 'items', cid] }))
      else api.createVaultNote(cid, { type: 'note', title: clipboard.trim().split('\n')[0].slice(0, 48), text: clipboard, lang: 'txt' }).then(() => qc.invalidateQueries({ queryKey: ['vault', 'items', cid] }))
    } catch { setComposer('note'); setText('Clipboard access was unavailable. Paste the text here.') }
  }
  function editCategory(category: VaultCategory) {
    const nextName = window.prompt('Category name', category.name); if (nextName === null) return
    const nextAccent = window.prompt('Accent colour', category.accent) || category.accent
    updateCategory.mutate({ ...category, name: nextName.trim() || category.name, accent: nextAccent })
  }
  function editItem(item: VaultItemRecord) {
    const nextTitle = window.prompt('Title', item.title); if (nextTitle === null) return
    if (item.type === 'note') {
      const nextText = window.prompt('Note text', item.text || ''); if (nextText === null) return
      updateItem.mutate({ item, next: { title: nextTitle, text: nextText, lang: item.lang || 'txt' } })
    } else updateItem.mutate({ item, next: { title: nextTitle } })
  }
  function removeItem(item: VaultItemRecord) { if (window.confirm(`Delete “${item.title}”?`)) deleteItem.mutate(item.id) }
  function removeCategory(category: VaultCategory) { if (window.confirm(`Delete “${category.name}” and all its items?`)) deleteCategory.mutate(category.id) }

  const selected = categories.data?.find(category => category.id === cid)
  return <main className="page feature-page vault-page">
    <header className="page-header"><div><p className="eyebrow">Knowledge vault</p><h1>Vault</h1><p className="muted">Global categories for links, notes, images, PDFs, and files—shared across projects.</p></div></header>
    <section className="vault-workspace">
      <aside className="panel vault-categories"><header><b>Categories</b><span>{categories.data?.length ?? 0}</span></header>
        {categories.data?.map(category => <article className={`vault-category-card ${cid === category.id ? 'selected' : ''}`} key={category.id} onClick={() => setCid(category.id)}><i style={{ background: category.accent }} /><button type="button"><b>{category.name}</b><small>{cid === category.id ? `${items.data?.length ?? 0} item${items.data?.length === 1 ? '' : 's'}` : ' '}</small></button><nav><button type="button" title="Rename / recolour" onClick={event => { event.stopPropagation(); editCategory(category) }}>⋯</button><button type="button" className="danger" title="Delete" onClick={event => { event.stopPropagation(); removeCategory(category) }}>×</button></nav></article>)}
        <form onSubmit={submitCategory}><input required value={name} onChange={event => setName(event.target.value)} placeholder="New category"/><input className="vault-accent" type="color" value={accent} onChange={event => setAccent(event.target.value)} title="Category colour"/><button type="submit" disabled={createCategory.isPending}>Add</button></form>
      </aside>
      <section className="vault-content" onDragOver={event => event.preventDefault()} onDrop={onDrop}>
        {!selected ? <div className="panel empty">Create or select a category.</div> : <>
          <header className="vault-content-header"><div><h2>{selected.name}</h2><span>{items.data?.length ?? 0} item{items.data?.length === 1 ? '' : 's'}</span></div><div className="vault-actions"><button onClick={() => setComposer('link')}>＋ Link</button><button onClick={() => setComposer('note')}>＋ Note</button><button onClick={() => fileInput.current?.click()}>＋ File</button><button onClick={pasteClipboard}>Paste</button><input ref={fileInput} hidden type="file" multiple onChange={onFileChange} /></div></header>
          {composer && <form className="panel vault-composer" onSubmit={submitItem}><header><b>{composer === 'link' ? 'Add link' : 'Add note'}</b><button type="button" onClick={resetComposer}>Cancel</button></header><input value={title} onChange={event => setTitle(event.target.value)} placeholder={composer === 'link' ? 'Title (optional)' : 'Note title (optional)'}/>{composer === 'link' ? <input required type="url" value={url} onChange={event => setUrl(event.target.value)} placeholder="https://target.example"/> : <><select value={lang} onChange={event => setLang(event.target.value)}>{noteLanguages.map(value => <option key={value}>{value}</option>)}</select><textarea required value={text} onChange={event => setText(event.target.value)} placeholder="Note content" /></>}<button type="submit" disabled={createItem.isPending}>Save</button></form>}
          {!items.data?.length ? <div className="panel empty vault-empty">Nothing here yet. Use the actions above, paste content, or drag files onto this panel.</div> : <section className="vault-item-grid">{items.data.map(item => <article className="panel vault-item-card" key={item.id}>
            <div className="vault-item-preview">{item.type === 'image' ? <img src={fileUrl(item.id)} alt={item.title} /> : <span>{item.type === 'pdf' ? '▤' : item.type === 'link' ? '🔗' : item.type === 'note' ? '✎' : '⛃'}</span>}</div><header><b title={item.title}>{item.title}</b><small>{itemSubtitle(item)}</small></header>
            {item.type === 'link' && <a href={item.url} target="_blank" rel="noreferrer">Open link ↗</a>}{item.type === 'note' && <pre>{item.text}</pre>}{item.type === 'pdf' || item.type === 'file' ? <a href={fileUrl(item.id)} target="_blank" rel="noreferrer">Open / download ↗</a> : null}
            <footer><button onClick={() => editItem(item)}>Rename{item.type === 'note' ? ' / edit' : ''}</button><button className="danger" onClick={() => removeItem(item)}>Delete</button></footer>
          </article>)}</section>}
        </>}
      </section>
    </section><Link className="back-link" to="/projects">← Projects</Link>
  </main>
}
