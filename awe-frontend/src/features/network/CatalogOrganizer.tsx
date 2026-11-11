import { useEffect, useRef, useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { catalog, type CatalogOrganization } from '../../api/catalog'
import { categoryPath } from './catalogOrganization'
import './catalog-organization.css'

export interface CatalogEntry { key: string; name: string; categoryId: string; kind: string }

export function CatalogOrganizer({ projectId, organization, entries, open, initialSelection, onClose }: { projectId: string; organization?: CatalogOrganization; entries: CatalogEntry[]; open: boolean; initialSelection: string[]; onClose: () => void }) {
  const ref = useRef<HTMLDialogElement>(null)
  const qc = useQueryClient()
  const [tab, setTab] = useState('Categories')
  const [editing, setEditing] = useState('')
  const [name, setName] = useState('')
  const [parent, setParent] = useState('')
  const [destination, setDestination] = useState('')
  const [selection, setSelection] = useState<string[]>([])
  const [search, setSearch] = useState('')
  const [message, setMessage] = useState('')
  const save = useMutation({ mutationFn: (action: () => Promise<CatalogOrganization>) => action(), onSuccess: data => { qc.setQueryData(['catalog-organization', projectId], data); void qc.invalidateQueries({ queryKey: ['catalog-organization'] }); setMessage('Catalog organization saved.'); setSelection([]) } })
  useEffect(() => {
    if (open) {
      setTab(initialSelection.length ? 'Placement' : 'Categories'); setSelection(initialSelection); setSearch(initialSelection.length === 1 ? entries.find(item => item.key === initialSelection[0])?.name || '' : ''); setMessage(''); setEditing(''); setName(''); setParent(''); setDestination(''); save.reset()
      if (!ref.current?.open) ref.current?.showModal()
    } else ref.current?.close()
    // Reset the dialog only when it is opened, not when polling updates its data.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open])
  const categories = [...(organization?.categories || [])].sort((a, b) => categoryPath(organization, a.id).localeCompare(categoryPath(organization, b.id)))
  const descendants = (id: string): string[] => categories.filter(item => item.parent_id === id).flatMap(item => [item.id, ...descendants(item.id)])
  const invalidParents = new Set(editing ? [editing, ...descendants(editing)] : [])
  const visible = entries.filter(item => `${item.name} ${item.kind} ${categoryPath(organization, item.categoryId)}`.toLowerCase().includes(search.toLowerCase()))
  const selectCategory = (id: string) => { const category = categories.find(item => item.id === id); setEditing(id); setName(category?.name || ''); setParent(category?.parent_id || ''); setMessage(''); save.reset() }
  const commit = (action: () => Promise<CatalogOrganization>) => { setMessage(''); save.mutate(action) }
  const saveCategory = () => commit(async () => {
    if (editing) return catalog.update(projectId, editing, name, parent || null)
    const data = await catalog.create(projectId, name, parent || null)
    setName('')
    return data
  })

  return <dialog ref={ref} className="graph-tool-dialog catalog-organizer" aria-labelledby="catalog-organizer-title" onClose={onClose}>
    <header><div><b id="catalog-organizer-title">Manage categories</b><p>Organize tools and transforms into your own categories and subcategories.</p></div><button type="button" className="subtle" aria-label="Close category manager" onClick={onClose}>×</button></header>
    <nav className="catalog-organizer-tabs" aria-label="Category management"><button aria-pressed={tab === 'Categories'} onClick={() => setTab('Categories')}>Categories</button><button aria-pressed={tab === 'Placement'} onClick={() => setTab('Placement')}>Placement</button></nav>
    {!organization ? <p className="muted">Loading organization…</p> : <div className="catalog-organizer-content">
      {save.isError && <p className="error" role="alert">{save.error.message}</p>}{message && <p className="success" role="status">{message}</p>}
      {tab === 'Categories' ? <form onSubmit={event => { event.preventDefault(); saveCategory() }}>
        <label>Category to edit<select aria-label="Category to edit" value={editing} onChange={event => selectCategory(event.target.value)}><option value="">New category</option>{categories.map(item => <option key={item.id} value={item.id}>{categoryPath(organization, item.id)}</option>)}</select></label>
        <label>Category name<input required maxLength={80} value={name} onChange={event => setName(event.target.value)} placeholder="e.g. Exploits, Web, PHP" /></label>
        <label>Parent category<select aria-label="Parent category" disabled={editing === 'uncategorized'} value={parent} onChange={event => setParent(event.target.value)}><option value="">Top level</option>{categories.filter(item => !invalidParents.has(item.id)).map(item => <option key={item.id} value={item.id}>{categoryPath(organization, item.id)}</option>)}</select></label>
        <p className="muted">Rename a category or change its parent to move the whole branch. Deleting moves its items to the parent (or Uncategorized) and keeps child categories.</p>
        <footer>{editing && editing !== 'uncategorized' && <button type="button" className="danger" disabled={save.isPending} onClick={() => commit(async () => { const data = await catalog.remove(projectId, editing); setEditing(''); setName(''); setParent(''); return data })}>Delete category</button>}<button disabled={!name.trim() || save.isPending}>{save.isPending ? 'Saving…' : editing ? 'Save category' : 'Create category'}</button></footer>
      </form> : <section className="catalog-placement">
        <div className="catalog-placement-destination"><label>Destination category<select aria-label="Destination category" value={destination} onChange={event => setDestination(event.target.value)}><option value="">Choose a category</option>{categories.map(item => <option key={item.id} value={item.id}>{categoryPath(organization, item.id)}</option>)}</select></label><button disabled={!destination || !selection.length || save.isPending} onClick={() => commit(() => catalog.assign(projectId, selection, destination))}>{save.isPending ? 'Moving…' : `Move selected (${selection.length})`}</button></div>
        <input aria-label="Search catalog items to organize" placeholder="Find a tool, transform, or category…" value={search} onChange={event => setSearch(event.target.value)} />
        <label className="catalog-select-all"><input type="checkbox" checked={!!visible.length && visible.every(item => selection.includes(item.key))} onChange={event => setSelection(event.target.checked ? [...new Set([...selection, ...visible.map(item => item.key)])] : selection.filter(key => !visible.some(item => item.key === key)))} />Select visible items ({visible.length})</label>
        <div className="catalog-placement-list">{visible.map(item => <label key={item.key}><input type="checkbox" checked={selection.includes(item.key)} onChange={event => setSelection(current => event.target.checked ? [...current, item.key] : current.filter(key => key !== item.key))} /><span><b>{item.name}</b><small>{item.kind} · {categoryPath(organization, item.categoryId)}</small></span></label>)}{!visible.length && <p className="muted">No catalog items match your search.</p>}</div>
        <p className="muted">Tools and their corresponding transforms share a placement across projects. Composite transform placement belongs to its project.</p>
      </section>}
    </div>}
  </dialog>
}
