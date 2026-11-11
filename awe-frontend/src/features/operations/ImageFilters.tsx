import { useState, type ReactNode } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { api, type DockerTool, type DockerImage } from '../../api/client'
import './image-filters.css'

type Filter = 'all' | 'installed' | 'uninstalled' | 'outdated'
const filters: Array<[Filter, string]> = [['all', 'All'], ['installed', 'Installed'], ['uninstalled', 'Uninstalled'], ['outdated', 'Outdated']]

function reference(value: string) {
  const parts = value.replace(/^(?:index\.)?docker\.io\//, '').split('/')
  if (!parts[parts.length - 1].includes(':') && !value.includes('@')) parts[parts.length - 1] += ':latest'
  if (parts.length === 1) parts.unshift('library')
  if (!/[.:]/.test(parts[0]) && parts[0] !== 'localhost') parts.unshift('docker.io')
  return parts.join('/')
}

export function imageStatus(tool: DockerTool) {
  if (!tool.image_present) return '○ Uninstalled'
  if (tool.update_status === 'outdated') return '● Outdated'
  if (tool.update_status === 'current') return '● Installed · current'
  return `● Installed · ${tool.update_status === 'unknown' ? 'update unknown' : 'updates not checked'}`
}

export function ImageFilters({ tools, images, children }: { tools: DockerTool[]; images: DockerImage[]; children: (tools: DockerTool[], images: DockerImage[], showInventory: boolean) => ReactNode }) {
  const [filter, setFilter] = useState<Filter>('all')
  const qc = useQueryClient()
  const check = useMutation({ mutationFn: api.checkImageUpdates, onSuccess: () => qc.invalidateQueries({ queryKey: ['docker', 'tools'] }) })
  const matches = (tool: DockerTool, value: Filter) => value === 'all' || (value === 'installed' ? tool.image_present : value === 'uninstalled' ? !tool.image_present : tool.image_present && tool.update_status === 'outdated')
  const visible = tools.filter(tool => matches(tool, filter))
  const tags = new Set(visible.map(tool => reference(tool.image)))
  const visibleImages = filter === 'all' ? images : images.filter(image => image.tags.some(tag => tags.has(reference(tag))))
  return <>
    <div className="image-filter-toolbar"><div role="group" aria-label="Filter images">{filters.map(([value, label]) => <button key={value} type="button" className={filter === value ? 'selected' : 'subtle'} aria-pressed={filter === value} onClick={() => setFilter(value)}>{label}<span>{new Set(tools.filter(tool => matches(tool, value)).map(tool => reference(tool.image))).size}</span></button>)}</div><button type="button" className="subtle" onClick={() => check.mutate()} disabled={check.isPending}>{check.isPending ? 'Checking updates…' : 'Check updates'}</button></div>
    <p className="image-filter-hint">Counts are unique image references; shared tool cards use the same status. Outdated means a changed registry digest or changed build sources. Unknown images need a check or an initial rebuild.</p>
    {check.isError && <p className="error" role="alert">{check.error.message}</p>}
    {check.isSuccess && <p className="image-filter-hint" role="status">Update check complete. Registry failures and missing provenance are shown as unknown. Registry results expire after 15 minutes.</p>}
    {!visible.length && <p className="muted">No {filter === 'all' ? '' : `${filter} `}tool images.</p>}
    {children(visible, visibleImages, filter !== 'uninstalled')}
  </>
}
