import { useRef, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'

import { api } from '../../api/client'

export function SubdomainImportPanel({ projectId, compact = false }: { projectId: string; compact?: boolean }) {
  const inputRef = useRef<HTMLInputElement>(null)
  const queryClient = useQueryClient()
  const [fileName, setFileName] = useState('')
  const [investigationId, setInvestigationId] = useState('')
  const [attachToGraph, setAttachToGraph] = useState(true)
  const [notice, setNotice] = useState('')

  const investigations = useQuery({ queryKey: ['projects', projectId, 'investigations'], queryFn: () => api.listInvestigations(projectId), enabled: Boolean(projectId) })
  const upload = useMutation({
    mutationFn: (file: File) => api.importSubdomains(projectId, file, { investigation_id: investigationId, attach_to_graph: attachToGraph }),
    onSuccess: result => {
      setNotice(`Imported ${result.imported} subdomains${result.duplicates ? ` · ${result.duplicates} duplicates` : ''}${result.graph_entities ? ` · ${result.graph_entities} graph entities` : ''}.`)
      setFileName('')
      if (inputRef.current) inputRef.current.value = ''
      void queryClient.invalidateQueries({ queryKey: ['projects', projectId, 'results'] })
      void queryClient.invalidateQueries({ queryKey: ['projects', projectId, 'sessions'] })
      void queryClient.invalidateQueries({ queryKey: ['projects', projectId, 'investigation-graph'] })
      void queryClient.invalidateQueries({ queryKey: ['projects', projectId, 'evidence'] })
    },
  })

  function pickFile(file?: File) {
    if (!file) return
    setFileName(file.name)
    upload.mutate(file)
  }

  return <section className={`panel subdomain-import-panel${compact ? ' compact' : ''}`}>
    <header><div><p className="eyebrow">Import</p><h2>Subdomains</h2><p className="muted">Load TXT, CSV, or XLSX files into Results and optionally attach them to the Network graph.</p></div></header>
    <div className="subdomain-import-controls">
      <input ref={inputRef} type="file" accept=".txt,.list,.csv,.xlsx,text/plain,text/csv,application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" onChange={event => pickFile(event.target.files?.[0])} />
      <select value={investigationId} onChange={event => setInvestigationId(event.target.value)} disabled={!attachToGraph}><option value="">Default investigation</option>{investigations.data?.map(item => <option value={item.id} key={item.id}>{item.name}</option>)}</select>
      <label><input type="checkbox" checked={attachToGraph} onChange={event => setAttachToGraph(event.target.checked)} /> Attach to graph</label>
    </div>
    {fileName && <small>Selected: {fileName}</small>}
    {upload.isPending && <p className="muted">Importing subdomains...</p>}
    {notice && <p className="success">{notice}</p>}
    {upload.isError && <p className="error">{upload.error.message}</p>}
  </section>
}
