import { useEffect, useMemo, useRef, useState } from 'react'
import { useMutation, useQuery } from '@tanstack/react-query'
import { useParams } from 'react-router-dom'

import { api, type EvidenceRecord, type ReportGenerateRequest, type ReportSeverity, type ReportTemplate, type StoredResult } from '../../api/client'
import { MarkdownContent } from '../docs/MarkdownContent'

const severities: ReportSeverity[] = ['informational', 'low', 'medium', 'high', 'critical']
const templates: Array<{ value: ReportTemplate; label: string }> = [
  { value: 'hackerone', label: 'HackerOne' },
  { value: 'bugcrowd', label: 'Bugcrowd' },
  { value: 'general', label: 'General' },
]

const emptyReport: ReportGenerateRequest = {
  template: 'hackerone',
  result_ids: [],
  evidence_ids: [],
  title: '',
  weakness: '',
  severity: 'medium',
  asset: '',
  vulnerability_type: '',
  affected_component: '',
  attacker: 'an unauthenticated attacker',
  impact: '',
  steps_to_reproduce: '',
  remediation: '',
  include_evidence: true,
  include_raw: false,
  include_project_notes: false,
  include_methodology_notes: true,
}

function displayValue(value: unknown): string {
  if (value === null || value === undefined || value === '') return ''
  if (Array.isArray(value)) return value.map(displayValue).filter(Boolean).join(', ')
  if (typeof value === 'object') return JSON.stringify(value)
  return String(value)
}

function resultLabel(result: StoredResult): string {
  const data = result.data
  return displayValue(data.url ?? data.domain ?? data.host ?? data.name ?? data.path ?? data.endpoint ?? data.template_id ?? data.value) || result.result_key
}

function evidenceLabel(record: EvidenceRecord): string {
  return record.title || record.summary || record.id
}

function downloadMarkdown(title: string, markdown: string) {
  const slug = (title || 'awe-report').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '') || 'awe-report'
  const url = URL.createObjectURL(new Blob([markdown], { type: 'text/markdown;charset=utf-8' }))
  const link = document.createElement('a')
  link.href = url
  link.download = `${slug}.md`
  link.click()
  URL.revokeObjectURL(url)
}

export function ReportPage() {
  const { projectId = '' } = useParams()
  const [draft, setDraft] = useState<ReportGenerateRequest>(emptyReport)
  const [markdown, setMarkdown] = useState('')
  const [activePreview, setActivePreview] = useState<'edit' | 'preview'>('edit')
  const [copied, setCopied] = useState(false)
  const initialized = useRef(false)

  const project = useQuery({ queryKey: ['projects', projectId], queryFn: () => api.getProject(projectId), enabled: Boolean(projectId) })
  const results = useQuery({ queryKey: ['projects', projectId, 'results'], queryFn: () => api.listProjectResults(projectId), enabled: Boolean(projectId) })
  const evidence = useQuery({ queryKey: ['projects', projectId, 'evidence'], queryFn: () => api.listEvidence(projectId), enabled: Boolean(projectId) })

  useEffect(() => {
    if (!project.data || draft.asset) return
    setDraft((current) => ({ ...current, asset: project.data.target || project.data.name }))
  }, [draft.asset, project.data])

  useEffect(() => {
    if (initialized.current || !results.data || !evidence.data) return
    const selectedResults = results.data
      .filter((item) => item.category === 'vuln' || displayValue(item.data.severity))
      .slice(0, 25)
      .map((item) => item.id)
    const selectedEvidence = evidence.data
      .filter((item) => item.kind === 'finding' || item.tags.some((tag) => ['finding', 'vulnerability', 'poc'].includes(tag.toLowerCase())))
      .slice(0, 20)
      .map((item) => item.id)
    setDraft((current) => ({ ...current, result_ids: selectedResults, evidence_ids: selectedEvidence }))
    initialized.current = true
  }, [evidence.data, results.data])

  const generate = useMutation({
    mutationFn: () => api.generateReport(projectId, draft),
    onSuccess: (response) => {
      setMarkdown(response.markdown)
      setActivePreview('edit')
    },
  })

  const selectedResultCount = draft.result_ids.length
  const selectedEvidenceCount = draft.evidence_ids.length
  const resultBuckets = useMemo(() => {
    const buckets = new Map<string, StoredResult[]>()
    for (const item of results.data ?? []) {
      const list = buckets.get(item.category) ?? []
      list.push(item)
      buckets.set(item.category, list)
    }
    return [...buckets.entries()].sort((a, b) => a[0].localeCompare(b[0]))
  }, [results.data])

  function update<K extends keyof ReportGenerateRequest>(key: K, value: ReportGenerateRequest[K]) {
    setDraft((current) => ({ ...current, [key]: value }))
  }

  function toggleResult(id: string) {
    setDraft((current) => ({
      ...current,
      result_ids: current.result_ids.includes(id) ? current.result_ids.filter((item) => item !== id) : [...current.result_ids, id],
    }))
  }

  function toggleEvidence(id: string) {
    setDraft((current) => ({
      ...current,
      evidence_ids: current.evidence_ids.includes(id) ? current.evidence_ids.filter((item) => item !== id) : [...current.evidence_ids, id],
    }))
  }

  async function copyReport() {
    await navigator.clipboard.writeText(markdown)
    setCopied(true)
    window.setTimeout(() => setCopied(false), 1200)
  }

  return <main className="page report-page">
    <header className="page-header report-header"><div><p className="eyebrow">Submission package</p><h1>Reports</h1><p className="muted">Build program-ready Markdown from selected workspace findings, evidence, notes, and methodology context.</p></div><span className="result-total">{selectedResultCount + selectedEvidenceCount} attached</span></header>

    <section className="report-workbench">
      <form className="panel report-form" onSubmit={(event) => { event.preventDefault(); generate.mutate() }}>
        <header><b>Report Details</b><span>{draft.template}</span></header>
        <div className="report-field-grid">
          <label>Template<select value={draft.template} onChange={(event) => update('template', event.target.value as ReportTemplate)}>{templates.map((item) => <option key={item.value} value={item.value}>{item.label}</option>)}</select></label>
          <label>Severity<select value={draft.severity} onChange={(event) => update('severity', event.target.value as ReportSeverity)}>{severities.map((item) => <option key={item} value={item}>{item}</option>)}</select></label>
          <label className="wide">Title<input value={draft.title} onChange={(event) => update('title', event.target.value)} placeholder="Leave empty to generate one" /></label>
          <label>Asset<input value={draft.asset} onChange={(event) => update('asset', event.target.value)} placeholder="https://target.example" /></label>
          <label>Component<input value={draft.affected_component} onChange={(event) => update('affected_component', event.target.value)} placeholder="/api/v1/resource" /></label>
          <label>Vulnerability Type<input value={draft.vulnerability_type} onChange={(event) => update('vulnerability_type', event.target.value)} placeholder="IDOR, XSS, SSRF..." /></label>
          <label>Weakness<input value={draft.weakness} onChange={(event) => update('weakness', event.target.value)} placeholder="CWE-639, CWE-79..." /></label>
          <label className="wide">Attacker<input value={draft.attacker} onChange={(event) => update('attacker', event.target.value)} /></label>
          <label className="wide">Steps to Reproduce<textarea value={draft.steps_to_reproduce} onChange={(event) => update('steps_to_reproduce', event.target.value)} placeholder={'1. Log in as...\n2. Send the request...\n3. Observe...'} /></label>
          <label className="wide">Impact<textarea value={draft.impact} onChange={(event) => update('impact', event.target.value)} /></label>
          <label className="wide">Remediation<textarea value={draft.remediation} onChange={(event) => update('remediation', event.target.value)} /></label>
        </div>
        <div className="report-options">
          <label><input type="checkbox" checked={draft.include_evidence} onChange={(event) => update('include_evidence', event.target.checked)} /> Evidence blocks</label>
          <label><input type="checkbox" checked={draft.include_methodology_notes} onChange={(event) => update('include_methodology_notes', event.target.checked)} /> Methodology notes</label>
          <label><input type="checkbox" checked={draft.include_project_notes} onChange={(event) => update('include_project_notes', event.target.checked)} /> Project notes</label>
          <label><input type="checkbox" checked={draft.include_raw} onChange={(event) => update('include_raw', event.target.checked)} /> Raw JSON</label>
        </div>
        <button disabled={generate.isPending}>{generate.isPending ? 'Generating...' : 'Generate Report'}</button>
        {generate.isError && <p className="error">Report generation failed. Check the selected records and backend logs.</p>}
      </form>

      <section className="panel report-attachments">
        <header><b>Attachments</b><span>{selectedResultCount} results · {selectedEvidenceCount} evidence</span></header>
        <div className="report-attachment-list">
          <details open>
            <summary>Results <span>{results.data?.length ?? 0}</span></summary>
            {resultBuckets.map(([category, rows]) => <div className="report-result-bucket" key={category}>
              <b>{category}</b>
              {rows.slice(0, 80).map((item) => <label key={item.id}><input type="checkbox" checked={draft.result_ids.includes(item.id)} onChange={() => toggleResult(item.id)} /><span>{resultLabel(item)}</span><em>{item.sources.join(', ') || item.category}</em></label>)}
            </div>)}
          </details>
          <details open>
            <summary>Evidence <span>{evidence.data?.length ?? 0}</span></summary>
            {(evidence.data ?? []).map((item) => <label key={item.id}><input type="checkbox" checked={draft.evidence_ids.includes(item.id)} onChange={() => toggleEvidence(item.id)} /><span>{evidenceLabel(item)}</span><em>{item.kind}</em></label>)}
          </details>
        </div>
      </section>

      <section className="panel report-output">
        <header><div><b>Markdown</b><span>{generate.data ? `${generate.data.result_count} results · ${generate.data.evidence_count} evidence` : 'No report generated'}</span></div><nav><button type="button" className={activePreview === 'edit' ? 'selected' : ''} onClick={() => setActivePreview('edit')}>Edit</button><button type="button" className={activePreview === 'preview' ? 'selected' : ''} onClick={() => setActivePreview('preview')}>Preview</button></nav></header>
        {generate.data?.warnings.length ? <div className="report-warnings">{generate.data.warnings.map((warning) => <span key={warning}>{warning}</span>)}</div> : null}
        {activePreview === 'edit'
          ? <textarea value={markdown} onChange={(event) => setMarkdown(event.target.value)} placeholder="Generated report Markdown appears here." />
          : <div className="report-preview"><MarkdownContent source={markdown || 'Generate a report to preview Markdown.'} /></div>}
        <footer><button className="secondary-button" type="button" onClick={copyReport} disabled={!markdown}>{copied ? 'Copied' : 'Copy Markdown'}</button><button type="button" onClick={() => downloadMarkdown(generate.data?.title || draft.title, markdown)} disabled={!markdown}>Download .md</button></footer>
      </section>
    </section>
  </main>
}
