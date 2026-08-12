import { useEffect, useRef, type ReactElement } from 'react'

export function createClientId(): string {
  const browserCrypto = globalThis.crypto
  if (typeof browserCrypto?.randomUUID === 'function') return browserCrypto.randomUUID()
  if (typeof browserCrypto?.getRandomValues === 'function') {
    const bytes = new Uint8Array(16)
    browserCrypto.getRandomValues(bytes)
    bytes[6] = (bytes[6] & 0x0f) | 0x40
    bytes[8] = (bytes[8] & 0x3f) | 0x80
    const hex = Array.from(bytes, (value) => value.toString(16).padStart(2, '0')).join('')
    return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`
  }
  return `awe-${Date.now().toString(36)}-${Math.random().toString(36).slice(2)}`
}

function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, (character) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[character]!)
}

function highlightBody(value: string): string {
  const token = /https?:\/\/[^\s"'<>]+|"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|\b(?:true|false|null)\b|-?\b\d+(?:\.\d+)?\b|[{}[\],:]/g
  let result = ''
  let cursor = 0
  for (const match of value.matchAll(token)) {
    const index = match.index ?? 0
    result += escapeHtml(value.slice(cursor, index))
    const text = match[0]
    let className = 'http-number'
    if (/^https?:\/\//.test(text)) className = 'http-url'
    else if (/^["']/.test(text)) className = 'http-string'
    else if (/^(true|false|null)$/.test(text)) className = 'http-literal'
    else if (/^[{}[\],:]$/.test(text)) className = 'http-bracket'
    result += `<span class="${className}">${escapeHtml(text)}</span>`
    cursor = index + text.length
  }
  return result + escapeHtml(value.slice(cursor))
}

function highlightLine(line: string, firstLine: boolean, inHeaders: boolean): string {
  if (firstLine && /^(?:HTTP\/\S+\s+\d{3}|(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|CONNECT|TRACE)\s+)/.test(line)) {
    const request = line.match(/^((?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|CONNECT|TRACE))(\s+)(\S+)(.*)$/)
    if (request) return `<span class="http-method">${request[1]}</span>${escapeHtml(request[2])}<span class="http-url">${escapeHtml(request[3])}</span>${highlightBody(request[4])}`
    const response = line.match(/^(HTTP\/\S+)(\s+)([0-9]{3})(.*)$/)
    if (response) {
      const statusClass = response[3].startsWith('2') ? 'http-status-ok' : response[3].startsWith('3') ? 'http-status-redirect' : response[3].startsWith('4') ? 'http-status-client' : 'http-status-server'
      return `<span class="http-version">${response[1]}</span>${escapeHtml(response[2])}<span class="${statusClass}">${response[3]}</span>${escapeHtml(response[4])}`
    }
  }
  if (inHeaders) {
    const header = line.match(/^([A-Za-z][A-Za-z0-9-]*)(:)(\s*)(.*)$/)
    if (header) return `<span class="http-header-name">${header[1]}</span><span class="http-header-separator">${header[2]}${header[3]}</span>${highlightBody(header[4])}`
  }
  return highlightBody(line)
}

export function highlightHttp(value: string): string {
  const lines = value.replace(/\r\n/g, '\n').split('\n')
  let inHeaders = lines.length > 1 && lines[0].trim().length > 0
  return lines.map((line, index) => {
    const rendered = highlightLine(line, index === 0, inHeaders)
    if (inHeaders && line === '') inHeaders = false
    return rendered || ' '
  }).join('\n')
}

export function HighlightedCode({ value, className = '' }: { value: string | ReactElement; className?: string }) {
  if (typeof value !== 'string') return value
  return <pre className={`http-code ${className}`} dangerouslySetInnerHTML={{ __html: highlightHttp(value) }} />
}

export function HighlightedEditor({ value, onChange, className = '', spellCheck = false }: { value: string; onChange: (value: string) => void; className?: string; spellCheck?: boolean }) {
  const previewRef = useRef<HTMLPreElement>(null)
  const editorRef = useRef<HTMLTextAreaElement>(null)
  useEffect(() => {
    const editor = editorRef.current
    const preview = previewRef.current
    if (!editor || !preview) return
    const syncScroll = () => { preview.scrollTop = editor.scrollTop; preview.scrollLeft = editor.scrollLeft }
    editor.addEventListener('scroll', syncScroll)
    syncScroll()
    return () => editor.removeEventListener('scroll', syncScroll)
  }, [])
  return <div className={`http-editor ${className}`}>
    <pre ref={previewRef} className="http-code http-editor-preview" aria-hidden="true" dangerouslySetInnerHTML={{ __html: highlightHttp(value) }} />
    <textarea ref={editorRef} value={value} onChange={(event) => onChange(event.target.value)} spellCheck={spellCheck} aria-label="HTTP message" />
  </div>
}
