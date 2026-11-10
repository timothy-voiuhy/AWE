import type { ExecutionOptions } from '../../api/runtime'

export function ExecutionFields({ value, onChange }: { value: ExecutionOptions; onChange: (next: ExecutionOptions) => void }) {
  const channels = value.output_channels || ['logs', 'structured']
  return <fieldset className="execution-fields"><legend>Execution and outputs</legend>
    <label>Execution kind<select value={value.execution_kind || 'batch'} onChange={e => onChange({ ...value, execution_kind: e.target.value as 'batch' | 'interactive', output_channels: e.target.value === 'interactive' ? [...new Set([...channels, 'session' as const])] : channels })}><option value="batch">Batch process</option><option value="interactive">Interactive console</option></select></label>
    <div>{(['logs', 'structured', 'artifacts', 'session'] as const).map(channel => <label key={channel}><input type="checkbox" checked={channels.includes(channel)} onChange={e => onChange({ ...value, output_channels: e.target.checked ? [...channels, channel] : channels.filter(c => c !== channel) })} />{channel}</label>)}</div>
    <label>Artifact paths (one per line, relative to /output)<textarea value={(value.artifact_paths || ['**/*']).join('\n')} onChange={e => onChange({ ...value, artifact_paths: e.target.value.split('\n').filter(Boolean) })} /></label>
    <label>Execution timeout (seconds)<input type="number" min="1" value={value.execution_timeout || 3600} onChange={e => onChange({ ...value, execution_timeout: Number(e.target.value) })} /></label>
    <label>Session idle timeout (seconds)<input type="number" min="1" value={value.session_idle_timeout || 3600} onChange={e => onChange({ ...value, session_idle_timeout: Number(e.target.value) })} /></label>
  </fieldset>
}
