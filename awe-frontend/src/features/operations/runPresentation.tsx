import type { ToolRun } from '../../api/runtime'

export const activeRunStatuses = new Set(['queued', 'running', 'approval_required', 'cancelling', 'active'])

export function RunStatus({ status }: { status: string }) {
  const tone = activeRunStatuses.has(status) ? 'active' : status === 'completed' ? 'success' : ['failed', 'disconnected'].includes(status) ? 'failure' : 'neutral'
  return <span className={`run-status run-status-${tone}`}><i aria-hidden="true" />{status.replaceAll('_', ' ')}</span>
}

export function runType(run: ToolRun) {
  return run.kind.startsWith('poc.build.') ? 'PoC build' : run.kind.startsWith('session.') ? 'Connection' : run.execution_kind === 'interactive' ? 'Interactive tool' : 'Tool execution'
}
