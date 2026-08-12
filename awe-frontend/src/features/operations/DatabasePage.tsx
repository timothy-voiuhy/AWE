import { useMemo } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Link } from 'react-router-dom'

import { api, type DatabaseCollectionStats, type DatabaseStats } from '../../api/client'

function formatBytes(value: number) {
  if (!value) return '0 B'
  const units = ['B', 'KB', 'MB', 'GB', 'TB']
  let amount = value
  let unit = 0
  while (amount >= 1024 && unit < units.length - 1) { amount /= 1024; unit += 1 }
  return `${amount.toFixed(amount >= 10 || unit === 0 ? 0 : 1)} ${units[unit]}`
}

function collectionSize(collection: DatabaseCollectionStats) {
  return collection.storage_bytes + collection.index_bytes
}

export function DatabasePage() {
  const queryClient = useQueryClient()
  const overview = useQuery({ queryKey: ['database', 'overview'], queryFn: api.getDatabaseOverview, refetchInterval: 15_000 })
  const clearTraffic = useMutation({
    mutationFn: api.clearAllProxyTraffic,
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: ['database', 'overview'] }),
  })

  const totals = useMemo(() => {
    const databases = overview.data?.databases ?? []
    return {
      documents: databases.reduce((sum, database) => sum + database.documents, 0),
      storage: databases.reduce((sum, database) => sum + database.storage_bytes + database.index_bytes, 0),
    }
  }, [overview.data])
  const trafficDatabase = overview.data?.databases.find(database => database.name === overview.data.traffic_database)
  const traffic = trafficDatabase?.collections.find(collection => collection.name === 'traffic')

  function removeAllTraffic() {
    const confirmation = window.prompt(
      'This permanently deletes ALL captured proxy traffic across every project and external device. Type DELETE ALL TRAFFIC to continue:',
    )
    if (confirmation === 'DELETE ALL TRAFFIC') clearTraffic.mutate()
  }

  return <main className="page feature-page database-page">
    <Link className="back-link" to="/projects">← Projects</Link>
    <header className="page-header">
      <div>
        <p className="eyebrow">System storage</p>
        <h1>Database</h1>
        <p className="muted">Inspect MongoDB usage and reclaim space from captured proxy traffic.</p>
      </div>
      <button onClick={() => void overview.refetch()} disabled={overview.isFetching}>↻ Refresh</button>
    </header>

    {overview.isError && <p className="error">Could not load database statistics: {overview.error.message}</p>}
    {clearTraffic.isError && <p className="error">Could not clear proxy traffic: {clearTraffic.error.message}</p>}
    {clearTraffic.isSuccess && <p className="success">Deleted {clearTraffic.data.deleted_documents.toLocaleString()} captured transactions and released approximately {formatBytes(clearTraffic.data.reclaimed_storage_bytes)}.</p>}

    <section className="database-metrics">
      <article className="panel database-metric"><span>Databases</span><strong>{overview.isPending ? '…' : overview.data?.databases.length ?? 0}</strong><small>Application databases</small></article>
      <article className="panel database-metric"><span>Documents</span><strong>{overview.isPending ? '…' : totals.documents.toLocaleString()}</strong><small>Estimated collection records</small></article>
      <article className="panel database-metric"><span>Storage</span><strong>{overview.isPending ? '…' : formatBytes(totals.storage)}</strong><small>Data plus indexes</small></article>
      <article className="panel database-metric database-metric-alert"><span>Proxy traffic</span><strong>{overview.isPending ? '…' : traffic ? formatBytes(collectionSize(traffic)) : '0 B'}</strong><small>{traffic ? `${traffic.documents.toLocaleString()} captured transactions` : 'No captured transactions'}</small></article>
    </section>

    <section className="database-layout">
      <section className="panel database-cleanup">
        <header><div><p className="eyebrow">Storage cleanup</p><h2>Captured proxy traffic</h2></div><span className="database-danger-badge">Global</span></header>
        <p>Proxy captures are shared globally, so this includes traffic from every project and external device. Request and response bodies are included in this store.</p>
        <div className="database-traffic-summary">
          <div><b>{traffic?.documents.toLocaleString() ?? '0'}</b><span>documents</span></div>
          <div><b>{traffic ? formatBytes(traffic.storage_bytes) : '0 B'}</b><span>body data</span></div>
          <div><b>{traffic ? formatBytes(traffic.index_bytes) : '0 B'}</b><span>indexes</span></div>
        </div>
        <button className="danger database-delete-button" onClick={removeAllTraffic} disabled={clearTraffic.isPending || !traffic?.documents}>
          {clearTraffic.isPending ? 'Clearing traffic…' : 'Delete all proxy traffic'}
        </button>
        <small className="muted">The traffic collection and its indexes are recreated immediately for new captures. This action cannot be undone.</small>
      </section>

      <section className="panel database-inventory">
        <header><div><p className="eyebrow">MongoDB inventory</p><h2>Collections</h2></div><span>{overview.data?.databases.length ?? 0}</span></header>
        {overview.isPending && <div className="empty">Reading database statistics…</div>}
        {!overview.isPending && !overview.data?.databases.length && <div className="empty">No application collections found.</div>}
        {overview.data?.databases.map(database => <DatabaseCard database={database} key={database.name} />)}
      </section>
    </section>
  </main>
}

function DatabaseCard({ database }: { database: DatabaseStats }) {
  return <details className="database-card" open={database.name === 'awe_proxy_traffic'}>
    <summary><b>{database.name}</b><span>{database.documents.toLocaleString()} docs · {formatBytes(database.storage_bytes + database.index_bytes)}</span></summary>
    <div className="database-collection-list">
      {database.collections.map(collection => <div className="database-collection" key={collection.name}>
        <code>{collection.name}</code><span>{collection.documents.toLocaleString()} docs</span><small>{formatBytes(collectionSize(collection))}</small>
      </div>)}
    </div>
  </details>
}
