import { useState, type ReactNode } from 'react'

export function groupByCategory<T extends { category: string }>(items: T[]) {
  const groups = new Map<string, T[]>()
  for (const item of items) {
    const category = item.category?.trim() || 'Other'
    groups.set(category, [...(groups.get(category) || []), item])
  }
  return [...groups].sort(([a], [b]) => a.localeCompare(b)).map(([category, entries]) => ({ category, entries }))
}

export function CategoryGroup({ name, count, children, defaultExpanded = false }: { name: string; count: number; children: ReactNode; defaultExpanded?: boolean }) {
  const [expanded, setExpanded] = useState(defaultExpanded)
  return <section className="catalog-category">
    <button type="button" className="catalog-category-toggle" aria-expanded={expanded} onClick={() => setExpanded(value => !value)}>
      <span className="catalog-category-chevron" aria-hidden="true">{expanded ? '▾' : '▸'}</span>
      <b>{name}</b><span className="catalog-category-count">{count}</span>
    </button>
    {expanded && children}
  </section>
}
