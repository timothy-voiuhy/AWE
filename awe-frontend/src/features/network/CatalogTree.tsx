import type { ReactNode } from 'react'
import type { CatalogOrganization } from '../../api/catalog'
import { CategoryGroup, groupByCategory } from '../../components/CategoryGroup'

export function CatalogTree<T extends { category: string }>({ organization, items, categoryId, search, renderItems }: { organization?: CatalogOrganization; items: T[]; categoryId: (item: T) => string; search: string; renderItems: (items: T[]) => ReactNode }) {
  if (!organization) return <>{groupByCategory(items).map(group => <CategoryGroup key={`${group.category}:${search}`} name={group.category} count={group.entries.length} defaultExpanded={!!search}>{renderItems(group.entries)}</CategoryGroup>)}</>
  const entries = new Map<string, T[]>()
  for (const item of items) {
    const id = categoryId(item)
    entries.set(id, [...(entries.get(id) || []), item])
  }
  const children = (parent: string | null) => organization.categories.filter(item => item.parent_id === parent).sort((a, b) => a.name.localeCompare(b.name))
  const count = (id: string): number => (entries.get(id)?.length || 0) + children(id).reduce((total, child) => total + count(child.id), 0)
  const render = (parent: string | null): ReactNode => children(parent).filter(category => count(category.id)).map(category => <CategoryGroup key={`${category.id}:${search}`} name={category.name} count={count(category.id)} defaultExpanded={!!search}>
    {!!entries.get(category.id)?.length && renderItems(entries.get(category.id)!)}
    <div className="catalog-subcategories">{render(category.id)}</div>
  </CategoryGroup>)
  return <>{render(null)}</>
}
