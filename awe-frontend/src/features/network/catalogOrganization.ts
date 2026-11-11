import type { CatalogOrganization } from '../../api/catalog'
import type { TransformManifest } from '../../api/client'

export function categoryPath(organization: CatalogOrganization | undefined, id: string): string {
  const category = organization?.categories.find(item => item.id === id)
  return category ? `${category.parent_id ? `${categoryPath(organization, category.parent_id)} / ` : ''}${category.name}` : 'Uncategorized'
}

export function categoryFor(organization: CatalogOrganization | undefined, key: string, item: { category: string; source_metadata?: Record<string, unknown> }) {
  const fallback = ['git', 'archive'].includes(String(item.source_metadata?.kind)) ? 'Exploits' : item.category
  return organization?.assignments[key] || organization?.placements?.[key] || organization?.defaults[fallback] || 'uncategorized'
}

export function transformCatalogKey(project: string, item: TransformManifest) {
  // Tool keys are slugs; composite keys are namespaced IDs. Identity must not
  // depend on Docker's slower image inventory finishing first.
  return !item.tool_key.includes(':') ? `tool:${item.tool_key}` : `transform:${project}:${item.id}`
}
