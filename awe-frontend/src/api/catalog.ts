import { request } from './client'

export interface CatalogCategory { id: string; name: string; parent_id: string | null }
export interface CatalogOrganization { categories: CatalogCategory[]; defaults: Record<string, string>; assignments: Record<string, string>; placements?: Record<string, string> }
const base = (project: string) => `/projects/${project}/catalog`
export const catalog = {
  organization: (project: string) => request<CatalogOrganization>(`${base(project)}/organization`),
  create: (project: string, name: string, parent_id: string | null) => request<CatalogOrganization>(`${base(project)}/categories`, { method: 'POST', body: JSON.stringify({ name, parent_id }) }),
  update: (project: string, id: string, name: string, parent_id: string | null) => request<CatalogOrganization>(`${base(project)}/categories/${id}`, { method: 'PATCH', body: JSON.stringify({ name, parent_id }) }),
  remove: (project: string, id: string) => request<CatalogOrganization>(`${base(project)}/categories/${id}`, { method: 'DELETE' }),
  assign: (project: string, item_keys: string[], category_id: string) => request<CatalogOrganization>(`${base(project)}/assignments`, { method: 'PUT', body: JSON.stringify({ item_keys, category_id }) }),
}
