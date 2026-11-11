import { request } from './client'

export type CoverageLevel = 'fixture_verified' | 'adapter_only' | 'manual_required'
export interface CoverageRow { id: string; area: string; family: string; tool_keys: string[]; registered_tool_keys: string[]; verification: CoverageLevel; inputs: string[]; limitations: string; cwe: string[]; fixture?: string }
export interface TransformCoverage { schema_version: number; suite_version: string; native_transform_count: number; verification_note: string; rows: CoverageRow[] }
export const getTransformCoverage = () => request<TransformCoverage>('/coverage/transforms')
