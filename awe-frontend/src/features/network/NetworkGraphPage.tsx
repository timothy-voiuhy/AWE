import { useEffect, useMemo, useRef, useState } from 'react'
import cytoscape, { type Core } from 'cytoscape'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Link, useParams } from 'react-router-dom'

import { api, type GraphBundle, type GraphEntity, type GraphRelationship } from '../../api/client'

const palette: Record<string, string> = {
  target: '#89b4fa', domain: '#74c7ec', subdomain: '#74c7ec', url: '#a6e3a1', endpoint: '#a6e3a1',
  ip: '#cba6f7', port: '#cba6f7', technology: '#f9e2af', tech: '#f9e2af', vulnerability: '#f38ba8', vuln: '#f38ba8',
  parameter: '#fab387', param: '#fab387', osint: '#f5c2e7', custom: '#bac2de',
}
const MAX_RENDER_NODES = 350
type TouchLabel = { text: string; x: number; y: number }
type SelectionSet = { name: string; ids: string[]; updatedAt: string }
type LayoutMode = 'force' | 'hierarchy' | 'radial' | 'concentric' | 'timeline'
type EdgeCurve = 'bezier' | 'straight' | 'taxi'
type LabelPolicy = 'smart' | 'all' | 'none'
type RelationshipGrouping = 'all' | 'pairs'
type ViewSnapshot = {
  query: string
  kind: string
  focusId: string
  focusDepth: number
  graphOrientation: 'portrait' | 'landscape'
  layoutMode: LayoutMode
  edgeCurve: EdgeCurve
  showArrows: boolean
  showEdgeLabels: boolean
  labelPolicy: LabelPolicy
  relationshipGrouping: RelationshipGrouping
  visibleRelationshipKinds: string[] | null
  selectedIds: string[]
  neighborhoodOnly: boolean
  componentOnly: boolean
  analysisDepth: number
}
type SavedView = { name: string; snapshot: ViewSnapshot; updatedAt: string }

function color(kind: string) { return palette[kind] || '#bac2de' }
function isTouchViewport() { return window.matchMedia('(pointer: coarse)').matches || window.innerWidth <= 900 }
function mergeGraphBundles(base: GraphBundle, extra: GraphBundle): GraphBundle {
  const entities = new Map(base.entities.map(entity => [entity.id, entity]))
  extra.entities.forEach(entity => entities.set(entity.id, entity))
  const relationships = new Map(base.relationships.map(edge => [edge.id, edge]))
  extra.relationships.forEach(edge => relationships.set(edge.id, edge))
  return { ...base, entities: [...entities.values()], relationships: [...relationships.values()] }
}
function graphAdjacency(graph: GraphBundle) {
  const adjacency = new Map<string, Set<string>>()
  graph.entities.forEach(entity => adjacency.set(entity.id, new Set()))
  graph.relationships.forEach(edge => {
    adjacency.get(edge.source_id)?.add(edge.target_id)
    adjacency.get(edge.target_id)?.add(edge.source_id)
  })
  return adjacency
}

export function NetworkGraphPage() {
  const { projectId = '' } = useParams()
  const queryClient = useQueryClient()
  const cyRef = useRef<Core | null>(null)
  const hostRef = useRef<HTMLDivElement>(null)
  const minimapRef = useRef<HTMLCanvasElement>(null)
  const [investigationId, setInvestigationId] = useState('')
  const [selectedId, setSelectedId] = useState('')
  const [focusId, setFocusId] = useState('')
  const [focusDepth, setFocusDepth] = useState(1)
  const [graphExpanded, setGraphExpanded] = useState(false)
  const [graphOrientation, setGraphOrientation] = useState<'portrait' | 'landscape'>('portrait')
  const [supplementalGraph, setSupplementalGraph] = useState<GraphBundle | null>(null)
  const [selectedIds, setSelectedIds] = useState<string[]>([])
  const [pathNodeIds, setPathNodeIds] = useState<string[]>([])
  const [pathEdgeIds, setPathEdgeIds] = useState<string[]>([])
  const [lassoMode, setLassoMode] = useState(false)
  const [selectionMenuOpen, setSelectionMenuOpen] = useState(false)
  const [selectionSetName, setSelectionSetName] = useState('')
  const [selectionSets, setSelectionSets] = useState<SelectionSet[]>([])
  const [neighborhoodOnly, setNeighborhoodOnly] = useState(false)
  const [componentOnly, setComponentOnly] = useState(false)
  const [analysisDepth, setAnalysisDepth] = useState(1)
  const [layoutMode, setLayoutMode] = useState<LayoutMode>('force')
  const [visibleRelationshipKinds, setVisibleRelationshipKinds] = useState<string[] | null>(null)
  const [edgeCurve, setEdgeCurve] = useState<EdgeCurve>('bezier')
  const [showArrows, setShowArrows] = useState(false)
  const [showEdgeLabels, setShowEdgeLabels] = useState(false)
  const [labelPolicy, setLabelPolicy] = useState<LabelPolicy>('smart')
  const [relationshipGrouping, setRelationshipGrouping] = useState<RelationshipGrouping>('all')
  const [displayMenuOpen, setDisplayMenuOpen] = useState(false)
  const [viewsMenuOpen, setViewsMenuOpen] = useState(false)
  const [savedViewName, setSavedViewName] = useState('')
  const [savedViews, setSavedViews] = useState<SavedView[]>([])
  const [historyAvailable, setHistoryAvailable] = useState({ undo: false, redo: false })
  const [mobileInspectorOpen, setMobileInspectorOpen] = useState(false)
  const [mobileMenuId, setMobileMenuId] = useState('')
  const [mobileTouchNodeId, setMobileTouchNodeId] = useState('')
  const [touchLabel, setTouchLabel] = useState<TouchLabel | null>(null)
  const [query, setQuery] = useState('')
  const [kind, setKind] = useState('')
  const [selectedTransform, setSelectedTransform] = useState('')
  const [transformParameters, setTransformParameters] = useState<Record<string, string>>({})
  const [transformJobId, setTransformJobId] = useState('')
  const [notice, setNotice] = useState('')
  const [entityDraft, setEntityDraft] = useState({ kind: 'custom', label: '', value: '' })
  const [relationshipDraft, setRelationshipDraft] = useState({ source_id: '', target_id: '', kind: 'linked_to', label: '' })
  const selectedIdRef = useRef('')
  const selectionSetsReadyRef = useRef(false)
  const preferencesHydratedRef = useRef(false)
  const preferenceRevisionRef = useRef(0)
  const historyCurrentRef = useRef<ViewSnapshot | null>(null)
  const historyPastRef = useRef<ViewSnapshot[]>([])
  const historyFutureRef = useRef<ViewSnapshot[]>([])
  const historySkipKeyRef = useRef('')
  const skipPreferencePersistRef = useRef(false)

  const investigations = useQuery({ queryKey: ['projects', projectId, 'investigations'], queryFn: () => api.listInvestigations(projectId) })
  useEffect(() => {
    selectedIdRef.current = selectedId
  }, [selectedId])

  useEffect(() => {
    if (!investigationId && investigations.data?.[0]) setInvestigationId(investigations.data[0].id)
  }, [investigations.data, investigationId])
  useEffect(() => {
    setSupplementalGraph(null)
    setPathNodeIds([])
    setPathEdgeIds([])
  }, [focusId])
  useEffect(() => {
    setSelectedIds([])
    setNeighborhoodOnly(false)
    setComponentOnly(false)
    setSelectionMenuOpen(false)
    setDisplayMenuOpen(false)
    setViewsMenuOpen(false)
    preferencesHydratedRef.current = false
    preferenceRevisionRef.current = 0
    historyCurrentRef.current = null
    historyPastRef.current = []
    historyFutureRef.current = []
    historySkipKeyRef.current = ''
    setHistoryAvailable({ undo: false, redo: false })
    skipPreferencePersistRef.current = false
  }, [investigationId])
  const selectionSetsKey = `awe:graph-selection-sets:${projectId}:${investigationId}`
  useEffect(() => {
    selectionSetsReadyRef.current = false
    if (!investigationId) { setSelectionSets([]); return }
    try {
      const stored = window.localStorage.getItem(selectionSetsKey)
      const parsed = stored ? JSON.parse(stored) as SelectionSet[] : []
      setSelectionSets(Array.isArray(parsed) ? parsed.filter(item => item && typeof item.name === 'string' && Array.isArray(item.ids)) : [])
    } catch {
      setSelectionSets([])
    } finally {
      selectionSetsReadyRef.current = true
    }
  }, [selectionSetsKey, investigationId])
  useEffect(() => {
    if (!selectionSetsReadyRef.current || !investigationId) return
    window.localStorage.setItem(selectionSetsKey, JSON.stringify(selectionSets))
  }, [selectionSets, selectionSetsKey, investigationId])
  const savedViewsKey = `awe:graph-saved-views:${projectId}:${investigationId}`
  useEffect(() => {
    if (!investigationId) { setSavedViews([]); return }
    try {
      const stored = window.localStorage.getItem(savedViewsKey)
      const parsed = stored ? JSON.parse(stored) as SavedView[] : []
      setSavedViews(Array.isArray(parsed) ? parsed.filter(item => item && typeof item.name === 'string' && item.snapshot) : [])
    } catch {
      setSavedViews([])
    }
  }, [savedViewsKey, investigationId])
  useEffect(() => {
    if (investigationId) window.localStorage.setItem(savedViewsKey, JSON.stringify(savedViews))
  }, [savedViews, savedViewsKey, investigationId])
  const graph = useQuery({ queryKey: ['projects', projectId, 'investigation-graph', investigationId, focusId, focusDepth], queryFn: () => api.getInvestigationGraph(projectId, investigationId, { focus_id: focusId || undefined, depth: focusDepth, limit: focusId ? 500 : undefined }), enabled: !!investigationId, refetchInterval: 5000 })
  const graphView = useMemo(() => graph.data && supplementalGraph ? mergeGraphBundles(graph.data, supplementalGraph) : graph.data, [graph.data, supplementalGraph])
  const viewSnapshot = useMemo<ViewSnapshot>(() => ({ query, kind, focusId, focusDepth, graphOrientation, layoutMode, edgeCurve, showArrows, showEdgeLabels, labelPolicy, relationshipGrouping, visibleRelationshipKinds, selectedIds, neighborhoodOnly, componentOnly, analysisDepth }), [query, kind, focusId, focusDepth, graphOrientation, layoutMode, edgeCurve, showArrows, showEdgeLabels, labelPolicy, relationshipGrouping, visibleRelationshipKinds, selectedIds, neighborhoodOnly, componentOnly, analysisDepth])
  const viewSnapshotKey = JSON.stringify(viewSnapshot)
  const viewPreferences = useMemo(() => ({ layoutMode, edgeCurve, showArrows, showEdgeLabels, labelPolicy, relationshipGrouping, visibleRelationshipKinds, graphOrientation }), [layoutMode, edgeCurve, showArrows, showEdgeLabels, labelPolicy, relationshipGrouping, visibleRelationshipKinds, graphOrientation])
  useEffect(() => {
    if (!graphView || preferencesHydratedRef.current || graphView.investigation.id !== investigationId) return
    const stored = graphView.investigation.preferences?.view as Partial<typeof viewPreferences> | undefined
    if (stored) {
      if (['force', 'hierarchy', 'radial', 'concentric', 'timeline'].includes(String(stored.layoutMode))) setLayoutMode(stored.layoutMode as LayoutMode)
      if (['bezier', 'straight', 'taxi'].includes(String(stored.edgeCurve))) setEdgeCurve(stored.edgeCurve as EdgeCurve)
      if (typeof stored.showArrows === 'boolean') setShowArrows(stored.showArrows)
      if (typeof stored.showEdgeLabels === 'boolean') setShowEdgeLabels(stored.showEdgeLabels)
      if (['smart', 'all', 'none'].includes(String(stored.labelPolicy))) setLabelPolicy(stored.labelPolicy as LabelPolicy)
      if (stored.relationshipGrouping === 'all' || stored.relationshipGrouping === 'pairs') setRelationshipGrouping(stored.relationshipGrouping)
      if (stored.visibleRelationshipKinds === null || Array.isArray(stored.visibleRelationshipKinds)) setVisibleRelationshipKinds(stored.visibleRelationshipKinds as string[] | null)
      if (stored.graphOrientation === 'portrait' || stored.graphOrientation === 'landscape') setGraphOrientation(stored.graphOrientation)
    }
    preferenceRevisionRef.current = graphView.investigation.revision
    preferencesHydratedRef.current = true
    skipPreferencePersistRef.current = true
  }, [graphView, investigationId, viewPreferences])
  const preferenceKey = JSON.stringify(viewPreferences)
  const lastPersistedPreferenceKeyRef = useRef('')
  const preferenceSaveTimerRef = useRef<number | undefined>(undefined)
  useEffect(() => {
    if (!preferencesHydratedRef.current || !graphView || graphView.investigation.id !== investigationId || lastPersistedPreferenceKeyRef.current === preferenceKey) return
    if (skipPreferencePersistRef.current) { skipPreferencePersistRef.current = false; return }
    if (preferenceSaveTimerRef.current) window.clearTimeout(preferenceSaveTimerRef.current)
    preferenceSaveTimerRef.current = window.setTimeout(() => {
      void api.saveGraphPreferences(projectId, investigationId, { preferences: { ...(graphView.investigation.preferences || {}), view: viewPreferences }, revision: preferenceRevisionRef.current || graphView.investigation.revision }).then(saved => {
        preferenceRevisionRef.current = saved.revision
        lastPersistedPreferenceKeyRef.current = preferenceKey
      }).catch(() => setNotice('Could not persist graph display preferences; the current view is still active.'))
    }, 350)
    return () => { if (preferenceSaveTimerRef.current) window.clearTimeout(preferenceSaveTimerRef.current) }
  }, [projectId, investigationId, graphView, preferenceKey, viewPreferences])
  useEffect(() => {
    if (!preferencesHydratedRef.current) return
    if (!historyCurrentRef.current) {
      historyCurrentRef.current = viewSnapshot
      setHistoryAvailable({ undo: false, redo: false })
      return
    }
    if (historySkipKeyRef.current === viewSnapshotKey) {
      historySkipKeyRef.current = ''
      historyCurrentRef.current = viewSnapshot
      setHistoryAvailable({ undo: historyPastRef.current.length > 0, redo: historyFutureRef.current.length > 0 })
      return
    }
    if (JSON.stringify(historyCurrentRef.current) === viewSnapshotKey) return
    historyPastRef.current = [...historyPastRef.current.slice(-49), historyCurrentRef.current]
    historyCurrentRef.current = viewSnapshot
    historyFutureRef.current = []
    setHistoryAvailable({ undo: true, redo: false })
  }, [viewSnapshot, viewSnapshotKey])
  const transforms = useQuery({ queryKey: ['projects', projectId, 'transforms'], queryFn: () => api.listGraphTransforms(projectId) })
  const activeTransform = transforms.data?.find(item => item.id === selectedTransform)
  const transformJob = useQuery({ queryKey: ['projects', projectId, 'transform-job', transformJobId], queryFn: () => api.getGraphTransform(projectId, transformJobId), enabled: !!transformJobId, refetchInterval: query => ['queued', 'running'].includes(query.state.data?.status || '') ? 1000 : false })
  const selected = graphView?.entities.find(item => item.id === selectedId) || graphView?.entities[0]
  const relationshipKinds = useMemo(() => [...new Set((graphView?.relationships || []).map(edge => edge.kind))].sort(), [graphView?.relationships])
  const visibleRelationships = useMemo(() => (graphView?.relationships || []).filter(edge => !visibleRelationshipKinds || visibleRelationshipKinds.includes(edge.kind)), [graphView?.relationships, visibleRelationshipKinds])
  const displayRelationships = useMemo(() => {
    if (relationshipGrouping === 'all' || pathEdgeIds.length) return visibleRelationships
    const groups = new Map<string, GraphRelationship[]>()
    visibleRelationships.forEach(edge => {
      const endpoints = [edge.source_id, edge.target_id].sort()
      const key = `${endpoints[0]}:${endpoints[1]}`
      groups.set(key, [...(groups.get(key) || []), edge])
    })
    return [...groups.values()].map(group => {
      if (group.length === 1) return group[0]
      const first = group[0]
      return { ...first, id: `bundle:${first.source_id}:${first.target_id}`, kind: 'bundle', label: `${group.length} relationships`, data: { ...first.data, bundled_count: group.length, bundled_kinds: group.map(edge => edge.kind) } }
    })
  }, [visibleRelationships, relationshipGrouping, pathEdgeIds.length])
  const analysisEntityIds = useMemo(() => {
    if (!graphView || !selectedIds.length || (!neighborhoodOnly && !componentOnly)) return null
    const adjacency = graphAdjacency(graphView)
    const included = new Set(selectedIds.filter(id => adjacency.has(id)))
    if (componentOnly) {
      const queue = [...included]
      while (queue.length) {
        const current = queue.shift()!
        for (const next of adjacency.get(current) || []) {
          if (included.has(next)) continue
          included.add(next); queue.push(next)
        }
      }
      return included
    }
    let frontier = [...included]
    for (let depth = 0; depth < analysisDepth; depth += 1) {
      const nextFrontier: string[] = []
      frontier.forEach(id => (adjacency.get(id) || new Set()).forEach(next => {
        if (included.has(next)) return
        included.add(next); nextFrontier.push(next)
      }))
      frontier = nextFrontier
      if (!frontier.length) break
    }
    return included
  }, [graphView, selectedIds, neighborhoodOnly, componentOnly, analysisDepth])
  const filteredEntities = useMemo(() => (graphView?.entities || []).filter(item => {
    const haystack = `${item.label} ${item.value} ${item.kind} ${JSON.stringify(item.data)}`.toLowerCase()
    return (!query || haystack.includes(query.toLowerCase())) && (!kind || item.kind === kind) && (!analysisEntityIds || analysisEntityIds.has(item.id))
  }), [graphView?.entities, query, kind, analysisEntityIds])
  const visibleEntities = useMemo(() => {
    if (filteredEntities.length <= MAX_RENDER_NODES) return filteredEntities
    const root = filteredEntities.find(item => item.kind === 'target')
    const selected = selectedId ? filteredEntities.find(item => item.id === selectedId) : undefined
    const prioritized = [root, selected, ...filteredEntities].filter((item): item is GraphEntity => Boolean(item))
    return [...new Map(prioritized.map(item => [item.id, item])).values()].slice(0, MAX_RENDER_NODES)
  }, [filteredEntities, selectedId])
  const renderSignature = useMemo(() => visibleEntities.map(item => `${item.id}:${item.label}:${item.kind}`).join('|'), [visibleEntities])
  const relationshipSignature = useMemo(() => {
    const allowed = new Set(visibleEntities.map(item => item.id))
    return displayRelationships.filter(edge => allowed.has(edge.source_id) && allowed.has(edge.target_id)).map(edge => `${edge.id}:${edge.source_id}:${edge.target_id}:${edge.label || edge.kind}`).join('|')
  }, [renderSignature, visibleEntities, displayRelationships])
  const selectedSignature = selectedIds.join('|')
  const pathSignature = `${pathNodeIds.join('|')}:${pathEdgeIds.join('|')}`

  useEffect(() => {
    if (!hostRef.current || !graphView) return
    cyRef.current?.destroy()
    const allowed = new Set(visibleEntities.map(item => item.id))
    const elements: cytoscape.ElementDefinition[] = [
      ...visibleEntities.map(entity => ({ data: { id: entity.id, label: entity.label, kind: entity.kind, color: color(entity.kind), source: entity.source }, position: { x: entity.x || 0, y: entity.y || 0 } })),
      ...displayRelationships.filter(edge => allowed.has(edge.source_id) && allowed.has(edge.target_id)).map(edge => ({ data: { id: edge.id, source: edge.source_id, target: edge.target_id, label: edge.label || edge.kind, kind: edge.kind } })),
    ]
    const rootId = visibleEntities.find(entity => entity.kind === 'target')?.id
    const layout = layoutMode === 'hierarchy'
      ? { name: 'breadthfirst', directed: true, roots: rootId ? [rootId] : undefined, animate: false, padding: 40, spacingFactor: 1.25 }
      : layoutMode === 'radial'
        ? { name: 'concentric', animate: false, padding: 40, concentric: (node: cytoscape.NodeSingular) => node.id() === rootId ? 3 : 1, levelWidth: () => 1 }
        : layoutMode === 'concentric'
          ? { name: 'concentric', animate: false, padding: 40, concentric: (node: cytoscape.NodeSingular) => node.degree(), levelWidth: () => 2 }
          : layoutMode === 'timeline'
            ? { name: 'grid', animate: false, padding: 40, rows: 1, cols: Math.max(1, visibleEntities.length) }
            : { name: 'cose', animate: false, padding: 40, numIter: 250 }
    const cy = cytoscape({ container: hostRef.current, elements, boxSelectionEnabled: lassoMode, selectionType: 'additive', style: [
      { selector: 'node', style: { 'background-color': 'data(color)', label: labelPolicy === 'all' ? 'data(label)' : '', color: '#cdd6f4', 'font-size': '10px', 'text-wrap': 'ellipsis', 'text-max-width': '120px', 'text-valign': 'bottom', 'text-margin-y': '8px', width: 34, height: 34, 'border-width': 2, 'border-color': '#313244' } as unknown as cytoscape.Css.Node },
      { selector: 'node[kind = "target"], node:selected, node.hovered, node.zoom-label', style: { label: labelPolicy === 'none' ? '' : 'data(label)', 'text-background-color': '#11111b', 'text-background-opacity': 0.86, 'text-background-padding': '3px', 'text-border-width': 1, 'text-border-color': '#313244' } as unknown as cytoscape.Css.Node },
      { selector: 'node:selected', style: { 'border-color': '#f9e2af', 'border-width': 4, 'overlay-color': '#f9e2af', 'overlay-opacity': 0.12 } as unknown as cytoscape.Css.Node },
      { selector: 'edge', style: { width: 1, opacity: 0.48, 'line-color': '#585b70', 'target-arrow-color': '#7f849c', 'target-arrow-shape': showArrows ? 'triangle' : 'none', label: showEdgeLabels ? 'data(label)' : '', color: '#cdd6f4', 'font-size': '8px', 'curve-style': edgeCurve, 'text-rotation': 'autorotate' } as unknown as cytoscape.Css.Edge },
      { selector: 'edge.hovered', style: { width: 2.5, opacity: 1, 'line-color': '#89b4fa', 'target-arrow-color': '#89b4fa', 'target-arrow-shape': 'triangle', label: 'data(label)', 'text-background-color': '#11111b', 'text-background-opacity': 0.9, 'text-background-padding': '3px' } as unknown as cytoscape.Css.Edge },
    ], layout })
    cy.on('tap', 'node', event => {
      const node = event.target
      const id = node.id()
      const position = event.renderedPosition
      const mobile = isTouchViewport()
      const wasSelected = selectedIdRef.current === id
      const originalEvent = event.originalEvent as MouseEvent | TouchEvent | undefined
      const additive = Boolean(originalEvent && 'shiftKey' in originalEvent && (originalEvent.shiftKey || (originalEvent as MouseEvent).metaKey))
      setSelectedId(id)
      selectedIdRef.current = id
      setSelectedIds(current => additive ? (current.includes(id) ? current.filter(item => item !== id) : [...current, id]) : [id])
      if (!additive) { setPathNodeIds([]); setPathEdgeIds([]) }
      setTouchLabel({ text: String(node.data('label') || id), x: position.x, y: position.y })
      setMobileTouchNodeId(id)
      setMobileMenuId('')
      if (mobile) setMobileInspectorOpen(wasSelected)
    })
    cy.on('taphold', 'node', event => {
      const node = event.target
      const position = event.renderedPosition
      setSelectedId(node.id())
      selectedIdRef.current = node.id()
      setMobileTouchNodeId(node.id())
      setTouchLabel({ text: String(node.data('label') || node.id()), x: position.x, y: position.y })
      setMobileMenuId(node.id())
      setMobileInspectorOpen(false)
    })
    cy.on('tap', 'edge', event => {
      const edge = event.target
      const position = event.renderedPosition
      setTouchLabel({ text: String(edge.data('label') || edge.data('kind') || 'relationship'), x: position.x, y: position.y })
      setMobileTouchNodeId('')
      setMobileMenuId('')
    })
    cy.on('boxselect', 'node', () => {
      const ids = cy.nodes(':selected').map(node => node.id())
      setSelectedIds(ids)
      setSelectedId(ids[0] || '')
      selectedIdRef.current = ids[0] || ''
      setPathNodeIds([])
      setPathEdgeIds([])
      setNotice(ids.length ? `Selected ${ids.length} graph entities.` : 'No graph entities selected.')
    })
    cy.on('tap', event => {
      if (event.target === cy) {
        setTouchLabel(null)
        setMobileTouchNodeId('')
        setMobileMenuId('')
      }
    })
    cy.on('mouseover', 'node', event => event.target.addClass('hovered'))
    cy.on('mouseout', 'node', event => event.target.removeClass('hovered'))
    cy.on('mouseover', 'edge', event => event.target.addClass('hovered'))
    cy.on('mouseout', 'edge', event => event.target.removeClass('hovered'))
    const updateZoomLabels = () => {
      const enabled = labelPolicy === 'smart' && cy.zoom() >= 1.15
      cy.nodes().toggleClass('zoom-label', enabled)
    }
    cy.on('zoom', updateZoomLabels)
    updateZoomLabels()
    const drawMinimap = () => {
      const canvas = minimapRef.current
      if (!canvas) return
      const width = canvas.clientWidth || 180
      const height = canvas.clientHeight || 110
      const dpr = window.devicePixelRatio || 1
      canvas.width = width * dpr
      canvas.height = height * dpr
      const context = canvas.getContext('2d')
      if (!context) return
      context.setTransform(dpr, 0, 0, dpr, 0, 0)
      context.clearRect(0, 0, width, height)
      context.fillStyle = '#11111b'
      context.fillRect(0, 0, width, height)
      const bounds = cy.nodes().boundingBox()
      const scale = Math.min((width - 12) / Math.max(bounds.w, 1), (height - 12) / Math.max(bounds.h, 1))
      const map = (point: { x: number; y: number }) => ({ x: 6 + (point.x - bounds.x1) * scale, y: 6 + (point.y - bounds.y1) * scale })
      cy.edges().forEach(edge => {
        const source = map(edge.source().position()); const target = map(edge.target().position())
        context.strokeStyle = '#45475a'; context.lineWidth = 0.7; context.beginPath(); context.moveTo(source.x, source.y); context.lineTo(target.x, target.y); context.stroke()
      })
      cy.nodes().forEach(node => {
        const point = map(node.position())
        context.fillStyle = node.selected() ? '#f9e2af' : String(node.data('color') || '#bac2de')
        context.fillRect(point.x - 2, point.y - 2, 4, 4)
      })
      const extent = cy.extent(); const topLeft = map({ x: extent.x1, y: extent.y1 })
      context.strokeStyle = '#89b4fa'; context.lineWidth = 1; context.strokeRect(topLeft.x, topLeft.y, extent.w * scale, extent.h * scale)
    }
    cy.on('render position layoutstop', drawMinimap)
    drawMinimap()
    cy.nodes().unselect()
    selectedIds.forEach(id => cy.$id(id).select())
    if (selectedId && !selectedIds.includes(selectedId)) cy.$id(selectedId).select()
    pathNodeIds.forEach(id => cy.$id(id).addClass('path-node'))
    pathEdgeIds.forEach(id => cy.$id(id).addClass('path-edge'))
    cy.on('dragfree', 'node', () => {
      const positions: Record<string, { x: number; y: number }> = {}
      cy.nodes().forEach(node => { positions[node.id()] = node.position() })
      if (graphView) void api.saveGraphPreferences(projectId, graphView.investigation.id, { preferences: { ...(graphView.investigation.preferences || {}), positions, view: viewPreferences }, revision: preferenceRevisionRef.current || graphView.investigation.revision }).then(saved => { preferenceRevisionRef.current = saved.revision }).catch(() => setNotice('Could not save the graph layout position.'))
    })
    cyRef.current = cy
    let rotationFrame = 0
    if (graphOrientation === 'landscape') {
      rotationFrame = window.requestAnimationFrame(() => {
        const nodes = cy.nodes()
        if (!nodes.length || cyRef.current !== cy) return
        const positions = nodes.map(node => node.position())
        const center = positions.reduce((result, position) => ({ x: result.x + position.x / positions.length, y: result.y + position.y / positions.length }), { x: 0, y: 0 })
        nodes.forEach((node, index) => {
          const position = positions[index]
          node.position({ x: center.x + (position.y - center.y), y: center.y - (position.x - center.x) })
        })
        cy.fit(undefined, 40)
      })
    }
    return () => { if (rotationFrame) window.cancelAnimationFrame(rotationFrame); cy.removeListener('zoom', updateZoomLabels); cy.removeListener('render position layoutstop', drawMinimap); cy.destroy(); cyRef.current = null }
  }, [projectId, renderSignature, relationshipSignature, graphOrientation, selectedSignature, pathSignature, lassoMode, layoutMode, edgeCurve, showArrows, showEdgeLabels, labelPolicy, viewPreferences, graphView?.investigation.revision])

  const createInvestigation = useMutation({ mutationFn: () => api.createInvestigation(projectId, 'New investigation'), onSuccess: item => { setInvestigationId(item.id); void queryClient.invalidateQueries({ queryKey: ['projects', projectId, 'investigations'] }) } })
  const createEntity = useMutation({ mutationFn: () => api.createGraphEntity(projectId, investigationId, { ...entityDraft, data: {}, confidence: 1, severity: '', scope: 'unknown', x: 0, y: 0 }), onSuccess: () => { setEntityDraft({ kind: 'custom', label: '', value: '' }); void queryClient.invalidateQueries({ queryKey: ['projects', projectId, 'investigation-graph', investigationId] }) } })
  const createRelationship = useMutation({ mutationFn: () => api.createGraphRelationship(projectId, investigationId, { ...relationshipDraft, data: {}, confidence: 1 }), onSuccess: () => { setRelationshipDraft({ source_id: '', target_id: '', kind: 'linked_to', label: '' }); void queryClient.invalidateQueries({ queryKey: ['projects', projectId, 'investigation-graph', investigationId] }) } })
  const deleteEntity = useMutation({ mutationFn: (id: string) => api.deleteGraphEntity(projectId, investigationId, id), onSuccess: () => { setSelectedId(''); void queryClient.invalidateQueries({ queryKey: ['projects', projectId, 'investigation-graph', investigationId] }) } })
  const transform = useMutation({ mutationFn: () => api.startGraphTransform(projectId, { transform_id: selectedTransform, entity_ids: selected ? [selected.id] : [], parameters: transformParameters, investigation_id: investigationId, approved: activeTransform?.requires_approval === true }), onSuccess: job => { setTransformJobId(job.id); setNotice(`Transform queued: ${activeTransform?.display_name || job.transform_id}.`); setSelectedTransform(''); setTransformParameters({}) } })
  const cancelTransform = useMutation({ mutationFn: () => { if (!transformJobId) throw new Error('No transform job is active'); return api.cancelGraphTransform(projectId, transformJobId) }, onSuccess: () => setNotice('Transform cancellation requested.') })
  const retryTransform = useMutation({ mutationFn: () => { const job = transformJob.data; if (!job) throw new Error('No transform job is available'); return api.startGraphTransform(projectId, { transform_id: job.transform_id, entity_ids: job.entity_ids, parameters: job.parameters, investigation_id: job.investigation_id, approved: true }) }, onSuccess: job => { setTransformJobId(job.id); setNotice(`Retry queued for ${job.transform_id}.`) } })
  const expandNeighbors = useMutation({
    mutationFn: () => {
      if (!selected) throw new Error('Select an entity first')
      return api.getInvestigationGraph(projectId, investigationId, { focus_id: selected.id, depth: 1, limit: 500 })
    },
    onSuccess: data => {
      setSupplementalGraph(current => current ? mergeGraphBundles(current, data) : data)
      setNotice(`Expanded neighbors for ${selected?.label || 'selected entity'}.`)
    },
  })

  useEffect(() => {
    if (!graphExpanded) return
    const closeOnEscape = (event: KeyboardEvent) => { if (event.key === 'Escape') setGraphExpanded(false) }
    document.addEventListener('keydown', closeOnEscape)
    return () => document.removeEventListener('keydown', closeOnEscape)
  }, [graphExpanded])

  const kinds = [...new Set((graphView?.entities || []).map(item => item.kind))].sort()
  const selectedRelationships = (graphView?.relationships || []).filter(item => item.source_id === selected?.id || item.target_id === selected?.id)
  const exportGraph = () => {
    if (!graphView) return
    const safeName = graphView.investigation.name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '') || 'investigation'
    const blob = new Blob([JSON.stringify(graphView, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const anchor = document.createElement('a')
    anchor.href = url
    anchor.download = `awe-${safeName}.json`
    document.body.appendChild(anchor)
    anchor.click()
    anchor.remove()
    URL.revokeObjectURL(url)
  }
  const findPathToTarget = () => {
    if (!selected || !graphView) return
    const target = graphView.entities.find(entity => entity.kind === 'target')
    if (!target) return
    if (selected.id === target.id) {
      setPathNodeIds([target.id]); setPathEdgeIds([]); setNotice('The selected entity is the investigation target.'); return
    }
    const adjacency = new Map<string, Array<{ id: string; edgeId: string }>>()
    graphView.relationships.forEach(edge => {
      adjacency.set(edge.source_id, [...(adjacency.get(edge.source_id) || []), { id: edge.target_id, edgeId: edge.id }])
      adjacency.set(edge.target_id, [...(adjacency.get(edge.target_id) || []), { id: edge.source_id, edgeId: edge.id }])
    })
    const previous = new Map<string, { id: string; edgeId: string } | null>([[selected.id, null]])
    const queue = [selected.id]
    while (queue.length && !previous.has(target.id)) {
      const current = queue.shift()!
      for (const next of adjacency.get(current) || []) {
        if (previous.has(next.id)) continue
        previous.set(next.id, { id: current, edgeId: next.edgeId }); queue.push(next.id)
      }
    }
    if (!previous.has(target.id)) { setNotice('No path to the target is available in the current graph view.'); return }
    const nodes: string[] = []; const edges: string[] = []
    let cursor = target.id
    while (cursor !== selected.id) {
      nodes.unshift(cursor)
      const step = previous.get(cursor)
      if (!step) break
      edges.unshift(step.edgeId); cursor = step.id
    }
    nodes.unshift(selected.id)
    setPathNodeIds(nodes); setPathEdgeIds(edges); setNotice(`Highlighted ${nodes.length - 1} relationship step${nodes.length === 2 ? '' : 's'} to the target.`)
  }
  const selectedEntities = (graphView?.entities || []).filter(entity => selectedIds.includes(entity.id))
  const saveSelectionSet = () => {
    const name = selectionSetName.trim()
    if (!name || !selectedIds.length) { setNotice('Choose entities and enter a name before saving a selection set.'); return }
    const item = { name, ids: selectedIds, updatedAt: new Date().toISOString() }
    setSelectionSets(current => [item, ...current.filter(existing => existing.name !== name)])
    setSelectionSetName('')
    setNotice(`Saved selection set “${name}” with ${selectedIds.length} entit${selectedIds.length === 1 ? 'y' : 'ies'}.`)
  }
  const applySelectionSet = (item: SelectionSet) => {
    const available = item.ids.filter(id => graphView?.entities.some(entity => entity.id === id))
    setSelectedIds(available)
    setSelectedId(available[0] || '')
    selectedIdRef.current = available[0] || ''
    setPathNodeIds([])
    setPathEdgeIds([])
    setNotice(`Loaded “${item.name}”: ${available.length} of ${item.ids.length} entities are in the current view.`)
  }
  const deleteSelectionSet = (name: string) => {
    setSelectionSets(current => current.filter(item => item.name !== name))
    setNotice(`Deleted selection set “${name}”.`)
  }
  const copySelection = () => {
    const values = selectedEntities.map(entity => entity.value || entity.label).join('\n')
    if (!values) return
    void navigator.clipboard?.writeText(values)
    setNotice(`Copied ${selectedEntities.length} selected entit${selectedEntities.length === 1 ? 'y' : 'ies'}.`)
  }
  const exportSelection = () => {
    if (!graphView || !selectedEntities.length) return
    const ids = new Set(selectedEntities.map(entity => entity.id))
    const payload = { investigation: graphView.investigation, entities: selectedEntities, relationships: graphView.relationships.filter(edge => ids.has(edge.source_id) && ids.has(edge.target_id)) }
    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const anchor = document.createElement('a')
    anchor.href = url
    anchor.download = 'awe-selection.json'
    document.body.appendChild(anchor)
    anchor.click()
    anchor.remove()
    URL.revokeObjectURL(url)
    setNotice(`Exported ${selectedEntities.length} selected entit${selectedEntities.length === 1 ? 'y' : 'ies'}.`)
  }
  const showSelectedNeighborhood = () => {
    if (!selectedIds.length) { setNotice('Select at least one entity first.'); return }
    setComponentOnly(false)
    setNeighborhoodOnly(value => !value)
    setNotice(neighborhoodOnly ? 'Showing the full graph again.' : `Showing the selected ${analysisDepth}-hop neighborhood.`)
  }
  const showSelectedComponents = () => {
    if (!selectedIds.length) { setNotice('Select at least one entity first.'); return }
    setNeighborhoodOnly(false)
    setComponentOnly(value => !value)
    setNotice(componentOnly ? 'Showing the full graph again.' : 'Showing the connected component containing the selection.')
  }
  const clearSelection = () => { setSelectedId(''); selectedIdRef.current = ''; setSelectedIds([]); setPathNodeIds([]); setPathEdgeIds([]); setNeighborhoodOnly(false); setComponentOnly(false); setNotice('Graph selection cleared.') }
  const applyViewSnapshot = (snapshot: ViewSnapshot, skipHistory = false) => {
    if (skipHistory) historySkipKeyRef.current = JSON.stringify(snapshot)
    setQuery(snapshot.query); setKind(snapshot.kind); setFocusId(snapshot.focusId); setFocusDepth(snapshot.focusDepth)
    setGraphOrientation(snapshot.graphOrientation); setLayoutMode(snapshot.layoutMode); setEdgeCurve(snapshot.edgeCurve)
    setShowArrows(snapshot.showArrows); setShowEdgeLabels(snapshot.showEdgeLabels); setLabelPolicy(snapshot.labelPolicy)
    setVisibleRelationshipKinds(snapshot.visibleRelationshipKinds); setSelectedIds(snapshot.selectedIds); setSelectedId(snapshot.selectedIds[0] || ''); selectedIdRef.current = snapshot.selectedIds[0] || ''
    setNeighborhoodOnly(snapshot.neighborhoodOnly); setComponentOnly(snapshot.componentOnly); setAnalysisDepth(snapshot.analysisDepth)
  }
  const saveView = () => {
    const name = savedViewName.trim()
    if (!name) { setNotice('Enter a name before saving this graph view.'); return }
    setSavedViews(current => [{ name, snapshot: viewSnapshot, updatedAt: new Date().toISOString() }, ...current.filter(item => item.name !== name)])
    setSavedViewName(''); setNotice(`Saved graph view “${name}”.`)
  }
  const deleteView = (name: string) => { setSavedViews(current => current.filter(item => item.name !== name)); setNotice(`Deleted graph view “${name}”.`) }
  const undoView = () => {
    const current = historyCurrentRef.current
    const target = historyPastRef.current.pop()
    if (!current || !target) return
    historyFutureRef.current = [current, ...historyFutureRef.current]
    applyViewSnapshot(target, true)
    setHistoryAvailable({ undo: historyPastRef.current.length > 0, redo: true }); setNotice('Undid the last graph view change.')
  }
  const redoView = () => {
    const current = historyCurrentRef.current
    const target = historyFutureRef.current.shift()
    if (!current || !target) return
    historyPastRef.current = [...historyPastRef.current, current]
    applyViewSnapshot(target, true)
    setHistoryAvailable({ undo: true, redo: historyFutureRef.current.length > 0 }); setNotice('Redid the graph view change.')
  }
  const zoomToSelection = () => {
    const cy = cyRef.current
    if (!cy) return
    const ids = selectedIds.length ? selectedIds : selected ? [selected.id] : []
    const collection = cy.collection()
    ids.forEach(id => { const node = cy.$id(id); if (node.length) collection.merge(node) })
    if (collection.length) { cy.animate({ fit: { eles: collection, padding: 70 }, duration: 250 }); setNotice(`Zoomed to ${collection.length} selected entit${collection.length === 1 ? 'y' : 'ies'}.`) }
    else setNotice('No selected entities are in the current rendered view.')
  }
  const resetGraphView = () => {
    setQuery(''); setKind(''); setFocusId(''); setFocusDepth(1); setSelectedId(''); selectedIdRef.current = ''; setSelectedIds([]); setPathNodeIds([]); setPathEdgeIds([]); setNeighborhoodOnly(false); setComponentOnly(false); setVisibleRelationshipKinds(null); setLayoutMode('force'); setEdgeCurve('bezier'); setShowArrows(false); setShowEdgeLabels(false); setLabelPolicy('smart'); setRelationshipGrouping('all'); setGraphOrientation('portrait'); setNotice('Graph view reset to the investigation overview.')
    window.setTimeout(() => cyRef.current?.fit(undefined, 40), 50)
  }
  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if (!(event.ctrlKey || event.metaKey) || event.key.toLowerCase() !== 'z') return
      event.preventDefault()
      if (event.shiftKey) redoView(); else undoView()
    }
    document.addEventListener('keydown', onKeyDown)
    return () => document.removeEventListener('keydown', onKeyDown)
  })

  return <main className={`page feature-page network-page${graphExpanded ? ' network-expanded' : ''}`}>
    <label className="graph-quick-grouping">Edge density<select value={relationshipGrouping} onChange={event => setRelationshipGrouping(event.target.value as RelationshipGrouping)}><option value="all">All relationships</option><option value="pairs">Group parallel edges</option></select></label>
    {transformJob.data && <section className={`panel graph-transform-activity transform-${transformJob.data.status}`}><header><div><b>Transform activity</b><span>{transformJob.data.transform_id} · {transformJob.data.status}</span></div>{['queued', 'running'].includes(transformJob.data.status) ? <button onClick={() => cancelTransform.mutate()} disabled={cancelTransform.isPending}>Cancel</button> : ['failed', 'cancelled'].includes(transformJob.data.status) ? <button onClick={() => retryTransform.mutate()} disabled={retryTransform.isPending}>Retry</button> : <span className="transform-complete">{transformJob.data.outputs_ingested ? 'Outputs ingested' : 'Completed'}</span>}</header><div className="transform-progress-track"><span style={{ width: `${transformJob.data.progress_total ? Math.min(100, Math.round(((transformJob.data.progress_completed || 0) / transformJob.data.progress_total) * 100)) : ['completed', 'failed', 'cancelled'].includes(transformJob.data.status) ? 100 : 18}%` }} /></div><div className="transform-activity-meta"><span>{transformJob.data.progress_total ? `${transformJob.data.progress_completed || 0}/${transformJob.data.progress_total} steps` : transformJob.data.message || 'Waiting for Docker operation…'}</span><button onClick={() => setTransformJobId('')} aria-label="Dismiss transform activity">×</button></div>{transformJob.data.logs?.length ? <details><summary>Recent logs ({transformJob.data.logs.length})</summary><pre>{transformJob.data.logs.slice(-8).join('\n')}</pre></details> : null}</section>}
    <Link className="back-link" to={`/projects/${projectId}`}>← Project workspace</Link><canvas ref={minimapRef} className="graph-minimap" aria-label="Graph minimap" onClick={event => { const cy = cyRef.current; const canvas = minimapRef.current; if (!cy || !canvas || !cy.nodes().length) return; const rect = canvas.getBoundingClientRect(); const bounds = cy.nodes().boundingBox(); const scale = Math.min((rect.width - 12) / Math.max(bounds.w, 1), (rect.height - 12) / Math.max(bounds.h, 1)); const point = { x: bounds.x1 + (event.clientX - rect.left - 6) / scale, y: bounds.y1 + (event.clientY - rect.top - 6) / scale }; let nearest = cy.nodes()[0]; let distance = Number.POSITIVE_INFINITY; cy.nodes().forEach(node => { const dx = node.position('x') - point.x; const dy = node.position('y') - point.y; const nextDistance = dx * dx + dy * dy; if (nextDistance < distance) { distance = nextDistance; nearest = node } }); cy.animate({ center: { eles: nearest } }, { duration: 250 }) }} />
    <header className="page-header"><div><p className="eyebrow">Investigation workbench</p><h1>Network Graph</h1><p className="muted">Explore derived attack-surface data, analyst entities, evidence, and Docker-backed transforms.</p></div><button className="graph-icon-button" title="New investigation" aria-label="New investigation" onClick={() => createInvestigation.mutate()} disabled={createInvestigation.isPending}>＋</button></header>
    <section className="panel graph-toolbar"><select aria-label="Investigation" value={investigationId} onChange={event => { setInvestigationId(event.target.value); setSelectedId(''); setSelectedIds([]); setFocusId('') }}>{investigations.data?.map(item => <option value={item.id} key={item.id}>{item.name}</option>)}</select><input value={query} onChange={event => setQuery(event.target.value)} placeholder="Search entities…"/><select aria-label="Entity type" value={kind} onChange={event => setKind(event.target.value)}><option value="">All entity types</option>{kinds.map(item => <option value={item} key={item}>{item}</option>)}</select><nav className="graph-icon-actions" aria-label="Graph actions"><button className="graph-icon-button" title="Fit graph" aria-label="Fit graph" onClick={() => cyRef.current?.fit(undefined, 40)}>⌖</button><button className="graph-icon-button" title="Auto layout" aria-label="Auto layout" onClick={() => cyRef.current?.layout({ name: 'cose', animate: true, padding: 40, numIter: 250 }).run()}>✣</button><button className="graph-icon-button" title="Expand neighbors without replacing the current graph" aria-label="Expand neighbors" onClick={() => expandNeighbors.mutate()} disabled={!selected || expandNeighbors.isPending}>⊕</button><button className="graph-icon-button" title="Shortest path to target" aria-label="Shortest path to target" onClick={findPathToTarget} disabled={!selected}>⌁</button><button className={`graph-icon-button${lassoMode ? ' active' : ''}`} title={lassoMode ? 'Disable area selection' : 'Enable area selection'} aria-label={lassoMode ? 'Disable area selection' : 'Enable area selection'} onClick={() => setLassoMode(value => !value)}>▧</button><button className="graph-icon-button" title="Selection tools and saved sets" aria-label="Selection tools and saved sets" onClick={() => setSelectionMenuOpen(value => !value)}>▦</button><button className={`graph-icon-button${displayMenuOpen ? ' active' : ''}`} title="Display and relationship controls" aria-label="Display and relationship controls" onClick={() => setDisplayMenuOpen(value => !value)}>◍</button><button className="graph-icon-button" title={`Rotate graph to ${graphOrientation === 'portrait' ? 'landscape' : 'portrait'}`} aria-label={`Rotate graph to ${graphOrientation === 'portrait' ? 'landscape' : 'portrait'}`} onClick={() => setGraphOrientation(value => value === 'portrait' ? 'landscape' : 'portrait')}>↻</button><select aria-label="Focus depth" title="Focus depth" value={focusDepth} onChange={event => setFocusDepth(Number(event.target.value))}><option value={1}>D1</option><option value={2}>D2</option><option value={3}>D3</option></select><button className="graph-icon-button" title="Focus selected entity" aria-label="Focus selected entity" onClick={() => selected && setFocusId(selected.id)} disabled={!selected}>◎</button>{focusId && <button className="graph-icon-button" title="Return to overview" aria-label="Return to overview" onClick={() => setFocusId('')}>◌</button>}{selectedIds.length > 0 && <button className="graph-icon-button" title="Clear selection and path" aria-label="Clear selection and path" onClick={clearSelection}>×</button>}<button className="graph-icon-button" title="Export investigation JSON" aria-label="Export investigation JSON" onClick={exportGraph} disabled={!graphView}>⇩</button><button className="graph-icon-button" title={graphExpanded ? 'Exit full workspace' : 'View graph full workspace'} aria-label={graphExpanded ? 'Exit full workspace' : 'View graph full workspace'} onClick={() => setGraphExpanded(value => !value)}>⛶</button></nav>{displayMenuOpen && <div className="graph-display-popover"><header><b>Display &amp; relationships</b><button onClick={() => setDisplayMenuOpen(false)} aria-label="Close display controls">×</button></header><label className="graph-display-row">Layout<select value={layoutMode} onChange={event => setLayoutMode(event.target.value as LayoutMode)}><option value="force">Force-directed</option><option value="hierarchy">Hierarchy</option><option value="radial">Radial target map</option><option value="concentric">Concentric</option><option value="timeline">Timeline</option></select></label><label className="graph-display-row">Edge shape<select value={edgeCurve} onChange={event => setEdgeCurve(event.target.value as EdgeCurve)}><option value="bezier">Curved</option><option value="straight">Straight</option><option value="taxi">Orthogonal</option></select></label><label className="graph-display-check"><input type="checkbox" checked={showArrows} onChange={event => setShowArrows(event.target.checked)}/> Arrowheads</label><label className="graph-display-check"><input type="checkbox" checked={showEdgeLabels} onChange={event => setShowEdgeLabels(event.target.checked)}/> Relationship labels</label><div className="graph-display-kinds"><small>Relationship types</small>{relationshipKinds.length ? relationshipKinds.map(item => <label key={item}><input type="checkbox" checked={!visibleRelationshipKinds || visibleRelationshipKinds.includes(item)} onChange={() => setVisibleRelationshipKinds(current => { if (!current) return relationshipKinds.filter(kind => kind !== item); return current.includes(item) ? current.filter(kind => kind !== item) : [...current, item] })}/>{item}</label>) : <span>No relationships</span>}<button onClick={() => setVisibleRelationshipKinds(null)} disabled={!visibleRelationshipKinds}>Show all types</button></div></div>}{selectionMenuOpen && <div className="graph-selection-popover"><header><b>Selection tools</b><button onClick={() => setSelectionMenuOpen(false)} aria-label="Close selection tools">×</button></header><div className="graph-selection-actions"><button onClick={() => setLassoMode(value => !value)}>{lassoMode ? 'Disable area select' : 'Enable area select'}</button><button onClick={copySelection} disabled={!selectedEntities.length}>Copy values</button><button onClick={exportSelection} disabled={!selectedEntities.length}>Export selection</button><button onClick={showSelectedNeighborhood} disabled={!selectedIds.length}>{neighborhoodOnly ? 'Show full graph' : 'Selected neighborhood'}</button><button onClick={showSelectedComponents} disabled={!selectedIds.length}>{componentOnly ? 'Show full graph' : 'Connected component'}</button></div><label className="graph-selection-depth">Neighborhood depth<select value={analysisDepth} onChange={event => setAnalysisDepth(Number(event.target.value))}><option value={1}>1 hop</option><option value={2}>2 hops</option><option value={3}>3 hops</option></select></label><form className="graph-selection-save" onSubmit={event => { event.preventDefault(); saveSelectionSet() }}><input value={selectionSetName} onChange={event => setSelectionSetName(event.target.value)} placeholder="Selection set name"/><button disabled={!selectedIds.length || !selectionSetName.trim()}>Save set</button></form>{selectionSets.length > 0 && <div className="graph-selection-sets"><small>Saved sets</small>{selectionSets.map(item => <div key={item.name}><button onClick={() => applySelectionSet(item)} title={`Load ${item.name}`}>{item.name}<span>{item.ids.length}</span></button><button onClick={() => deleteSelectionSet(item.name)} aria-label={`Delete ${item.name}`}>×</button></div>)}</div>}</div>}<span className="graph-count">{visibleEntities.length} entities · {graphView?.relationships.length || 0} links · {graphOrientation}{selectedIds.length > 0 ? ` · ${selectedIds.length} selected` : ''}{neighborhoodOnly ? ' · neighborhood' : componentOnly ? ' · component' : ''}{visibleRelationshipKinds && visibleRelationshipKinds.length ? ` · ${visibleRelationshipKinds.length}/${relationshipKinds.length} edge types` : visibleRelationshipKinds ? ' · no edge types' : ''}</span></section>
    <section className="graph-secondary-toolbar"><div className="graph-secondary-group"><button onClick={undoView} disabled={!historyAvailable.undo} title="Undo (Ctrl/Cmd+Z)">↶ Undo</button><button onClick={redoView} disabled={!historyAvailable.redo} title="Redo (Ctrl/Cmd+Shift+Z)">↷ Redo</button><button onClick={zoomToSelection} disabled={!selectedIds.length && !selected}>Zoom selection</button><button onClick={() => cyRef.current?.fit(undefined, 40)}>Overview</button><button onClick={resetGraphView}>Reset view</button></div><label className="graph-secondary-label">Labels<select value={labelPolicy} onChange={event => setLabelPolicy(event.target.value as LabelPolicy)}><option value="smart">Smart zoom</option><option value="all">Always show</option><option value="none">Hide labels</option></select></label>{viewsMenuOpen && <div className="graph-views-popover"><header><b>Saved views</b><button onClick={() => setViewsMenuOpen(false)} aria-label="Close saved views">×</button></header><form onSubmit={event => { event.preventDefault(); saveView() }}><input value={savedViewName} onChange={event => setSavedViewName(event.target.value)} placeholder="View name"/><button disabled={!savedViewName.trim()}>Save current</button></form>{savedViews.length ? <div className="graph-saved-views">{savedViews.map(item => <div key={item.name}><button onClick={() => { applyViewSnapshot(item.snapshot); setNotice(`Loaded graph view “${item.name}”.`) }}>{item.name}</button><button onClick={() => deleteView(item.name)} aria-label={`Delete ${item.name}`}>×</button></div>)}</div> : <small>No saved views yet.</small>}</div>}<button className={`graph-views-toggle${viewsMenuOpen ? ' active' : ''}`} onClick={() => setViewsMenuOpen(value => !value)}>▣ Views{savedViews.length ? ` · ${savedViews.length}` : ''}</button></section>
    {notice && <p className="success">{notice}</p>}{graph.isError && <p className="error">Could not load the investigation graph.</p>}{transformJob.data && <p className={transformJob.data.status === 'failed' ? 'error' : 'success'}>Transform {transformJob.data.status}{transformJob.data.message ? ` — ${transformJob.data.message}` : ''}</p>}{focusId && <p className="graph-focus-notice">Focused on <code>{focusId}</code> through depth {focusDepth}. <button onClick={() => setFocusId('')}>Return to overview</button></p>}{filteredEntities.length > MAX_RENDER_NODES && <p className="graph-limit-notice">Large graph detected: showing {MAX_RENDER_NODES} of {filteredEntities.length} matching entities for responsive rendering. Use search or type filters to narrow the view.</p>}
    <section className="graph-workbench"><section className="panel graph-canvas"><div ref={hostRef} className="cytoscape-host" />{touchLabel && <div className="graph-touch-label" style={{ left: touchLabel.x, top: touchLabel.y }} aria-live="polite">{touchLabel.text}</div>}{mobileTouchNodeId && selected && <div className="graph-touch-actions" aria-label="Selected node actions"><button onClick={() => setMobileInspectorOpen(true)}>Inspect</button><button onClick={() => { setFocusId(mobileTouchNodeId); setMobileMenuId('') }}>Focus</button><button onClick={() => void navigator.clipboard?.writeText(selected.value || selected.label)}>Copy</button></div>}{mobileMenuId && selected && <div className="graph-touch-menu" aria-label="Node actions"><button onClick={() => { setMobileInspectorOpen(true); setMobileMenuId('') }}>◉<span>Inspect</span></button><button onClick={() => { setFocusId(mobileMenuId); setMobileMenuId('') }}>◎<span>Focus</span></button><button onClick={() => { void navigator.clipboard?.writeText(selected.value || selected.label); setMobileMenuId('') }}>⧉<span>Copy</span></button><button onClick={() => setMobileMenuId('')}>×<span>Close</span></button></div>}{graph.isPending && !graph.data && <div className="graph-overlay">Loading graph…</div>}{!visibleEntities.length && !graph.isPending && <div className="graph-overlay">No entities match the active filters.</div>}</section>
      <aside className={`panel graph-inspector${mobileInspectorOpen ? ' mobile-inspector-open' : ''}`}>{selected ? <><header><div><b>{selected.label}</b><span>{selected.kind} · {selected.source}</span></div><button className="graph-mobile-close" onClick={() => setMobileInspectorOpen(false)} aria-label="Close inspector">×</button><button className="danger" onClick={() => { if (selected.source === 'manual' && confirm('Delete this analyst entity?')) deleteEntity.mutate(selected.id) }}>Delete</button></header><dl className="graph-properties"><dt>Value</dt><dd><code>{selected.value || selected.label}</code></dd><dt>Confidence</dt><dd>{Math.round(selected.confidence * 100)}%</dd><dt>Relationships</dt><dd>{selectedRelationships.length}</dd></dl><div className="graph-actions"><select value={selectedTransform} onChange={event => { setSelectedTransform(event.target.value); setTransformParameters({}) }}><option value="">Run transform…</option>{transforms.data?.filter(item => item.input_types.includes(selected.kind)).map(item => <option value={item.id} key={item.id}>{item.display_name}{item.requires_approval ? ' · approval' : ''}</option>)}</select><button disabled={!selectedTransform || transform.isPending} onClick={() => transform.mutate()}>Run</button></div>{activeTransform && <div className="transform-parameters"><small>{activeTransform.description || 'Transform parameters'}</small>{activeTransform.parameters.map(parameter => { const key = String(parameter.key || ''); return <label key={key}>{String(parameter.label || key)}<input value={transformParameters[key] || String(parameter.default || '')} onChange={event => setTransformParameters({ ...transformParameters, [key]: event.target.value })} placeholder={key} /></label> })}<span className={`transform-risk risk-${activeTransform.mode}`}>{activeTransform.mode}{activeTransform.requires_approval ? ' · approval required' : ''}</span></div>}<div className="graph-relationships"><b>Relationships</b>{selectedRelationships.map(edge => <span key={edge.id}>{edge.kind}: {edge.source_id === selected.id ? edge.target_id : edge.source_id}</span>)}</div><div className="graph-provenance"><b>Provenance</b>{selected.provenance.length ? selected.provenance.map((item, index) => <span key={`${String(item.source || item.tool_key || 'source')}-${index}`}>{String(item.source || item.tool_key || 'source')}{item.tool_key ? ` · ${String(item.tool_key)}` : ''}{item.transform_job_id ? ` · job ${String(item.transform_job_id)}` : ''}</span>) : <small>No source metadata recorded.</small>}</div><details><summary>Properties</summary><pre>{JSON.stringify(selected.data, null, 2)}</pre></details></> : <div className="empty">Select an entity to inspect it.</div>}
        <form className="graph-form" onSubmit={event => { event.preventDefault(); if (entityDraft.label.trim()) createEntity.mutate() }}><b>Add analyst entity</b><input value={entityDraft.kind} onChange={event => setEntityDraft({ ...entityDraft, kind: event.target.value })} placeholder="Type"/><input value={entityDraft.label} onChange={event => setEntityDraft({ ...entityDraft, label: event.target.value })} placeholder="Label"/><input value={entityDraft.value} onChange={event => setEntityDraft({ ...entityDraft, value: event.target.value })} placeholder="Canonical value"/><button>Add entity</button></form>
        <form className="graph-form" onSubmit={event => { event.preventDefault(); if (relationshipDraft.source_id && relationshipDraft.target_id) createRelationship.mutate() }}><b>Add relationship</b><input value={relationshipDraft.source_id} onChange={event => setRelationshipDraft({ ...relationshipDraft, source_id: event.target.value })} placeholder="Source entity ID"/><input value={relationshipDraft.target_id} onChange={event => setRelationshipDraft({ ...relationshipDraft, target_id: event.target.value })} placeholder="Target entity ID"/><input value={relationshipDraft.kind} onChange={event => setRelationshipDraft({ ...relationshipDraft, kind: event.target.value })} placeholder="Relationship type"/><button>Add link</button></form>
      </aside></section>
  </main>
}
