import { useEffect, useMemo, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Link, useParams } from 'react-router-dom'

import { api, type PipelineJob, type PipelineTemplate } from '../../api/client'

type Tab = 'configuration' | 'monitor' | 'logs'
const activeStatuses = new Set(['queued', 'running', 'stopping'])

function eventToolState(job: PipelineJob | undefined) {
  const states = new Map<string, { status:string; count:number }>()
  job?.events.forEach(event => {
    const key = String(event.data.tool_key ?? '')
    if (!key) return
    if (event.type === 'pipeline.tool_started') states.set(key, { status:'running', count:0 })
    if (event.type === 'pipeline.tool_done') states.set(key, { status:String(event.data.status ?? 'completed'), count:Number(event.data.result_count ?? 0) })
  })
  return states
}

function eventToolLogs(job: PipelineJob | undefined) {
  const logs = new Map<string, string[]>()
  job?.events.forEach(event => {
    const key = String(event.data.tool_key ?? '')
    if (!key || event.type !== 'pipeline.tool_log') return
    logs.set(key, [...(logs.get(key) ?? []), String(event.data.line ?? '')])
  })
  return logs
}

export function PipelinePage() {
  const { projectId = '' } = useParams(); const qc = useQueryClient()
  const [pipelineKey,setPipelineKey]=useState(''); const [sessionId,setSessionId]=useState(''); const [jobId,setJobId]=useState(''); const [tab,setTab]=useState<Tab>('configuration'); const [checked,setChecked]=useState<Set<string>>(new Set()); const [toolLog,setToolLog]=useState('')
  const project=useQuery({queryKey:['projects',projectId],queryFn:()=>api.getProject(projectId)})
  const pipelines=useQuery({queryKey:['pipelines'],queryFn:api.listPipelines})
  const jobs=useQuery({queryKey:['projects',projectId,'pipeline-runs'],queryFn:()=>api.listPipelineRuns(projectId),refetchInterval:q=>q.state.data?.some(j=>activeStatuses.has(j.status))?1500:false})
  const sessions=useQuery({queryKey:['projects',projectId,'sessions'],queryFn:()=>api.listSessions(projectId),refetchInterval:jobs.data?.some(j=>activeStatuses.has(j.status))?2500:false})
  const toolRuns=useQuery({queryKey:['projects',projectId,'sessions',sessionId,'tool-runs'],queryFn:()=>api.listSessionToolRuns(projectId,sessionId),enabled:!!sessionId,refetchInterval:jobs.data?.some(j=>activeStatuses.has(j.status))?2000:false})
  useEffect(()=>{if(!pipelineKey&&pipelines.data?.[0])setPipelineKey(pipelines.data[0].key)},[pipelineKey,pipelines.data])
  const selectedSession=sessions.data?.find(s=>s.id===sessionId); const selectedJob=jobs.data?.find(j=>j.id===jobId)??jobs.data?.find(j=>j.session_id===sessionId)??jobs.data?.[0]; const activeJob=jobs.data?.find(j=>activeStatuses.has(j.status)); const template=pipelines.data?.find(p=>p.key===(selectedSession?.pipeline_key||pipelineKey)); const eventStates=useMemo(()=>eventToolState(selectedJob),[selectedJob]); const eventLogs=useMemo(()=>eventToolLogs(selectedJob),[selectedJob])
  useEffect(()=>{if(selectedSession)setPipelineKey(selectedSession.pipeline_key)},[selectedSession])
  useEffect(()=>{if(!sessionId&&selectedJob?.session_id)setSessionId(selectedJob.session_id)},[sessionId,selectedJob?.session_id])
  useEffect(()=>{if(!sessionId&&pipelineKey&&sessions.data?.length){const latest=sessions.data.find(s=>s.pipeline_key===pipelineKey);if(latest)setSessionId(latest.id)}},[sessionId,pipelineKey,sessions.data])
  useEffect(()=>{if(!activeJob)return;const protocol=location.protocol==='https:'?'wss':'ws';const ws=new WebSocket(`${protocol}://${location.host}/api/v1/projects/${projectId}/pipeline-runs/${activeJob.id}/events`);ws.onmessage=()=>{void qc.invalidateQueries({queryKey:['projects',projectId,'pipeline-runs']});void qc.invalidateQueries({queryKey:['projects',projectId,'sessions']});if(sessionId)void qc.invalidateQueries({queryKey:['projects',projectId,'sessions',sessionId,'tool-runs']})};return()=>ws.close()},[activeJob?.id,projectId,qc,sessionId])
  const start=useMutation({mutationFn:(input:{pipeline:string;session?:string;tools?:string[]})=>api.startPipelineRun(projectId,input.pipeline,{session_id:input.session,tool_keys:input.tools}),onSuccess:job=>{setJobId(job.id);setTab('monitor');setChecked(new Set());void qc.invalidateQueries({queryKey:['projects',projectId,'pipeline-runs']})}})
  const cancel=useMutation({mutationFn:(id:string)=>api.cancelPipelineRun(projectId,id),onSuccess:()=>void qc.invalidateQueries({queryKey:['projects',projectId,'pipeline-runs']})})
  const remove=useMutation({mutationFn:(id:string)=>api.deleteSession(projectId,id),onSuccess:()=>{setSessionId('');void qc.invalidateQueries({queryKey:['projects',projectId,'sessions']})}})
  const latestRuns=useMemo(()=>{
    const map=new Map<string,typeof toolRuns.data extends (infer T)[]|undefined?T:never>()
    toolRuns.data?.forEach(run=>{
      const previous=map.get(run.tool_key)
      if(!previous){map.set(run.tool_key,run);return}
      // Mongo can return a newly-created pending rerun (started_at=null) after
      // the completed historical run. Keep the historical log until the new
      // execution has actually produced output instead of blanking the card.
      const previousTime=previous.started_at?Date.parse(previous.started_at):0
      const runTime=run.started_at?Date.parse(run.started_at):0
      const newer=runTime>=previousTime?run:previous
      if(newer.log_lines.length===0&&previous.log_lines.length>0)
        map.set(run.tool_key,{...newer,log_lines:previous.log_lines})
      else map.set(run.tool_key,newer)
    })
    return map
  },[toolRuns.data])
  const failed=template?.steps.filter(step=>(latestRuns.get(step.tool_key)?.status??eventStates.get(step.tool_key)?.status)==='failed').map(step=>step.tool_key)??[]
  const incomplete=template?.steps.filter(step=>!['completed','skipped'].includes(latestRuns.get(step.tool_key)?.status??'pending')).map(step=>step.tool_key)??[]
  const fullLog=selectedJob?.events.map(event=>{const key=event.data.tool_key?`[${event.data.tool_key}] `:'';return `${new Date(event.timestamp).toLocaleTimeString()} ${key}${event.data.line??event.data.message??event.type}`}).join('\n')||toolRuns.data?.flatMap(run=>run.log_lines.map(line=>`[${run.tool_key}] ${line}`)).join('\n')||'No log output yet.'
  function runTools(keys:string[]){if(!template||!sessionId||!keys.length)return;start.mutate({pipeline:template.key,session:sessionId,tools:keys})}
  function selectSession(id:string){setSessionId(id);setJobId('');setChecked(new Set());setToolLog('');setTab('monitor')}
  function selectPipeline(key:string){setPipelineKey(key);const latest=sessions.data?.find(s=>s.pipeline_key===key);setSessionId(latest?.id??'');setJobId('')}
  function toggle(key:string){setChecked(old=>{const next=new Set(old);next.has(key)?next.delete(key):next.add(key);return next})}
  const stages=useMemo(()=>{const grouped=new Map<number,PipelineTemplate['steps']>();template?.steps.forEach(step=>grouped.set(step.stage,[...(grouped.get(step.stage)??[]),step]));return [...grouped.entries()].sort((a,b)=>a[0]-b[0])},[template])
  return <main className="page feature-page pipeline-page"><Link className="back-link" to={`/projects/${projectId}`}>← Project workspace</Link><header className="page-header"><div><p className="eyebrow">Automated testing</p><h1>Pipeline</h1><p className="muted">Configure, run, monitor, resume, and selectively rerun project tooling.</p></div><div className="pipeline-health"><span className={activeJob?'live-dot active':'live-dot'}>{activeJob?`${activeJob.status} · ${activeJob.progress_completed}/${activeJob.progress_total}`:'Idle'}</span><Link className="button-link" to={`/projects/${projectId}/results${sessionId?`?session=${sessionId}`:''}`}>View results</Link></div></header>
  <div className="pipeline-commandbar panel"><button disabled={!pipelineKey||!project.data?.target||!!activeJob||start.isPending} onClick={()=>start.mutate({pipeline:pipelineKey})}>▶ Run pipeline</button>{activeJob&&<button className="danger" disabled={activeJob.status==='stopping'} onClick={()=>cancel.mutate(activeJob.id)}>■ {activeJob.status==='stopping'?'Stopping…':'Stop'}</button>}<button disabled={!failed.length||!!activeJob} onClick={()=>runTools(failed)}>↺ Retry failed ({failed.length})</button><button disabled={!sessionId||!incomplete.length||!!activeJob} onClick={()=>runTools(incomplete)}>▶▶ Resume ({incomplete.length})</button><button disabled={!checked.size||!!activeJob} onClick={()=>runTools([...checked])}>Run selected ({checked.size})</button><Link className="button-link subtle" to={`/projects/${projectId}/settings`}>⚙ Settings</Link></div>
  {(start.isError||cancel.isError||remove.isError)&&<p className="error">{String((start.error||cancel.error||remove.error)?.message)}</p>}
  <section className="pipeline-workbench"><aside className="panel pipeline-history"><header><b>Session history</b><button onClick={()=>void sessions.refetch()}>↻</button></header>{sessions.data?.map(session=><button className={session.id===sessionId?'selected':''} onClick={()=>selectSession(session.id)} key={session.id}><strong>{session.pipeline_name}</strong><span>{session.status} · {new Date(session.started_at).toLocaleString()}</span><small>{session.target}</small></button>)}{!sessions.data?.length&&<div className="empty compact">No sessions yet.</div>}{sessionId&&<button className="delete-session" onClick={()=>{if(confirm('Delete this session and all of its stored results? This cannot be undone.'))remove.mutate(sessionId)}}>Delete selected session</button>}</aside>
  <div className="panel pipeline-main"><nav className="pipeline-tabs">{(['configuration','monitor','logs'] as Tab[]).map(item=><button className={tab===item?'selected':''} onClick={()=>setTab(item)} key={item}>{item==='monitor'?'Live Monitor':item==='logs'?'Full Log':'Configuration'}</button>)}</nav>
  {tab==='configuration'&&<div className="pipeline-config"><label>Pipeline<select value={pipelineKey} onChange={e=>selectPipeline(e.target.value)}>{pipelines.data?.map(p=><option value={p.key} key={p.key}>{p.name}</option>)}</select></label><label>Target<input value={project.data?.target??''} readOnly/></label>{template&&<><p>{template.description}</p><div className="pipeline-step-preview">{stages.map(([stage,steps])=><section key={stage}><b>Stage {stage}</b>{steps.map(step=><div key={step.tool_key}><code>{step.tool_key}</code><span>{step.condition}{step.input_category?` · input: ${step.input_category}`:''}</span></div>)}</section>)}</div></>}</div>}
  {tab==='monitor'&&<div className="pipeline-monitor">{!template&&<div className="empty">Select a pipeline or session.</div>}{stages.map(([stage,steps])=><details className="pipeline-stage panel" key={stage} open><summary className="pipeline-stage-summary"><span><b>Stage {stage}</b><small>{steps.length} tool{steps.length===1?'':'s'}</small></span><button type="button" disabled={!sessionId||!!activeJob} onClick={e=>{e.preventDefault();e.stopPropagation();runTools(steps.map(s=>s.tool_key))}}>↺ Run stage</button></summary><div className="pipeline-stage-tools">{steps.map(step=>{const stored=latestRuns.get(step.tool_key);const live=eventStates.get(step.tool_key);const status=live?.status??stored?.status??'pending';const count=live?.count??stored?.result_count??0;const lines=[...(stored?.log_lines??[]),...(eventLogs.get(step.tool_key)??[])];return <details className={`pipeline-tool tool-${status}`} key={step.tool_key}><summary><input type="checkbox" checked={checked.has(step.tool_key)} onChange={()=>toggle(step.tool_key)}/><div><b>{step.tool_key}</b><span>{step.condition}{stored?.error_msg?` · ${stored.error_msg}`:''}</span></div><em>{status}{count?` · ${count}`:''}</em><button type="button" disabled={!sessionId||!!activeJob} onClick={e=>{e.preventDefault();e.stopPropagation();runTools([step.tool_key])}}>↺</button></summary><pre className="pipeline-tool-log">{lines.length?lines.join('\n'):'No log output yet.'}</pre></details>})}</div></details>)}{toolLog&&<pre className="pipeline-tool-log">{toolLog}</pre>}</div>}
  {tab==='logs'&&<div className="pipeline-full-log"><button onClick={()=>navigator.clipboard.writeText(fullLog)}>Copy all</button><pre>{fullLog}</pre></div>}</div></section></main>
}
