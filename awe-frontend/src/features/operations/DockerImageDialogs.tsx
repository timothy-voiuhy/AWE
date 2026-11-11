import { useState, type RefObject } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { api } from '../../api/client'
import './docker-image-dialogs.css'

export function DockerImageDialogs({ pullDialog, buildDialog }: { pullDialog: RefObject<HTMLDialogElement>; buildDialog: RefObject<HTMLDialogElement> }) {
  const qc = useQueryClient()
  const [image, setImage] = useState('')
  const [tag, setTag] = useState('')
  const [dockerfile, setDockerfile] = useState('FROM alpine:3.19\nRUN mkdir -p /output\n')
  const refreshImages = () => Promise.all([
    qc.invalidateQueries({ queryKey: ['docker', 'images'] }),
    qc.invalidateQueries({ queryKey: ['docker', 'tools'] }),
  ])
  const pull = useMutation({ mutationFn: (reference: string) => api.pullImage(reference), onSuccess: refreshImages })
  const build = useMutation({ mutationFn: (input: { tag: string; dockerfile: string }) => api.buildImage(input.tag, input.dockerfile), onSuccess: refreshImages })

  return <>
    <dialog ref={pullDialog} className="docker-image-dialog" aria-labelledby="docker-pull-title" onClose={() => { if (!pull.isPending) pull.reset() }} onClick={event => { if (event.target === event.currentTarget) pullDialog.current?.close() }}>
      <header><div><b id="docker-pull-title">Pull another image</b><p>Download an image to this Docker host. The tool-image inventory shows images referenced by registered tools.</p></div><button type="button" className="subtle" aria-label="Close pull image dialog" onClick={() => pullDialog.current?.close()}>×</button></header>
      <form onSubmit={event => { event.preventDefault(); if (image.trim()) pull.mutate(image.trim()) }}>
        <label>Image reference<input required value={image} onChange={event => setImage(event.target.value)} placeholder="docker.io/library/alpine:latest" autoComplete="off" /></label>
        {pull.isError && <p className="error" role="alert">{pull.error.message}</p>}
        {pull.isSuccess && <p className="success" role="status">Pulled {pull.variables}.</p>}
        <footer><button type="button" className="subtle" onClick={() => pullDialog.current?.close()}>Close</button><button disabled={!image.trim() || pull.isPending}>{pull.isPending ? 'Pulling…' : 'Pull image'}</button></footer>
      </form>
    </dialog>
    <dialog ref={buildDialog} className="docker-image-dialog docker-inline-build-dialog" aria-labelledby="docker-build-title" onClose={() => { if (!build.isPending) build.reset() }} onClick={event => { if (event.target === event.currentTarget) buildDialog.current?.close() }}>
      <header><div><b id="docker-build-title">Build an inline Dockerfile</b><p>Inline builds contain only the Dockerfile. Use a custom tool when COPY/ADD build context is required.</p></div><button type="button" className="subtle" aria-label="Close build image dialog" onClick={() => buildDialog.current?.close()}>×</button></header>
      <form onSubmit={event => { event.preventDefault(); if (tag.trim() && dockerfile.trim()) build.mutate({ tag: tag.trim(), dockerfile }) }}>
        <label>Image tag<input required value={tag} onChange={event => setTag(event.target.value)} placeholder="awe/my-tool:latest" autoComplete="off" /></label>
        <label>Dockerfile<textarea required value={dockerfile} onChange={event => setDockerfile(event.target.value)} spellCheck={false} /></label>
        {build.isError && <p className="error" role="alert">{build.error.message}</p>}
        {build.isSuccess && <><p className="success" role="status">Built {build.variables.tag}.</p><details className="docker-inline-build-output" open><summary>Build output</summary><pre>{build.data.logs.join('\n') || 'Build completed.'}</pre></details></>}
        <footer><button type="button" className="subtle" onClick={() => buildDialog.current?.close()}>Close</button><button disabled={!tag.trim() || !dockerfile.trim() || build.isPending}>{build.isPending ? 'Building…' : 'Build image'}</button></footer>
      </form>
    </dialog>
  </>
}
