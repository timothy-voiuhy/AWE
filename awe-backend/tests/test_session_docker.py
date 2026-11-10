"""Opt-in Linux/Docker test of the real PTY and backend-restart boundary."""
import asyncio
import json
import os
import subprocess
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from awe_backend.config import Settings
from awe_backend.projects import ProjectStore
from awe_backend.run_outputs import RunOutputs
from awe_backend.schemas import ProjectCreate
from awe_backend.session_service import SessionService


@pytest.mark.skipif(os.environ.get('AWE_TEST_DOCKER') != '1', reason='Set AWE_TEST_DOCKER=1 for real Docker PTY test')
def test_real_container_pty_survives_manager_restart(tmp_path):
    import docker
    binary = tmp_path / 'pty-runner'
    subprocess.run(['go', 'build', '-o', str(binary), 'pty-runner/main.go'], check=True, env={**os.environ, 'CGO_ENABLED':'0'})
    async def scenario():
        settings = Settings(workspace_dir=tmp_path, pty_runner_path=binary)
        store = ProjectStore(tmp_path)
        project = store.create(ProjectCreate(name='PTY fixture', target='localhost'))
        project_dir = store.project_dir(project.id)
        output = project_dir / 'output'; output.mkdir()
        record = RunOutputs(project_dir, 'test-run')
        record.update(kind='tool.fixture', status='running', output_dir=str(output))
        client = docker.from_env()
        container = client.containers.create('nginx:1.27-alpine', entrypoint=['/tmp/awe-pty-runner'], command=['serve','sh','-c','echo fixture-ready; while read line; do echo "received:$line"; done'], volumes={str(output):{'bind':'/output','mode':'rw'}}, labels={'awe.session':'true'}, name=f'awe_pty_fixture_{project.id}')
        manager = SessionService(settings)
        await manager.start()
        try:
            row = manager.create_container(project_dir, 'test-run', container, output, SimpleNamespace(display_name='Fixture'))
            for _ in range(50):
                if 'fixture-ready' in ''.join(e['data'] for e in record.events()['events']): break
                await asyncio.sleep(.1)
            assert 'fixture-ready' in ''.join(e['data'] for e in record.events()['events'])
            await manager.shutdown()
            container.reload()
            assert container.status == 'running'
            recovered = SessionService(settings)
            await recovered.start()
            recovered.writers[row['id']] = 'writer'
            await recovered.control(project.id, row['id'], 'writer', {'type':'input','data':'after-restart\n'})
            await recovered.control(project.id, row['id'], 'writer', {'type':'resize','cols':100,'rows':24})
            for _ in range(50):
                if 'received:after-restart' in ''.join(e['data'] for e in record.events()['events']): break
                await asyncio.sleep(.1)
            assert 'received:after-restart' in ''.join(e['data'] for e in record.events()['events'])
            await recovered.terminate(project.id, row['id'])
            assert recovered.get(project.id, row['id'])['status'] == 'terminated'
            await recovered.shutdown()
        finally:
            await manager.shutdown()
            try: container.remove(force=True)
            except docker.errors.NotFound: pass
    asyncio.run(scenario())
