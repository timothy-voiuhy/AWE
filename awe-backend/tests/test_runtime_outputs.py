import asyncio
import io
import json
import tarfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from awe_backend.config import Settings
from awe_backend.poc_sources import unpack_source
from awe_backend.projects import ProjectStore
from awe_backend.run_outputs import RunOutputs
from awe_backend.schemas import ProjectCreate
from awe_backend.session_service import SessionService


def test_durable_events_limits_and_artifact_containment(tmp_path):
    output = tmp_path / 'output'
    output.mkdir()
    (output / 'report.txt').write_text('research output')
    outside = tmp_path / 'private.txt'
    outside.write_text('outside output')
    (output / 'escape.txt').symlink_to(outside)
    record = RunOutputs(tmp_path, 'run-1')
    record.update(output_dir=str(output), status='running')
    record.append('one')
    record.append('two', 'stderr')
    loaded = RunOutputs(tmp_path, 'run-1')
    assert [e['data'] for e in loaded.events(after=1)['events']] == ['two']
    assert loaded.events(search='ONE')['events'][0]['sequence'] == 1
    files = loaded.collect()
    assert [f['name'] for f in files] == ['report.txt']
    assert loaded.artifact(files[0]['id'])[0].read_text() == 'research output'
    record.append('dropped', limit=1)
    assert record.metadata()['logs_truncated'] is True
    count = record.metadata()['last_sequence']
    record.append('not recorded')
    assert record.metadata()['last_sequence'] == count
    with pytest.raises(ValueError):
        record.collect(['../*'])


def test_evidence_capture_keeps_an_immutable_artifact_copy(tmp_path):
    from awe_backend.routes.run_outputs import OutputEvidence, promote_evidence, download_evidence_snapshot
    store = ProjectStore(tmp_path)
    project = store.create(ProjectCreate(name='Evidence', target='localhost'))
    project_dir = store.project_dir(project.id)
    folder = project_dir / 'output'; folder.mkdir()
    path = folder / 'report.txt'; path.write_text('original report')
    record = RunOutputs(project_dir, 'evidence-run')
    record.update(output_dir=str(folder))
    artifact = record.collect()[0]
    evidence = promote_evidence(project.id, 'evidence-run', OutputEvidence(title='Reviewed report', artifact_id=artifact['id']), store)
    path.write_text('later mutation')
    response = download_evidence_snapshot(project.id, evidence.id, store)
    assert Path(response.path).read_text() == 'original report'


def test_archive_rejects_traversal_and_links(tmp_path):
    for name, kind in [('../escape', tarfile.REGTYPE), ('link', tarfile.SYMTYPE)]:
        raw = io.BytesIO()
        with tarfile.open(fileobj=raw, mode='w') as archive:
            info = tarfile.TarInfo(name); info.type = kind; info.size = 1 if kind == tarfile.REGTYPE else 0
            archive.addfile(info, io.BytesIO(b'x') if info.size else None)
        with pytest.raises(ValueError):
            unpack_source(raw.getvalue(), tmp_path / 'source')


def test_tcp_and_listener_sessions_detach_persist_and_terminate(tmp_path):
    async def scenario():
        settings = Settings(workspace_dir=tmp_path, callback_bind_host='127.0.0.1', callback_port_start=45100, callback_port_end=45109)
        store = ProjectStore(tmp_path)
        project = store.create(ProjectCreate(name='Sessions', target='localhost'))
        manager = SessionService(settings)
        def payload(kind, **values):
            return SimpleNamespace(kind=kind, host='127.0.0.1', port=0, run_id='', label='', expected_peer='', **values)
        row = await manager.create(project.id, store.project_dir(project.id), payload('listener'))
        reader, writer = await asyncio.open_connection('127.0.0.1', row['port'])
        writer.write(b'callback hello\n'); await writer.drain()
        await asyncio.sleep(.1)
        session = manager.get(project.id, row['id'])
        assert session['status'] == 'active'
        record = RunOutputs(store.project_dir(project.id), row['run_id'])
        assert 'callback hello' in record.events()['events'][0]['data']
        with pytest.raises(KeyError):
            manager.get('another-project', row['id'])
        manager.writers[row['id']] = 'first'
        with pytest.raises(PermissionError):
            await manager.control(project.id, row['id'], 'second', {'type':'input','data':'no'})
        await manager.control(project.id, row['id'], 'second', {'type':'take_control'})
        await manager.control(project.id, row['id'], 'second', {'type':'input','data':'operator input\n'})
        assert await asyncio.wait_for(reader.readline(), 1) == b'operator input\n'
        # Releasing a browser writer leaves the underlying socket usable.
        manager.writers.pop(row['id'])
        assert manager.get(project.id, row['id'])['status'] == 'active'
        await manager.shutdown()
        recovered = SessionService(settings)
        await recovered.start()
        assert recovered.get(project.id, row['id'])['status'] == 'disconnected'
        await recovered.shutdown()
        writer.close(); await writer.wait_closed()
    asyncio.run(scenario())


def test_parser_optional_contract_and_catalog(tmp_path, monkeypatch):
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'src'))
    from containers.custom_tools import register_custom_tool, remove_custom_tool
    from awe_backend.routes.transform_catalog import _graph_transforms
    from awe_backend.schemas import DockerToolCreate
    payload = DockerToolCreate(key='logs_fixture', display_name='Logs fixture', category='vuln', image='alpine:3.19', command_template='echo hello', dockerfile='FROM alpine:3.19', input_types=['domain'], output_types=[], output_channels=['logs'])
    folder = tmp_path / 'logs_fixture'; folder.mkdir()
    (folder / 'tool.json').write_text(payload.model_dump_json(exclude={'dockerfile','parser'}))
    (folder / 'Dockerfile').write_text(payload.dockerfile)
    register_custom_tool(str(folder))
    try:
        transform = next(t for t in _graph_transforms(Settings()) if t.tool_key == 'logs_fixture')
        assert transform.output_types == []
        assert transform.output_channels == ['logs']
    finally:
        from containers.tool_registry import TOOL_REGISTRY, TOOL_CATEGORIES
        TOOL_REGISTRY.pop('logs_fixture', None)
        TOOL_CATEGORIES['vuln'].remove('logs_fixture')


def test_archive_build_pins_source_and_registers_without_parser(tmp_path, monkeypatch):
    import zipfile
    from unittest.mock import Mock, patch
    from awe_backend.routes.pocs import PocCreate
    from awe_backend.poc_sources import build_poc
    from config import config
    from containers.tool_registry import TOOL_REGISTRY, TOOL_CATEGORIES
    monkeypatch.setattr(config, 'CUSTOM_TOOLS_DIR', str(tmp_path / 'custom'))
    raw = io.BytesIO()
    with zipfile.ZipFile(raw, 'w') as archive:
        archive.writestr('poc.py', 'print("fixture")')
    payload = PocCreate(key='poc_fixture', display_name='PoC fixture', command_template='python /poc/poc.py', dockerfile='FROM python:3.12-slim\nCOPY . /poc', input_types=['domain'], output_types=[])
    record = RunOutputs(tmp_path, 'poc-build')
    record.update(kind='poc.build', status='running', output_dir=str(tmp_path / '.awe-builds' / 'poc-build'))
    client = Mock()
    client.api.build.return_value = iter([{'stream':'built fixture'}])
    with patch('awe_backend.docker_service.DockerService._client', return_value=client):
        build_poc(tmp_path, 'poc-build', payload, raw.getvalue(), Settings())
    try:
        assert record.metadata()['status'] == 'completed'
        tool = TOOL_REGISTRY['poc_fixture']
        assert tool.source_metadata['kind'] == 'archive'
        assert len(tool.source_metadata['sha256']) == 64
        assert tool.image.startswith('awe/poc-poc_fixture:')
        assert tool.output_channels == ('logs','artifacts')
        assert Path(tool.dockerfile).parent.joinpath('poc.py').is_file()
    finally:
        TOOL_REGISTRY.pop('poc_fixture', None)
        if 'poc_fixture' in TOOL_CATEGORIES['vuln']:
            TOOL_CATEGORIES['vuln'].remove('poc_fixture')


def test_ssh_and_outbound_tcp_adapters_keep_credentials_out_of_storage(tmp_path):
    import asyncssh
    from awe_backend.routes.sessions import SessionCreate
    class Server(asyncssh.SSHServer):
        def begin_auth(self, username): return True
        def password_auth_supported(self): return True
        def validate_password(self, username, password): return username == 'fixture' and password == 'never-store-this'
    async def shell(process):
        process.stdout.write('ssh-ready\n')
        async for line in process.stdin:
            process.stdout.write('ssh-echo:' + line)
    async def echo(reader, writer):
        try:
            while data := await reader.read(4096):
                writer.write(data); await writer.drain()
        finally:
            writer.close()
    async def scenario():
        settings = Settings(workspace_dir=tmp_path)
        store = ProjectStore(tmp_path)
        project = store.create(ProjectCreate(name='Adapter fixtures', target='localhost'))
        project_dir = store.project_dir(project.id)
        ssh = await asyncssh.create_server(Server, '127.0.0.1', 0, server_host_keys=[asyncssh.generate_private_key('ssh-rsa')], process_factory=shell)
        tcp = await asyncio.start_server(echo, '127.0.0.1', 0)
        manager = SessionService(settings)
        try:
            payloads = [SessionCreate(kind='ssh', host='127.0.0.1', port=ssh.get_port(), username='fixture', password='never-store-this', trust_host_key=True), SessionCreate(kind='tcp', host='127.0.0.1', port=tcp.sockets[0].getsockname()[1])]
            for payload in payloads:
                row = await manager.create(project.id, project_dir, payload)
                manager.writers[row['id']] = 'fixture'
                await manager.control(project.id, row['id'], 'fixture', {'type':'input','data':'adapter-input\n'})
                record = RunOutputs(project_dir, row['run_id'])
                for _ in range(50):
                    if 'adapter-input' in ''.join(e['data'] for e in record.events()['events']): break
                    await asyncio.sleep(.02)
                assert 'adapter-input' in ''.join(e['data'] for e in record.events()['events'])
                await manager.terminate(project.id, row['id'])
            assert 'never-store-this' not in (project_dir / '.awe-sessions.json').read_text()
        finally:
            await manager.shutdown()
            ssh.close(); await ssh.wait_closed()
            tcp.close(); await tcp.wait_closed()
    asyncio.run(scenario())
