import json
import os
import subprocess
import sys
from pathlib import Path
import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'dockerfiles'))
sys.path.insert(0, str(ROOT / 'src'))
from awe_validation.engine import PROFILES, execute
from awe_validation.transport import Transport, parse_context
from containers.tool_registry import TOOL_REGISTRY
from containers.parsers import PARSERS
from validation_fixture import PRIVATE, JWT, start_server


@pytest.fixture(scope='module')
def servers(tmp_path_factory):
    directory = tmp_path_factory.mktemp('validation-tls')
    cert, key = directory / 'cert.pem', directory / 'key.pem'
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', str(key), '-out', str(cert), '-days', '1', '-subj', '/CN=localhost'], check=True, capture_output=True)
    http, http_thread = start_server()
    https, https_thread = start_server(tls=True, cert=cert, key=key)
    yield http, https
    for server, thread in ((http, http_thread), (https, https_thread)):
        server.shutdown(); server.server_close(); thread.join(timeout=2)


def configuration(server, slug, vulnerable):
    url = f'http://127.0.0.1:{server.server_port}/{slug}'
    mode = 'vulnerable' if vulnerable else 'safe'
    headers = {'Authorization': 'Bearer ' + (JWT if slug.startswith('jwt_') else 'owner-secret'), 'Cookie': 'sid=primary-cookie-secret', 'X-Fixture-Mode': mode}
    context = {'headers': headers, 'negative_control_url': '/negative-control', 'logout': {'url': '/logout', 'method': 'POST'}, 'valid_steps': [{'url': '/workflow/allow'}], 'invalid_steps': [{'url': '/workflow/skip'}]}
    peer = {'headers': {'Authorization': 'Bearer peer-secret', 'X-Fixture-Mode': mode}}
    return {'url': url, 'request_context': json.dumps(context), 'peer_context': json.dumps(peer), 'parameter': 'next', 'marker': PRIVATE, 'canary_file': 'research-canary.txt', 'callback_context': json.dumps({'callback_url': f'http://127.0.0.1:{server.server_port}/callback', 'monitor_url': f'http://127.0.0.1:{server.server_port}/monitor', 'monitor_headers': {'Authorization': 'Bearer monitor-secret'}}), 'max_requests': 12, 'timeout': 2, 'delay': 0, 'allow_state_change': True}


@pytest.mark.parametrize('profile', PROFILES, ids=lambda profile: profile['slug'])
@pytest.mark.parametrize('vulnerable', [True, False], ids=['vulnerable', 'protected'])
def test_positive_and_negative_controlled_fixtures(profile, vulnerable, servers, tmp_path):
    server = servers[1] if profile['slug'] == 'mixed_content' else servers[0]
    server.callbacks.clear(); server.requests.clear(); server.logged_out = False
    config = configuration(server, profile['slug'], vulnerable)
    if profile['slug'] == 'mixed_content':
        config.update(url=config['url'].replace('http:', 'https:', 1), insecure_tls=True)
    report = execute(profile['id'], config, tmp_path)
    assert len(report['requests']) <= 12
    if vulnerable and profile['slug'] == 'graphql_batching':
        assert report['observations'] and not report['findings']
    elif vulnerable:
        assert report['findings'], report
        assert report['outcome'] == 'findings', report
    else:
        assert not report['findings'], report
        if profile['slug'] in {'ssrf_callback', 'xxe_callback'}:
            assert report['outcome'] == 'inconclusive'
        else:
            assert not report['errors'], report
    serialized = (tmp_path / 'validation-report.json').read_text()
    for secret in ['owner-secret', 'primary-cookie-secret', 'peer-secret', 'monitor-secret', 'server-session-secret', 'response-secret', 'private-source-secret', PRIVATE, JWT]:
        assert secret not in serialized
    parsed = PARSERS[profile['id']](str(tmp_path))
    assert len(parsed) == len(report['findings'])
    assert all(result.verification in {'candidate', 'verified_behavior'} and result.evidence['requests'] for result in parsed)
    assert all(result.url.startswith(config['url']) for result in parsed)


def test_controls_reject_shared_identities_and_public_markers(servers, tmp_path):
    server = servers[0]
    config = configuration(server, 'authz_horizontal', True)
    config['peer_context'] = config['request_context']
    assert execute('awe_authz_horizontal', config, tmp_path)['outcome'] == 'inconclusive'
    config = configuration(server, 'anonymous_access', True)
    config['request_context'] = json.dumps({'headers': {'Authorization': 'Bearer owner-secret', 'X-Fixture-Mode': 'vulnerable'}, 'negative_control_url': '/anonymous_access'})
    assert execute('awe_anonymous_access', config, tmp_path)['outcome'] == 'inconclusive'


def test_budget_truncation_tls_and_write_gates_are_inconclusive(servers, tmp_path):
    config = configuration(servers[0], 'cors', True); config['max_requests'] = 1
    report = execute('awe_cors', config, tmp_path)
    assert report['outcome'] == 'inconclusive' and len(report['requests']) == 1
    config = configuration(servers[0], 'oversized', True); config['max_bytes'] = 1024
    report = execute('awe_security_headers', config, tmp_path)
    assert report['outcome'] == 'inconclusive' and report['requests'][0]['truncated']
    config = configuration(servers[1], 'security_headers', False); config['url'] = config['url'].replace('http:', 'https:', 1)
    assert execute('awe_security_headers', config, tmp_path)['outcome'] == 'inconclusive'
    config = configuration(servers[0], 'xxe_callback', True); config['allow_state_change'] = False
    assert execute('awe_xxe_callback', config, tmp_path)['outcome'] == 'inconclusive'


def test_context_origin_and_header_constraints(servers):
    base = f'http://127.0.0.1:{servers[0].server_port}/'
    captured = parse_context({'raw_request': 'POST /resource?token=secret HTTP/1.1\r\nAuthorization: Bearer secret\r\nContent-Type: application/json\r\n\r\n{"x":1}'}, base)
    assert captured['method'] == 'POST' and captured['headers']['Authorization'] == 'Bearer secret'
    with pytest.raises(ValueError): parse_context({'raw_request': 'GET https://outside.invalid/a HTTP/1.1\r\n\r\n'}, base)
    with pytest.raises(ValueError): parse_context({'url': 'https://outside.invalid/'}, base)
    transport = Transport({'url': base, 'delay': 0})
    with pytest.raises(ValueError): transport.request('https://outside.invalid/')
    with pytest.raises(ValueError): transport.request(headers={'X-Test': 'one\r\nInjected: two'})
    assert transport.records == []


def test_adapters_keep_secrets_out_of_commands_and_logs():
    for profile in PROFILES:
        tool = TOOL_REGISTRY[profile['id']]
        assert tool.execution_mode == 'active' and tool.output_channels == ('logs', 'structured', 'artifacts')
        assert profile['id'] in PARSERS and Path(tool.dockerfile).is_file()
        assert 'owner-secret' not in tool.build_command(url='http://local/', request_context='owner-secret')
        env = tool.build_environment(url='http://local/', request_context='owner-secret')
        assert 'owner-secret' in env['AWE_VALIDATION_CONFIG']
        assert all(spec['type'] == 'secret' for spec in tool.param_spec() if spec['key'] in {'request_context', 'peer_context', 'callback_context', 'marker'})


def test_coverage_metadata_and_api_match_the_registry():
    from awe_backend.routes.coverage import transform_coverage
    from awe_backend.config import Settings
    data = transform_coverage(Settings())
    assert data['native_transform_count'] == len(PROFILES) == 29
    native = [row for row in data['rows'] if row['verification'] == 'fixture_verified']
    assert {key for row in native for key in row['tool_keys']} == {profile['id'] for profile in PROFILES}
    assert all(key in TOOL_REGISTRY for row in data['rows'] if not row.get('optional') for key in row['tool_keys'])
    assert all(row['inputs'] and row['limitations'] for row in data['rows'])
    generated = (ROOT / 'awe-frontend/src/docs/vulnerability-coverage.md').read_text()
    assert all(row['area'] in generated for row in data['rows'])


def test_graph_evidence_redacts_native_request_contexts(tmp_path):
    from types import SimpleNamespace
    from unittest.mock import Mock, patch
    from awe_backend.projects import ProjectStore
    from awe_backend.schemas import ProjectCreate, DockerToolRun, DockerOperation
    from awe_backend.routes.docker import run_docker_tool
    from awe_backend.config import Settings
    store = ProjectStore(tmp_path)
    project = store.create(ProjectCreate(name='Validation evidence', target='http://lab.invalid'))
    manager = Mock()
    manager.start_tool.return_value = DockerOperation(id='native-test', kind='tool.awe_authz_horizontal', status='queued')
    payload = DockerToolRun(params={'url': 'http://lab.invalid/private', 'request_context': 'primary-secret', 'peer_context': 'peer-secret', 'marker': 'private-marker'}, approved=True, ingest_to_graph=True)
    with patch('awe_backend.routes.docker._ensure_investigation', return_value=SimpleNamespace(id='inv')), patch('awe_backend.routes.docker._ingest_graph_results', return_value=0), patch('awe_backend.routes.docker._create_evidence_record') as evidence:
        run_docker_tool(project.id, 'awe_authz_horizontal', payload, store, Mock(), manager, lambda _: Mock(), Settings(workspace_dir=tmp_path))
        callback = manager.start_tool.call_args.args[4]
        callback([], tmp_path)
        parameters = evidence.call_args.args[2].data['parameters']
        assert parameters['request_context'] == parameters['peer_context'] == parameters['marker'] == '[redacted]'
        assert parameters['url'] == '[redacted]'


def test_native_urls_are_sensitive_without_hiding_the_editable_field():
    from awe_backend.schemas import TransformManifest
    from awe_backend.routes.transform_catalog import _redact_transform_params
    tool = TOOL_REGISTRY['awe_cors']
    manifest = TransformManifest(id='docker:awe_cors', tool_key='awe_cors', display_name=tool.display_name, parameters=tool.param_spec())
    public, private = _redact_transform_params(manifest, {'url': 'https://lab.invalid/?token=private-query-token'})
    assert public['url'] == '[redacted]' and 'private-query-token' in private['url']
    assert next(spec for spec in tool.param_spec() if spec['key'] == 'url')['type'] == 'text'


def test_html_boolean_attributes_are_valid_inputs():
    from awe_validation.exposure_checks import Page
    page = Page('<form method><input name><link rel><script src="data:text/javascript,void(0)"></script></form>')
    assert page.forms == [{'method': 'GET', 'fields': ['']}]


def test_chaining_preserves_credentials_but_uses_the_new_selected_target(monkeypatch, tmp_path):
    from types import SimpleNamespace
    from unittest.mock import Mock
    from awe_backend.routes import graph
    from awe_backend.projects import ProjectStore
    from awe_backend.config import Settings
    from awe_backend.schemas import ProjectCreate, GraphEntity, TransformManifest, TransformStart, DockerOperation
    store = ProjectStore(tmp_path)
    project = store.create(ProjectCreate(name='Native handoff', target='https://lab.invalid'))
    entity = GraphEntity(id='selected', kind='url', label='Current object', value='https://lab.invalid/current')
    manifest = TransformManifest(id='docker:awe_cors', tool_key='awe_cors', display_name='CORS', input_types=['url'], parameters=TOOL_REGISTRY['awe_cors'].param_spec())
    monkeypatch.setattr(graph, '_graph_transforms', lambda *_: [manifest])
    monkeypatch.setattr(graph, '_graph_store', lambda *_: SimpleNamespace(get=lambda *_: SimpleNamespace(id='inv')))
    monkeypatch.setattr(graph, '_graph_bundle', lambda *_: SimpleNamespace(entities=[entity]))
    monkeypatch.setattr(graph, '_GRAPH_TRANSFORM_JOBS', {})
    monkeypatch.setattr(graph, '_GRAPH_TRANSFORM_SECRETS', {'source': {'url': 'https://lab.invalid/old?token=old-secret', 'request_context': '{"headers":{"Authorization":"Bearer fixture"}}'}})
    launch = Mock(return_value=DockerOperation(id='operation', kind='tool.awe_cors', status='queued'))
    monkeypatch.setattr(graph, '_launch_graph_transform_operation', launch)
    result = graph.start_graph_transform(project.id, TransformStart(transform_id=manifest.id, entity_ids=['selected'], investigation_id='inv', source_job_id='source'), store=store, settings=Settings(workspace_dir=tmp_path), docker_operations=Mock(), docker_service=Mock(), repositories=Mock())
    params = launch.call_args.args[7]
    assert params['url'] == 'https://lab.invalid/current'
    assert 'Bearer fixture' in params['request_context']
    assert result.parameters['url'] == result.parameters['request_context'] == '[redacted]'


def test_cli_bad_context_is_retained_without_secret_leak(tmp_path):
    environment = {**os.environ, 'AWE_VALIDATION_CONFIG': json.dumps({'url': 'http://127.0.0.1/', 'request_context': '{"Authorization":"secret-value"'})}
    result = subprocess.run([sys.executable, str(ROOT / 'dockerfiles/awe_validation/cli.py'), '--profile', 'awe_cors', '--output', str(tmp_path)], env=environment, capture_output=True, text=True)
    assert result.returncode == 2
    assert 'secret-value' not in result.stdout + result.stderr + (tmp_path / 'validation-report.json').read_text()
    assert json.loads((tmp_path / 'validation-report.json').read_text())['outcome'] == 'inconclusive'


@pytest.mark.skipif(os.environ.get('AWE_TEST_DOCKER') != '1', reason='Enable controlled Docker validation with AWE_TEST_DOCKER=1')
@pytest.mark.parametrize('profile', PROFILES, ids=lambda profile: profile['slug'])
def test_real_docker_runner_profiles(profile, servers, tmp_path):
    server = servers[1] if profile['slug'] == 'mixed_content' else servers[0]
    server.callbacks.clear(); server.requests.clear(); server.logged_out = False
    config = configuration(server, profile['slug'], True)
    if profile['slug'] == 'mixed_content':
        config.update(url=config['url'].replace('http:', 'https:', 1), insecure_tls=True)
    environment = {**os.environ, 'AWE_VALIDATION_CONFIG': json.dumps(config)}
    result = subprocess.run(['docker', 'run', '--rm', '--network', 'host', '-e', 'AWE_VALIDATION_CONFIG', '-v', f'{tmp_path}:/output', 'awe/validation:1', '--profile', profile['id']], env=environment, capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr
    report = json.loads((tmp_path / 'validation-report.json').read_text())
    assert report['findings'] or profile['slug'] == 'graphql_batching'
    assert not report['errors']
