"""Direct provider MCP clients behind the existing service interfaces.

No MCP server, model tool selection, credential discovery, write retry or
failure-triggered REST fallback. REST supplements are fixed before execution.
"""

from contextlib import closing
from hashlib import sha256
from time import perf_counter
from urllib.parse import urlsplit
import base64
import copy
import json
import os
import re
import ssl
import threading
import urllib.error
import urllib.request

from ILA_ECA_REAL_DISCOVERY_LAB.core.artifacts import canonical_json, data_digest
from ILA_ECA_REAL_DISCOVERY_LAB.llm.cloud import parse
from ILA_ECA_REAL_DISCOVERY_LAB.collaboration.adapters import (
    GoogleAPI,
    GitLabAPI,
    HTTPS,
    ServiceError,
    origin,
)

VERSIONS = {'2025-11-25', '2025-06-18', '2025-03-26'}
CALENDAR_ENDPOINT = 'https://calendarmcp.googleapis.com/mcp/v1'
DRIVE_ENDPOINT = 'https://drivemcp.googleapis.com/mcp/v1'


def validate_settings(settings, provider):
    if type(settings) is not dict or set(settings) - {
        'enabled',
        'credential_env',
        'rest_supplement',
        'calendar',
        'drive',
    }:
        raise PermissionError('MCP_CONFIG_FIELDS_INVALID')
    if provider == 'gitlab' and set(settings) & {'calendar', 'drive'}:
        raise PermissionError('MCP_CONFIG_FIELDS_INVALID')
    for name in ('enabled', 'rest_supplement', 'calendar', 'drive'):
        if name in settings and type(settings[name]) is not bool:
            raise ValueError('MCP_CONFIG_BOOLEAN_REQUIRED')
    if 'credential_env' in settings and (
        type(settings['credential_env']) is not str
        or not re.fullmatch(
            r'ILA_' + provider.upper() + r'_MCP_[A-Z0-9_]+', settings['credential_env']
        )
    ):
        raise PermissionError('MCP_CREDENTIAL_ENV_NAME_REQUIRED')
    if settings.get('enabled') and settings.get('rest_supplement') is not True:
        raise PermissionError('MCP_REQUIRED_REST_SUPPLEMENT_NOT_AUTHORIZED')
    return settings


class MCPClient:
    """Narrow Streamable HTTP client: initialize, tools/list and tools/call.

    Supports JSON and SSE replies; no reconnection, automatic replay, sampling,
    elicitation, task polling or subprocess launch. Authorization stays in memory.
    """

    def __init__(
        self,
        endpoint,
        credential,
        tools,
        *,
        timeout=60,
        max_bytes=8 * 1024 * 1024,
        record=None,
        opener=None,
    ):
        parts = urlsplit(endpoint)
        origin(parts.scheme + '://' + parts.netloc)
        if parts.query or parts.fragment or not parts.path or not callable(credential):
            raise PermissionError('MCP_ENDPOINT_OR_CREDENTIAL_INVALID')
        if type(max_bytes) is not int or max_bytes <= 0 or timeout <= 0:
            raise ValueError('MCP_RUNTIME_INVALID')
        self.endpoint = endpoint
        self.credential = credential
        self.allowed = frozenset(tools)
        self.timeout = timeout
        self.max_bytes = max_bytes
        self.record = record
        self.opener = opener
        self.session = None
        self.version = None
        self.tools = None
        self.sequence = 0
        self.lock = threading.RLock()

    def _message(self, raw, request_id):
        message = parse(raw)
        if type(message) is not dict or message.get('jsonrpc') != '2.0':
            raise ServiceError('MCP_RESPONSE_INVALID')
        if 'method' in message:
            if 'id' in message:
                raise ServiceError('MCP_SERVER_REQUEST_UNSUPPORTED')
            return None
        if type(message.get('id')) is not int or message['id'] != request_id:
            raise ServiceError('MCP_RESPONSE_ID_MISMATCH')
        if ('result' in message) == ('error' in message):
            raise ServiceError('MCP_RESPONSE_INVALID')
        if 'error' in message:
            raise ServiceError('MCP_RPC_ERROR')
        return message['result']

    def _rpc(self, method, params, traces, *, notification=False):
        self.sequence += 1
        message = {'jsonrpc': '2.0', 'method': method, 'params': params}
        if not notification:
            message['id'] = self.sequence
        token = self.credential()
        if not isinstance(token, str) or not token or any(c.isspace() for c in token):
            raise ServiceError('MCP_CREDENTIAL_UNAVAILABLE')
        headers = {
            'Authorization': 'Bearer ' + token,
            'Content-Type': 'application/json',
            'Accept': 'application/json, text/event-stream',
        }
        if self.version:
            headers['MCP-Protocol-Version'] = self.version
        if self.session:
            headers['Mcp-Session-Id'] = self.session
        if self.endpoint.endswith('/api/v4/mcp'):
            headers['X-Gitlab-Enabled-Mcp-Server-Toolsets'] = 'meta,core,repository,merge_requests'
        request = urllib.request.Request(
            self.endpoint, data=canonical_json(message).encode(), headers=headers, method='POST'
        )

        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *args, **kwargs):
                return None

        opener = (
            self.opener
            or urllib.request.build_opener(
                urllib.request.ProxyHandler({}),
                NoRedirect(),
                urllib.request.HTTPSHandler(context=ssl.create_default_context()),
            ).open
        )
        trace = {
            'method': method,
            'request': copy.deepcopy(message),
            'transport_calls': 0,
            'automatic_retry': False,
            'response': None,
            'response_body': None,
            'response_complete': False,
        }
        traces.append(trace)
        raw = bytearray()

        def retain(chunk):
            raw.extend(chunk)
            if token.encode() in raw:
                raw.clear()
                raise ServiceError('MCP_CREDENTIAL_IN_RESPONSE_DENIED')
            if len(raw) > self.max_bytes:
                raise ServiceError('MCP_RESPONSE_CAPACITY_EXCEEDED')

        try:
            trace['transport_calls'] = 1
            with closing(opener(request, timeout=self.timeout)) as response:
                trace['http_status'] = response.status
                if notification:
                    if response.status != 202:
                        raise ServiceError('MCP_NOTIFICATION_NOT_ACCEPTED')
                    return None
                if response.status != 200:
                    raise ServiceError('MCP_RESPONSE_HTTP_STATUS_INVALID')
                session = response.headers.get('Mcp-Session-Id')
                if session:
                    if not re.fullmatch(r'[\x21-\x7e]+', session):
                        raise ServiceError('MCP_SESSION_INVALID')
                    if self.session is not None and session != self.session:
                        raise ServiceError('MCP_SESSION_CHANGED')
                    self.session = session
                content_type = response.headers.get('Content-Type', '').split(';')[0].strip()
                if content_type == 'application/json':
                    retain(response.read(self.max_bytes + 1))
                    trace['response_complete'] = True
                    result = self._message(bytes(raw), message['id'])
                    if result is None:
                        raise ServiceError('MCP_RESULT_MISSING')
                elif content_type == 'text/event-stream':
                    data = []
                    while True:
                        chunk = response.readline(self.max_bytes - len(raw) + 1)
                        if not chunk:
                            raise ServiceError('MCP_STREAM_INTERRUPTED_RESULT_UNKNOWN')
                        retain(chunk)
                        line = chunk.decode('utf8').rstrip('\r\n')
                        if line.startswith('data:'):
                            data.append(line[5:].removeprefix(' '))
                        elif not line:
                            if data and any(data):
                                result = self._message('\n'.join(data).encode(), message['id'])
                                if result is not None:
                                    trace['response_complete'] = True
                                    break
                            data = []
                else:
                    raise ServiceError('MCP_CONTENT_TYPE_UNSUPPORTED')
                trace['response'] = copy.deepcopy(result)
                return result
        except urllib.error.HTTPError as exc:
            code = exc.code
            exc.close()
            trace['http_status'] = code
            raise ServiceError('MCP_HTTP_' + str(code), code) from None
        except ServiceError:
            raise
        except (TimeoutError, ConnectionError, OSError):
            raise ServiceError('MCP_TRANSPORT_RESULT_UNKNOWN') from None
        except (ValueError, TypeError, KeyError):
            raise ServiceError('MCP_RESPONSE_INVALID') from None
        finally:
            if raw:
                trace['response_body'] = {
                    'base64': base64.b64encode(raw).decode('ascii'),
                    'sha256': sha256(raw).hexdigest(),
                    'received_bytes': len(raw),
                    'complete_response': trace['response_complete'],
                }

    def _discover(self, traces):
        if self.tools is not None:
            return
        result = self._rpc(
            'initialize',
            {
                'protocolVersion': '2025-11-25',
                'capabilities': {},
                'clientInfo': {'name': 'ila-eca-provider-client', 'version': '1.0'},
            },
            traces,
        )
        if type(result) is not dict or result.get('protocolVersion') not in VERSIONS:
            raise ServiceError('MCP_PROTOCOL_VERSION_UNSUPPORTED')
        if type(result.get('capabilities', {}).get('tools')) is not dict:
            raise ServiceError('MCP_TOOLS_CAPABILITY_REQUIRED')
        self.version = result['protocolVersion']
        self._rpc('notifications/initialized', {}, traces, notification=True)
        tools = {}
        seen = set()
        cursor = None
        while True:
            page = self._rpc('tools/list', {'cursor': cursor} if cursor else {}, traces)
            if type(page) is not dict or type(page.get('tools')) is not list:
                raise ServiceError('MCP_TOOLS_INVALID')
            for tool in page['tools']:
                if type(tool) is not dict or type(tool.get('name')) is not str:
                    raise ServiceError('MCP_TOOLS_INVALID')
                if tool['name'] in tools or type(tool.get('inputSchema')) is not dict:
                    raise ServiceError('MCP_TOOL_SCHEMA_INVALID')
                tools[tool['name']] = tool
            cursor = page.get('nextCursor')
            if not cursor:
                break
            if type(cursor) is not str or cursor in seen:
                raise ServiceError('MCP_TOOL_PAGINATION_LOOP')
            seen.add(cursor)
        self.tools = tools

    def preflight(self, requirements):
        """Read tool availability before a multi-step submission reserves a write."""
        if set(requirements) - self.allowed:
            raise PermissionError('MCP_TOOL_NOT_ALLOWED')
        traces = []
        started = perf_counter()
        failure = None
        with self.lock:
            try:
                self._discover(traces)
                for name, fields in requirements.items():
                    if name not in self.tools:
                        raise ServiceError('MCP_REQUIRED_TOOL_UNAVAILABLE')
                    schema = self.tools[name]['inputSchema']
                    if schema.get('type') != 'object':
                        raise ServiceError('MCP_TOOL_SCHEMA_INCOMPATIBLE')
                    if set(schema.get('required', [])) - fields:
                        raise ServiceError('MCP_TOOL_ARGUMENTS_INCOMPATIBLE')
                    if (
                        schema.get('additionalProperties') is False
                        and fields - schema.get('properties', {}).keys()
                    ):
                        raise ServiceError('MCP_TOOL_ARGUMENTS_INCOMPATIBLE')
            except BaseException as exc:
                failure = getattr(exc, 'code', type(exc).__name__)
                raise
            finally:
                if self.record:
                    self.record(
                        {
                            'endpoint': self.endpoint,
                            'operation': 'READ_TOOL_CATALOG_PREFLIGHT',
                            'required_tools': sorted(requirements),
                            'protocol_version': self.version,
                            'elapsed_seconds': perf_counter() - started,
                            'failure': failure,
                            'transport_calls': sum(item['transport_calls'] for item in traces),
                            'traces': traces,
                            'automatic_retry': False,
                        }
                    )

    def call(self, name, arguments):
        if name not in self.allowed:
            raise PermissionError('MCP_TOOL_NOT_ALLOWED')
        started = perf_counter()
        traces = []
        failure = None
        with self.lock:
            try:
                self._discover(traces)
                tool = self.tools.get(name)
                if tool is None:
                    raise ServiceError('MCP_REQUIRED_TOOL_UNAVAILABLE')
                schema = tool['inputSchema']
                if schema.get('type') != 'object' or type(arguments) is not dict:
                    raise ServiceError('MCP_TOOL_SCHEMA_INCOMPATIBLE')
                if set(schema.get('required', [])) - arguments.keys():
                    raise ServiceError('MCP_TOOL_ARGUMENTS_INCOMPATIBLE')
                if (
                    schema.get('additionalProperties') is False
                    and set(arguments) - schema.get('properties', {}).keys()
                ):
                    raise ServiceError('MCP_TOOL_ARGUMENTS_INCOMPATIBLE')
                result = self._rpc('tools/call', {'name': name, 'arguments': arguments}, traces)
                if type(result) is not dict or result.get('isError') is True:
                    raise ServiceError('MCP_TOOL_ERROR')
                if 'isError' in result and type(result['isError']) is not bool:
                    raise ServiceError('MCP_TOOL_RESULT_INVALID')
                if 'structuredContent' in result:
                    if type(result['structuredContent']) is not dict:
                        raise ServiceError('MCP_STRUCTURED_RESULT_REQUIRED')
                    return copy.deepcopy(result['structuredContent'])
                content = result.get('content')
                if (
                    type(content) is not list
                    or len(content) != 1
                    or content[0].get('type') != 'text'
                ):
                    raise ServiceError('MCP_STRUCTURED_RESULT_REQUIRED')
                return parse(content[0]['text'].encode())
            except BaseException as exc:
                failure = getattr(exc, 'code', type(exc).__name__)
                raise
            finally:
                if self.record:
                    self.record(
                        {
                            'endpoint': self.endpoint,
                            'tool': name,
                            'protocol_version': self.version,
                            'input_schema_sha256': (
                                data_digest(self.tools[name]['inputSchema'])
                                if self.tools and name in self.tools
                                else None
                            ),
                            'elapsed_seconds': perf_counter() - started,
                            'failure': failure,
                            'transport_calls': sum(item['transport_calls'] for item in traces),
                            'traces': traces,
                            'automatic_retry': False,
                        }
                    )


class GoogleMCPAPI:
    def __init__(self, rest, calendar, drive):
        self.rest = rest
        self.calendar = calendar
        self.drive_client = drive
        self.calendars = rest.calendars
        self.execution_kind = rest.execution_kind

    def events(self, calendar_id, start, end):
        if calendar_id not in self.calendars:
            raise PermissionError('CALENDAR_NOT_ALLOWED')
        if self.calendar is None:
            return self.rest.events(calendar_id, start, end)
        arguments = {
            'calendarId': calendar_id,
            'startTime': start,
            'endTime': end,
            'orderBy': 'startTime',
            'pageSize': 100,
        }
        events = []
        seen = set()
        while True:
            page = self.calendar.call('list_events', arguments)
            if type(page) is not dict or type(page.get('events')) is not list:
                raise ServiceError('MCP_CALENDAR_EVENTS_INVALID')
            for original in page['events']:
                if type(original) is not dict:
                    raise ServiceError('MCP_CALENDAR_EVENT_INVALID')
                event = copy.deepcopy(original)
                video = event.get('conferenceData', {}).get('videoEntryPoint', {}).get('uri')
                if video or event.get('conferenceUrl'):
                    event['hangoutLink'] = video or event['conferenceUrl']
                events.append(event)
            cursor = page.get('nextPageToken')
            if not cursor:
                return events
            if type(cursor) is not str or cursor in seen:
                raise ServiceError('MCP_CALENDAR_PAGINATION_LOOP')
            seen.add(cursor)
            arguments['pageToken'] = cursor

    def drive(self, file_id):
        if self.drive_client is None:
            return self.rest.drive(file_id)
        # MCP metadata lacks the REST version/capabilities contract. Preserve it.
        before = self.rest.drive_metadata(file_id)
        if not before.get('version'):
            raise ServiceError('MCP_DRIVE_VERSION_REQUIRED')
        if (
            before.get('id') != file_id
            or before.get('capabilities', {}).get('canDownload') is False
        ):
            raise PermissionError('DRIVE_DOWNLOAD_NOT_ALLOWED')
        arguments = {'fileId': file_id}
        if before.get('mimeType') == 'application/vnd.google-apps.document':
            arguments['exportMimeType'] = 'text/plain'
        result = self.drive_client.call('download_file_content', arguments)
        if (
            type(result) is not dict
            or result.get('id') != file_id
            or type(result.get('content')) is not str
        ):
            raise ServiceError('MCP_DRIVE_CONTENT_INVALID')
        try:
            raw = base64.b64decode(result['content'], validate=True)
        except ValueError:
            raise ServiceError('MCP_DRIVE_CONTENT_INVALID') from None
        if before != self.rest.drive_metadata(file_id):
            raise ServiceError('DRIVE_VERSION_CHANGED_DURING_READ')
        return before, raw

    # These are explicit REST supplements, never fallback after an MCP error.
    def conferences(self, *args):
        return self.rest.conferences(*args)

    def artifacts(self, *args):
        return self.rest.artifacts(*args)

    def pages(self, url, key, params=None):
        # collect() uses this older narrow interface for Meet artifact pages.
        if key not in {'transcripts', 'recordings'} or not re.fullmatch(
            r'https://meet\.googleapis\.com/v2/conferenceRecords/[A-Za-z0-9_-]+/' + key,
            url,
        ):
            raise PermissionError('MCP_REST_SUPPLEMENT_ENDPOINT_DENIED')
        return self.rest.pages(url, key, params)

    def entries(self, *args):
        return self.rest.entries(*args)


class GitLabMCPAPI:
    def __init__(self, rest, client):
        self.rest = rest
        self.client = client
        self.origin, self.project, self.base = rest.origin, rest.project, rest.base
        self.execution_kind = rest.execution_kind

    def preflight_submission(self):
        self.client.preflight(
            {
                'add_commit': {'project_id', 'branch', 'start_sha', 'commit_message', 'actions'},
                'save_merge_request': {
                    'project_id',
                    'source_branch',
                    'target_branch',
                    'title',
                    'description',
                    'remove_source_branch',
                },
            }
        )

    def commit(self, branch, start_sha, files, message):
        self.client.call(
            'add_commit',
            {
                'project_id': self.project,
                'branch': branch,
                'start_sha': start_sha,
                'commit_message': message + ' [skip ci]',
                'actions': [
                    {
                        'action': 'create',
                        'file_path': path,
                        'encoding': 'base64',
                        'content': base64.b64encode(raw).decode(),
                    }
                    for path, raw in files.items()
                ],
            },
        )
        # Existing submit() independently verifies the commit parent and full bytes.
        return self.rest.branch(branch)

    def create_mr(self, branch, target, marker):
        self.client.call(
            'save_merge_request',
            {
                'project_id': self.project,
                'source_branch': branch,
                'target_branch': target,
                'title': 'Draft: ILA/ECA ' + marker,
                'description': marker,
                'remove_source_branch': False,
            },
        )
        matches = self.rest.mrs(branch)
        if len(matches) != 1:
            raise ServiceError('MCP_MR_RESULT_UNCONFIRMED_NO_RESEND')
        return matches[0]  # Existing _mr_matches() checks project, marker and commit.

    def assign_reviewer(self, iid, user_id, existing_ids=()):
        if type(iid) is not int or iid <= 0 or type(user_id) is not int or user_id <= 0:
            raise ValueError('GITLAB_REVIEW_ASSIGNMENT_INVALID')
        ids = sorted(set(existing_ids) | {user_id})
        if any(type(value) is not int or value <= 0 for value in ids):
            raise ValueError('GITLAB_REVIEW_ASSIGNMENT_INVALID')
        self.client.call(
            'save_merge_request',
            {
                'project_id': self.project,
                'merge_request_iid': iid,
                'reviewer_ids': ids,
            },
        )
        return self.rest.mr(iid)

    def __getattr__(self, name):
        if name in {
            'branch',
            'file',
            'commit_info',
            'mrs',
            'mr',
            'approvals',
            'approval_policy',
            'user_approvals',
            'member',
        }:
            return getattr(self.rest, name)
        raise AttributeError(name)


def _record(db, case_id):
    from ILA_ECA_REAL_DISCOVERY_LAB.collaboration.store import Store

    return lambda value: Store(db).evidence(case_id, 'mcp_provider_exchange_v1', value)


def google_api(db, config, case_id):
    rest = GoogleAPI(
        HTTPS(lambda: os.environ.get('ILA_GOOGLE_ACCESS_TOKEN'), **config.get('http_options', {})),
        config.get('google', {}).get('calendar_ids', []),
    )
    settings = validate_settings(config.get('google', {}).get('mcp', {}), 'google')
    if not settings.get('enabled'):
        return rest
    credential = lambda: os.environ.get(
        settings.get('credential_env', 'ILA_GOOGLE_MCP_ACCESS_TOKEN')
    )
    options = {
        key: value
        for key, value in config.get('http_options', {}).items()
        if key in {'timeout', 'max_bytes'}
    }
    record = _record(db, case_id)
    calendar = (
        MCPClient(CALENDAR_ENDPOINT, credential, {'list_events'}, record=record, **options)
        if settings.get('calendar', True)
        else None
    )
    drive = (
        MCPClient(DRIVE_ENDPOINT, credential, {'download_file_content'}, record=record, **options)
        if settings.get('drive', True)
        else None
    )
    return GoogleMCPAPI(rest, calendar, drive)


def gitlab_api(db, config, case_id):
    target = config['gitlab']
    rest = GitLabAPI(
        HTTPS(
            lambda: os.environ.get('ILA_GITLAB_TOKEN'),
            header='PRIVATE-TOKEN',
            **config.get('http_options', {}),
        ),
        target['base_url'],
        target['project_id'],
    )
    settings = validate_settings(target.get('mcp', {}), 'gitlab')
    if not settings.get('enabled'):
        return rest
    credential = lambda: os.environ.get(settings.get('credential_env', 'ILA_GITLAB_MCP_TOKEN'))
    options = {
        key: value
        for key, value in config.get('http_options', {}).items()
        if key in {'timeout', 'max_bytes'}
    }
    client = MCPClient(
        rest.origin + '/api/v4/mcp',
        credential,
        {'add_commit', 'save_merge_request'},
        record=_record(db, case_id),
        **options,
    )
    return GitLabMCPAPI(rest, client)
