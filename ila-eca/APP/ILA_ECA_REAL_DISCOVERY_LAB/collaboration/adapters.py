"""Provider-only REST adapters. No model, lifecycle authority or automatic retries."""

from dataclasses import dataclass
from urllib.parse import quote, urlencode, urlsplit
import json
import re
import ssl
import urllib.request
import urllib.error
from ILA_ECA_REAL_DISCOVERY_LAB.llm.cloud import parse

Q = lambda value: quote(str(value), safe='')


class ServiceError(RuntimeError):
    def __init__(self, code, status=None):
        self.code = code
        self.status = status
        super().__init__(code)


def origin(value):
    u = urlsplit(value)
    if (
        u.scheme != 'https'
        or not u.hostname
        or u.username
        or u.password
        or u.query
        or u.fragment
        or u.path not in ('', '/')
    ):
        raise PermissionError('SERVICE_HTTPS_ORIGIN_REQUIRED')
    return value.rstrip('/')


class HTTPS:
    """Credentials remain in memory; redirects and retries are disabled."""

    def __init__(
        self, credential, *, timeout=60, max_bytes=8 * 1024 * 1024, header='Authorization'
    ):
        if (
            not callable(credential)
            or not 0 < timeout
            or type(max_bytes) is not int
            or max_bytes <= 0
        ):
            raise ValueError('SERVICE_RUNTIME_INVALID')
        self.credential = credential
        self.timeout = timeout
        self.max_bytes = max_bytes
        self.header = header

    def __call__(self, method, url, body=None):
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *args, **kwargs):
                return None

        token = self.credential()
        if not isinstance(token, str) or not token or any(x.isspace() for x in token):
            raise ServiceError('CREDENTIAL_UNAVAILABLE')
        headers = {
            self.header: ('Bearer ' + token if self.header == 'Authorization' else token),
            'Accept': 'application/json',
        }
        if body is not None:
            headers['Content-Type'] = 'application/json'
        data = (
            json.dumps(body, ensure_ascii=False, allow_nan=False).encode()
            if body is not None
            else None
        )
        opener = urllib.request.build_opener(
            NoRedirect(), urllib.request.HTTPSHandler(context=ssl.create_default_context())
        )
        try:
            with opener.open(
                urllib.request.Request(url, data=data, headers=headers, method=method),
                timeout=self.timeout,
            ) as r:
                raw = r.read(self.max_bytes + 1)
                if len(raw) > self.max_bytes:
                    raise ServiceError('RESPONSE_CAPACITY_EXCEEDED')
                if token.encode() in raw:
                    raise ServiceError('CREDENTIAL_IN_RESPONSE_DENIED')
                return raw
        except urllib.error.HTTPError as e:
            # Provider bodies can contain private request material; never log exceptions/headers.
            e.close()
            raise ServiceError('HTTP_' + str(e.code), e.code) from None
        except (TimeoutError, ConnectionError, OSError):
            raise ServiceError('TRANSPORT_RESULT_UNKNOWN') from None


class GoogleAPI:
    def __init__(self, transport, calendar_ids, *, execution_kind='LIVE'):
        if execution_kind not in {'LIVE', 'MOCK', 'REPLAY'}:
            raise ValueError('SERVICE_EXECUTION_KIND_INVALID')
        self.http = transport
        self.calendars = frozenset(calendar_ids)
        self.execution_kind = execution_kind

    def get(self, url):
        return parse(self.http('GET', url))

    def pages(self, url, key, params=None):
        params = dict(params or {})
        seen = set()
        items = []
        while True:
            result = self.get(url + '?' + urlencode(params))
            part = result.get(key, [])
            if not isinstance(part, list):
                raise ServiceError('GOOGLE_LIST_INVALID')
            items.extend(part)
            n = result.get('nextPageToken')
            if not n:
                return items
            if n in seen:
                raise ServiceError('GOOGLE_PAGINATION_LOOP')
            seen.add(n)
            params['pageToken'] = n

    def events(self, calendar_id, start, end):
        if calendar_id not in self.calendars:
            raise PermissionError('CALENDAR_NOT_ALLOWED')
        return self.pages(
            'https://www.googleapis.com/calendar/v3/calendars/' + Q(calendar_id) + '/events',
            'items',
            {'timeMin': start, 'timeMax': end, 'singleEvents': 'true', 'orderBy': 'startTime'},
        )

    def conferences(self, meeting_code, start, end):
        if not re.fullmatch('[a-z]{3}-[a-z]{4}-[a-z]{3}', meeting_code):
            raise ValueError('MEET_CODE_INVALID')
        return self.pages(
            'https://meet.googleapis.com/v2/conferenceRecords',
            'conferenceRecords',
            {
                'filter': f'space.meeting_code = "{meeting_code}" AND start_time <= "{end}" AND end_time >= "{start}"'
            },
        )

    def artifacts(self, conference):
        if not re.fullmatch(r'conferenceRecords/[A-Za-z0-9_-]+', conference):
            raise ValueError('CONFERENCE_NAME_INVALID')
        base = 'https://meet.googleapis.com/v2/' + conference
        transcripts = self.pages(base + '/transcripts', 'transcripts')
        recordings = self.pages(base + '/recordings', 'recordings')
        return transcripts, recordings

    def entries(self, name):
        if not re.fullmatch(r'conferenceRecords/[A-Za-z0-9_-]+/transcripts/[A-Za-z0-9_-]+', name):
            raise ValueError('TRANSCRIPT_NAME_INVALID')
        return self.pages(
            'https://meet.googleapis.com/v2/' + name + '/entries', 'transcriptEntries'
        )

    def drive_metadata(self, file_id):
        if not re.fullmatch(r'[A-Za-z0-9_-]+', file_id):
            raise ValueError('DRIVE_ID_INVALID')
        base = 'https://www.googleapis.com/drive/v3/files/' + Q(file_id)
        return self.get(
            base
            + '?'
            + urlencode(
                {
                    'fields': 'id,name,mimeType,version,modifiedTime,md5Checksum,capabilities(canDownload)'
                }
            )
        )

    def drive(self, file_id):
        before = self.drive_metadata(file_id)
        base = 'https://www.googleapis.com/drive/v3/files/' + Q(file_id)
        if (
            before.get('id') != file_id
            or before.get('capabilities', {}).get('canDownload') is False
        ):
            raise PermissionError('DRIVE_DOWNLOAD_NOT_ALLOWED')
        docs = before.get('mimeType') == 'application/vnd.google-apps.document'
        raw = self.http('GET', base + ('/export?mimeType=text%2Fplain' if docs else '?alt=media'))
        after = self.drive_metadata(file_id)
        if before != after:
            raise ServiceError('DRIVE_VERSION_CHANGED_DURING_READ')
        return before, raw


class GitLabAPI:
    def __init__(self, transport, base_url, project, *, execution_kind='LIVE'):
        if execution_kind not in {'LIVE', 'MOCK', 'REPLAY'}:
            raise ValueError('SERVICE_EXECUTION_KIND_INVALID')
        self.execution_kind = execution_kind
        self.http = transport
        self.origin = origin(base_url)
        self.project = str(project)
        if not self.project:
            raise ValueError('GITLAB_PROJECT_REQUIRED')
        self.base = self.origin + '/api/v4/projects/' + Q(project)

    def get(self, path, params=None):
        return parse(
            self.http('GET', self.base + path + ('?' + urlencode(params) if params else ''))
        )

    def post(self, path, body):
        if path not in {'/repository/commits', '/merge_requests'}:
            raise PermissionError('GITLAB_WRITE_NOT_ALLOWED')
        return parse(self.http('POST', self.base + path, body))

    def branch(self, branch):
        return self.get('/repository/branches/' + Q(branch))['commit']['id']

    def commit(self, branch, start_sha, files, message):
        import base64

        return self.post(
            '/repository/commits',
            {
                'branch': branch,
                'start_sha': start_sha,
                'commit_message': message + ' [skip ci]',
                'actions': [
                    {
                        'action': 'create',
                        'file_path': p,
                        'encoding': 'base64',
                        'content': base64.b64encode(b).decode(),
                    }
                    for p, b in files.items()
                ],
            },
        )['id']

    def file(self, path, sha):
        return self.http(
            'GET', self.base + '/repository/files/' + Q(path) + '/raw?' + urlencode({'ref': sha})
        )

    def commit_info(self, sha):
        return self.get('/repository/commits/' + Q(sha))

    def mrs(self, branch):
        results = []
        page = 1
        while True:
            part = self.get(
                '/merge_requests',
                {
                    'state': 'all',
                    'scope': 'all',
                    'source_branch': branch,
                    'per_page': 100,
                    'page': page,
                },
            )
            if not isinstance(part, list):
                raise ServiceError('MR_LIST_INVALID')
            results.extend(part)
            if len(part) < 100:
                return results
            page += 1

    def create_mr(self, branch, target, marker):
        return self.post(
            '/merge_requests',
            {
                'source_branch': branch,
                'target_branch': target,
                'title': 'Draft: ILA/ECA ' + marker,
                'description': marker,
                'remove_source_branch': False,
            },
        )

    def mr(self, iid):
        return self.get('/merge_requests/' + Q(iid))

    def approvals(self, iid):
        return self.get('/merge_requests/' + Q(iid) + '/approval_state')

    def approval_policy(self):
        return self.get('/approvals')

    def user_approvals(self, iid):
        return self.get('/merge_requests/' + Q(iid) + '/approvals')

    def member(self, user_id):
        return self.get('/members/all/' + Q(user_id))

    def assign_reviewer(self, iid, user_id, existing_ids=()):
        # Narrow write capability: does not expose general PUT, approve or merge.
        if type(iid) is not int or iid <= 0 or type(user_id) is not int or user_id <= 0:
            raise ValueError('GITLAB_REVIEW_ASSIGNMENT_INVALID')
        ids = sorted(set(existing_ids) | {user_id})
        if any(type(n) is not int or n <= 0 for n in ids):
            raise ValueError('GITLAB_REVIEW_ASSIGNMENT_INVALID')
        return parse(
            self.http('PUT', self.base + '/merge_requests/' + Q(iid), {'reviewer_ids': ids})
        )
