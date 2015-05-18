import os
import json
import urllib
import logging
import binascii
import posixpath

import github3

def github_set_ref(repo, ref, sha, *, force=False, auto_create=True):
    url = repo._build_url('git', 'refs', ref, base_url=repo._api)
    data = {'sha': sha, 'force': force}

    try:
        js = repo._json(repo._patch(url, data=json.dumps(data)), 200)
    except github3.models.GitHubError as e:
        if e.code == 422 and auto_create:
            return repo.create_ref('refs/' + ref, sha)
        else:
            raise

    return github3.git.Reference(js, repo) if js else None

class Status(github3.repos.status.Status):
    def __init__(self, info):
        super(Status, self).__init__(info)

        self.context = info.get('context')

def github_iter_statuses(repo, sha):
    url = repo._build_url('statuses', sha, base_url=repo._api)
    return repo._iter(-1, url, Status)

def github_create_status(repo, sha, state, target_url='', description='', *,
                         context=''):
    data = {'state': state, 'target_url': target_url,
            'description': description, 'context': context}
    url = repo._build_url('statuses', sha, base_url=repo._api)
    js = repo._json(repo._post(url, data=data), 201)
    return Status(js) if js else None

def remove_url_keys_from_json(json):
    if isinstance(json, dict):
        return {key: remove_url_keys_from_json(value)
                for key, value in json.items()
                if not key.endswith('url')}
    elif isinstance(json, list):
        return [remove_url_keys_from_json(value) for value in json]
    else:
        return json

def lazy_debug(logger, f):
    if logger.isEnabledFor(logging.DEBUG):
        logger.debug(f())

def maybe_call(dkt, key, func):
    if key in dkt:
        return func(dkt[key])

def update_in(dkt, key, func):
    if key in dkt:
        dkt[key] = func(dkt[key])
    return dkt

def merge_dicts(fst, snd=None, **kwargs):
    snd = snd or kwargs
    res = dict(fst)
    res.update(snd)
    return res

def random_string(n=20):
    return binascii.b2a_hex(os.urandom(n)).decode()

# Make url from components:
# make_url('http', '127.0.0.1', 12345, '/path') -> 'http://127.0.0.1:12345/path'
# make_url('http', '127.0.0.1', '/path') -> 'http://127.0.0.1/path'
# make_url('http', '127.0.0.1') -> 'http://127.0.0.1/'
# make_url('http', '127.0.0.1:12345') -> 'http://127.0.0.1:12345/'
# make_url('http', '127.0.0.1', 12345, '/path', {'var':'val'}) -> 'http://127.0.0.1:12345/path?var=val'
# make_url('http', '127.0.0.1', query={'var':'val'}) -> 'http://127.0.0.1/?var=val'
# etc.
# NOTE: last *port* arg to catch cases like make_url(**conf)
def make_url(scheme, hostname, port_or_path=None, path='/',
             query=None, username=None, password=None, port=None):
    if port_or_path and isinstance(port_or_path, int):
        port = port_or_path
    else:
        port = port
        path = port_or_path or path
    address = '{}:{}'.format(hostname, port) if port else hostname
    if username:
        if password:
            password = ':{}'.format(password)
        else:
            password = ''
        netloc = '{}{}@{}'.format(urllib.parse.quote(username), password,
                                  address)
    else:
        netloc = address
    query = urllib.parse.urlencode(query) if query else ''
    return urllib.parse.urlunsplit((scheme, netloc, path, query, ''))

def join_paths(*paths):
    # Can't use os.path.join, because *in theory* we can be on some platform
    # with different separator. So explicitly call posixpath.join
    return posixpath.join(*paths)

def get_query(url):
    return urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)

def webhook_url(cfg, path, username=None, password=None):
    return make_url(**merge_dicts(cfg['external'],
                                  path=path,
                                  username=username,
                                  password=password))
