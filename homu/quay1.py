# API wrappers for quay
import re
from contextlib import contextmanager

import requests

from . import utils

QUAY_SCHEME = 'https'
QUAY_HOSTNAME = 'quay.io'
QUAY_API = 'api/v1/'
CSRF_TOKEN_RE = re.compile(r'__token\s?=\s?\'(.*)\';')

EVENT_BUILD_SUCCESS = 'build_success'
EVENT_BUILD_FAILURE = 'build_failure'

# import http.client as http_client
# http_client.HTTPConnection.debuglevel = 1

class Quay:
    def __init__(self, cfg):
        self.access_token = cfg['access_token']
        self.username = cfg['username']
        self.password = cfg['password']
        self.hostname = cfg.get('address', QUAY_HOSTNAME)
        self.api_prefix = cfg.get('api_prefix', QUAY_API)
        self.scheme = cfg.get('scheme', QUAY_SCHEME)
        self.namespace = cfg['namespace']
        # Quay.io has it own sense of http basic auth, so we can't use
        # requests `auth` param. We need to send access_token *as is*,
        # not the result of `hashfunc(username+token)`.
        # So we craft auth header ourselves as "Bearer {access_token}"
        self.auth_header = {'Authorization': 'Bearer {}'.format(
            self.access_token)}

    def url(self, *paths, query=None):
        path = utils.join_paths(*paths)
        return utils.make_url(self.scheme, self.hostname,
                              path, query=query)
    def api_url(self, *paths, query=None):
        paths = (self.api_prefix, ) + paths
        return self.url(*paths, query=query)

    @contextmanager
    def login(self):
        session = requests.Session()
        r = session.post(self.api_url('signin'),
                              headers=self.auth_header,
                              json={'username': self.username,
                                    'password': self.password})
        # TODO: cleanup this with custom error classes
        r.raise_for_status()
        yield session
        r = session.post(self.api_url('signout'),
                              headers=self.auth_header,
                              json={})

    # TODO: change defaults
    # TODO: object to represent repo?
    # TODO: only one namespace?
    def create_repo(self, name, private=True, namespace=None):
        namespace = namespace or self.namespace
        r = requests.post(self.api_url('repository'),
                          headers=self.auth_header,
                          json={'namespace': namespace, 'repository': name,
                                'visibility': 'private' if private else 'public',
                                'description': ''})
        r.raise_for_status()
        info = r.json()
        url = self.url('repository', info['namespace'], info['name'])
        return {'url': url, 'name': info['name']}

    def delete_repo(self, name, namespace=None):
        namespace = namespace or self.namespace
        r = requests.delete(self.api_url('repository', namespace, name),
                            headers=self.auth_header)
        r.raise_for_status()

    def create_build_trigger(self, repo, git_url, namespace=None):
        namespace = namespace or self.namespace
        trigger = None
        with self.login() as sess:
            create_url = self.url('customtrigger/setup', namespace, repo)
            resp = sess.get(create_url, headers=self.auth_header)
            resp.raise_for_status()
            # TODO: handle errors and re-raise?
            trigger_uuid = utils.get_query(resp.url)['newtrigger'][0]
            csrf_token = CSRF_TOKEN_RE.search(resp.text).groups()[0]
            activate_url = self.api_url('repository', namespace, repo,
                                        'trigger', trigger_uuid, 'activate',
                                        query={'_csrf_token': csrf_token})
            config = {'build_source': git_url, 'subdir':'/'}
            resp = sess.post(activate_url,
                             json={'config': config})
            # TODO: remove trigger if not activated?
            # DELETE https://quay.io/api/v1/repository/lhtest/apitest/trigger/b48bf16e-2559-4e4e-810c-826417cec9ee?_csrf_token=xzQ7yMOL6MEvL8Cv0%2FJtCignQnAwCNvl7P0Po5NOgYhRjFgnBgyeb0O6j3QBTVy%2F
            resp.raise_for_status()
            trigger = resp.json()
        result = {
            'id': trigger['id']
        }
        interesting_keys = ['ssh', 'webhook']
        for cred in trigger['config']['credentials']:
            for key in interesting_keys:
                if key in cred['name'].lower():
                    result[key] = cred['value']
        return result

    def add_web_hook(self, repo, event, webhook_url, namespace=None):
        namespace = namespace or self.namespace
        url = self.api_url('repository', namespace, repo, 'notification/')
        r = requests.post(url,
                          headers=self.auth_header,
                          json={'method': 'webhook',
                                'event': event,
                                'config': {'url': webhook_url}})
        r.raise_for_status()
        return r.json()['uuid']
