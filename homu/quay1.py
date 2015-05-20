# API wrappers for quay
import re
import functools
from contextlib import contextmanager

import requests

from . import utils
from .utils import lazy_debug

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
            trigger_uuid = utils.get_query(resp.url)['newtrigger'][0]
            csrf_token = CSRF_TOKEN_RE.search(resp.text).groups()[0]
            activate_url = self.api_url('repository', namespace, repo,
                                        'trigger', trigger_uuid, 'activate',
                                        query={'_csrf_token': csrf_token})
            config = {'build_source': git_url, 'subdir':'/'}
            resp = sess.post(activate_url,
                             json={'config': config})
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

# TODO: classmethods?
def register(g, repo, settings):
    logger = g.logger
    q = Quay(g.cfg['quay'])
    lazy_debug(logger, lambda: 'Going to create quay repo: {}'.format(repo.name))
    # private by default
    private = settings.get('private', not settings.get('public', False))
    repo_info = q.create_repo(repo.name, private=private)
    settings.update(repo_info)
    lazy_debug(logger, lambda: 'Quay repo created: {} '.format(repo_info))
    q_name = repo_info['name']
    lazy_debug(logger, lambda: 'Going to create build trigger for: {} in {}'.format(
        repo.ssh_url, q_name))
    q_build_trigger = q.create_build_trigger(q_name, repo.ssh_url)
    lazy_debug(logger, lambda: 'Build trigger created in {}: {}'.format(
        q_name, q_build_trigger['id']))
    # Web hook to call to trigger build on push
    settings['webhook'] = q_build_trigger['webhook']
    lazy_debug(logger, lambda: 'Going to register deploy key in {}/{}'.format(
        repo.owner, repo.name))
    deploy_key = repo.create_key('Quay.io Builder', q_build_trigger['ssh'])
    # Save the key id, so we can remove it later
    settings['ssh'] = deploy_key.id
    settings['secret'] = quay_secret = settings.get('secret',
                                                    utils.random_string())
    settings['username'] = quay_username = settings.get('username',
                                                        utils.random_string())
    quay_webhook = g.make_webhook_url('quay', quay_username, quay_secret)
    lazy_debug(logger, lambda: 'Registering {} as status webhooks in {}'.format(
        quay_webhook, q_name))
    q.add_web_hook(q_name, EVENT_BUILD_SUCCESS, quay_webhook)
    q.add_web_hook(q_name, EVENT_BUILD_FAILURE, quay_webhook)

def unregister(g, repo, settings):
    logger = g.logger
    lazy_debug(logger, lambda: 'Going to remove quay repo: {}'.format(settings))
    ignore = functools.partial(utils.ignore, logger=g.logger)
    q = Quay(g.cfg['quay'])
    lazy_debug(logger, lambda: 'Going to remove deploy key from: {}/{}'.format(
        repo.owner, repo.name))
    ignore(lambda: utils.maybe_call(settings, 'ssh', repo.delete_key))
    # build trigger and webhooks will go away along with repo
    lazy_debug(logger, lambda: 'Going to delete repo from quay: {}'.format(
        settings))
    ignore(lambda: utils.maybe_call(settings, 'name', q.delete_repo))

def push_hook(g, push_event, settings):
    ref = push_event['ref'][len('refs/heads/'):]
    if ref in settings['build_branches']:
        # create push event
        # quay wants some fields in push event like avatar_url of author
        # and we have to request them :(
        author = g.gh.user(push_event['head_commit']['author']['username'])
        committer = g.gh.user(push_event['head_commit']['committer']['username'])
        quay_push_event = {
            'commit': push_event['head_commit']['id'][:7],
            'commit_push_event': {
                'author': {
                    'username': author.login,
                    'url': author.html_url,
                    'avatar_url': author.avatar_url
                },
                'committer': {
                    'username': committer.login,
                    'url': committer.html_url,
                    'avatar_url': committer.avatar_url
                },
                'date': push_event['head_commit']['timestamp'],
                'message': push_event['head_commit']['message'],
                'url': push_event['head_commit']['url']
            },
            'default_branch': push_event['repository']['default_branch'],
            'ref': push_event['ref']
        }
        lazy_debug(g.logger, lambda: 'Sending event to quay: {}'.format(
            quay_push_event))
        r = requests.post(settings['webhook'], json=quay_push_event)
        lazy_debug(g.logger, lambda: 'Quay response: {}/{}'.format(
            r.status_code, r.text))
