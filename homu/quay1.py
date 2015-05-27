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

class QuayResource:
    def __init__(self, access_token, username, password,
                 address=QUAY_HOSTNAME, api_prefix=QUAY_API, scheme=QUAY_SCHEME,
                 parent_url=None, resource_path=[]):
        self.auth_credentials = {'username': username, 'password':password}
        # Quay.io has it own sense of http basic auth, so we can't use
        # requests `auth` param. We need to send access_token *as is*,
        # not the result of `hashfunc(username+token)`.
        # So we craft auth header ourselves as "Bearer {access_token}"
        self.auth_header = {'Authorization': 'Bearer {}'.format(
            access_token)}
        self.scheme = scheme
        self.access_token = access_token
        self.api_prefix = api_prefix
        self.address = address
        self._set_resource_api_url(parent_url, *resource_path)
        self.basic_params = dict(access_token=access_token,
                                 username=username,
                                 password=password,
                                 scheme=scheme,
                                 api_prefix=api_prefix,
                                 address=address)
        # Parameter, that need to be passed to childs
        self.inherited = {}
        # Other parameters that need to be stored
        self.details = {}

    def __repr__(self):
        return '{}: {}'.format(super().__repr__(), self.as_dict())

    # Convinient access to inherited/details
    def __getattr__(self, name):
        val = self.inherited.get(name, self.details.get(name))
        if val is None:
            raise AttributeError(name)
        else:
            return val

    def as_dict(self):
        return utils.merge_dicts(self.inherited, self.details)

    def delete(self):
        if self.resource_url is not None:
            r = requests.delete(self.resource_url,
                                headers=self.auth_header)
            r.raise_for_status()
        else:
            raise TypeError('Object does not support deletion')

    def refresh(self):
        if self.resource_url is not None and hasattr(self, 'update_details'):
            r = requests.get(self.resource_url, headers=self.auth_header)
            r.raise_for_status()
            self.update_details(r.json())
        else:
            raise TypeError('Object does not support refreshing')

    def _create_child(self, kls, *args, **kwargs):
        params = utils.merge_dicts(self.basic_params,
                                   self.inherited,
                                   kwargs,
                                   parent_url=self.resource_url)
        return kls(*args, **params)

    def _make_url(self, *paths, query=None):
        path = utils.join_paths(*paths)
        return utils.make_url(self.scheme, self.address,
                              path, query=query)
    def _api_url(self, *paths, query=None):
        paths = (self.api_prefix, ) + paths
        return self._make_url(*paths, query=query)
    def _child_api_url(self, *paths, **query_params):
        if self.resource_url is not None:
            return utils.add_url_params(utils.join_url(self.resource_url,
                                                       *paths),
                                        **query_params)
        else:
            raise TypeError('Resource can not have child entities')
    def _set_resource_api_url(self, parent_url=None, *paths):
        if parent_url:
            self.resource_url = utils.join_url(parent_url, *paths)
        else:
            self.resource_url = None

class NamespacedResource(QuayResource):
    def __init__(self, namespace=None, **kwargs):
        super().__init__(**kwargs)
        self.inherited['namespace'] = namespace

class Namespace(NamespacedResource):
    # TODO: save private?
    def create_repo(self, name, private=True):
        r = requests.post(self._api_url('repository'),
                          headers=self.auth_header,
                          json={'namespace': self.namespace, 'repository': name,
                                'visibility': 'private' if private else 'public',
                                'description': ''})
        r.raise_for_status()
        info = r.json()
        return self.repo(info['name'])

    # Get the repo object (NOTE: no requests are made here)
    def repo(self, name):
        return self._create_child(Repo, name)

class Repo(NamespacedResource):
    def __init__(self, name, **kwargs):
        super().__init__(**kwargs)
        self.details['name'] = name
        self.details['url'] = self._make_url('repository', self.namespace, name)
        self._set_resource_api_url(self._api_url(),
                                'repository', self.namespace, name)

    @contextmanager
    def login(self):
        session = requests.Session()
        r = session.post(self._api_url('signin'),
                         headers=self.auth_header,
                         json=self.auth_credentials)
        # TODO: cleanup this with custom error classes
        r.raise_for_status()
        yield session
        r = session.post(self._api_url('signout'),
                         headers=self.auth_header,
                         json={})

    # much rest very api
    def create_build_trigger(self, git_url):
        with self.login() as sess:
            create_url = self._make_url('customtrigger/setup',
                                       self.namespace, self.name)
            resp = sess.get(create_url, headers=self.auth_header)
            resp.raise_for_status()
            trigger_uuid = utils.get_query(resp.url)['newtrigger'][0]
            csrf_token = CSRF_TOKEN_RE.search(resp.text).groups()[0]
            # XXX: Ideally, we want to run this in BuildTrigger itself
            activate_url = self._child_api_url('trigger', trigger_uuid,
                                               'activate',
                                               _csrf_token=csrf_token)
            config = {'build_source': git_url, 'subdir':'/'}
            resp = sess.post(activate_url,
                             json={'config': config})
            resp.raise_for_status()
            trigger_json = resp.json()
        trigger = self.build_trigger(trigger_json['id'])
        trigger.update_details(trigger_json)
        return trigger

    # Get the build_trigger object (NOTE: no requests are made here)
    def build_trigger(self, uuid):
        return self._create_child(BuildTrigger, uuid)

    def create_web_hook(self, event, webhook_url):
        r = requests.post(self._child_api_url('notification/'),
                          headers=self.auth_header,
                          json={'method': 'webhook',
                                'event': event,
                                'config': {'url': webhook_url}})
        r.raise_for_status()
        return self.web_hook(r.json()['uuid'])

    def web_hook(self, uuid):
        return self._create_child(Hook, uuid)

class BuildTrigger(NamespacedResource):
    def __init__(self, uuid, ssh=None, webhook=None, **kwargs):
        super().__init__(resource_path=['trigger', uuid],
                                             **kwargs)
        self.details['uuid'] = uuid
        self.details['ssh'] = ssh
        self.details['webhook'] = webhook

    def update_details(self, resource_json):
        interesting_keys = ['ssh', 'webhook']
        for cred in resource_json['config']['credentials']:
            for key in interesting_keys:
                if key in cred['name'].lower():
                    self.details[key] = cred['value']

class Hook(NamespacedResource):
    def __init__(self, uuid, **kwargs):
        super().__init__(resource_path=['notification', uuid],
                                             **kwargs)
        self.details['uuid'] = uuid


def register(g, repo, settings):
    logger = g.logger
    namespace = Namespace(**g.cfg['quay'])
    existing_repo = settings.get('existing_repo')
    # We're keeping existing_repo flag, so we will not delete repo in rollback
    # if smth will go wrong during registration process
    if existing_repo is not None:
        lazy_debug(logger, lambda: 'Going to use existing repo: {}'.format(
            existing_repo))
        # Do not create repo, if we want to use extisting
        quay_repo = namespace.repo(existing_repo)
    else:
        lazy_debug(logger, lambda: 'Going to create quay repo: {}'.format(repo.name))
        # private by default
        private = settings.get('private', not settings.get('public', False))
        quay_repo = namespace.create_repo(repo.name, private=private)
    settings.update(quay_repo.as_dict())
    lazy_debug(logger, lambda: 'Got quay repo: {} '.format(quay_repo))
    lazy_debug(logger,
               lambda: 'Going to create build trigger for: {} in {}'.format(
                   repo.ssh_url, quay_repo.name))
    build_trigger = quay_repo.create_build_trigger(repo.ssh_url)
    lazy_debug(logger, lambda: 'Build trigger created in {}: {}'.format(
        quay_repo.name, build_trigger.uuid))
    # We can't just store quay repo id and request triggers/webhooks later
    # Because there might be another webhooks / triggers we don't want to delete
    # Web hook to call to trigger build on push
    settings['webhook'] = build_trigger.webhook
    # Save build trigger id, so we can remove it
    settings['trigger_uuid'] = build_trigger.uuid
    lazy_debug(logger, lambda: 'Going to register deploy key in {}/{}'.format(
        repo.owner, repo.name))
    deploy_key = repo.create_key('Quay.io Builder', build_trigger.ssh)
    # Save the key id, so we can remove it later
    settings['ssh'] = deploy_key.id
    settings['secret'] = quay_secret = settings.get('secret',
                                                    utils.random_string())
    settings['username'] = quay_username = settings.get('username',
                                                        utils.random_string())
    quay_webhook = g.make_webhook_url('quay', quay_username, quay_secret)
    lazy_debug(logger, lambda: 'Registering {} as status webhooks in {}'.format(
        quay_webhook, quay_repo.name))
    settings['status_webhook_uuids'] = [
        quay_repo.create_web_hook(EVENT_BUILD_SUCCESS, quay_webhook).uuid,
        quay_repo.create_web_hook(EVENT_BUILD_FAILURE, quay_webhook).uuid
    ]
    # Remove existing_repo flag, so decision on removing repo will be done
    # solely on keep_repo flag
    settings.pop('existing_repo', None)

def unregister(g, repo, settings):
    logger = g.logger
    ignore = functools.partial(utils.ignore, logger=g.logger)
    namespace = Namespace(**g.cfg['quay'])
    lazy_debug(logger, lambda: 'Going to unregister quay repo: {}'.format(
        settings))
    quay_repo = utils.maybe_call(settings, 'name', namespace.repo)
    # Do not have 'name' in settings, maybe haven't created it
    if quay_repo is None:
        return
    if 'existing_repo' in settings or 'keep_repo' in settings:
        # We do not want to delete quay repo,
        # So we need to delete build trigger and hooks
        lazy_debug(logger,
                   lambda: 'Going to delete build trigger from quay: {}'.format(
                       settings.get('trigger_uuid')))
        ignore(lambda:
               utils.maybe_call(settings, 'trigger_uuid',
                                lambda t: quay_repo.build_trigger(t).delete()))
        lazy_debug(logger,
                   lambda: 'Going to delete web hooks from quay: {}'.format(
                       settings.get('status_webhook_uuids')))
        ignore(lambda:
               utils.maybe_call(settings, 'status_webhook_uuids',
                                lambda ids:
                                [quay_repo.web_hook(h).delete() for h in ids]))
    else:
        # build trigger and webhooks will go away along with repo
        lazy_debug(logger, lambda: 'Going to delete repo from quay: {}'.format(
            settings.get('name')))
        ignore(lambda: quay_repo.delete())
    lazy_debug(logger, lambda: 'Going to remove deploy key from: {}/{}'.format(
        repo.owner, repo.name))
    ignore(lambda: utils.maybe_call(settings, 'ssh', repo.delete_key))


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
