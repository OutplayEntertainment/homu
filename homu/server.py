import hmac
import json
import urllib.parse
from .main import PullReqState, parse_commands, db_query, INTERRUPTED_BY_HOMU_RE
from . import utils
from . import quay1
from .utils import lazy_debug
import github3
import sqlite3
import jinja2
import requests
import pkg_resources
from bottle import get, post, put, delete, run, request, redirect, abort, response
import hashlib
import functools

import bottle; bottle.BaseRequest.MEMFILE_MAX = 1024 * 1024 * 10

DEFAULT_BRANCHES = ['master', 'develop', 'auto']

class G: pass
g = G()

# Dict with routines for auto register/unregister in builder.
# builder_type => {'register': reg_func,
#                  'unregister': unreg_func,
#                  <hook_type>:event_hook}
# reg func should modify settings in-place, to allow unregistration at any point
AUTO_BUILDERS = {
    'quay': {
        'register': quay1.register,
        'unregister': quay1.unregister,
        'push': quay1.push_hook
    }
}

def register_in_buider(repo_label):
    builder_kind = g.repo_cfgs[repo_label]['builder']
    reg_func = AUTO_BUILDERS.get(builder_kind, {}).get('register')
    if reg_func:
        repo = g.repos[repo_label]
        settings = g.repo_cfgs[repo_label][builder_kind]
        reg_func(g, repo, settings)
    else:
        g.logger.warning('Cannot register repo {} in {} automatically'.format(
            repo_label, builder_kind))

def unregister_in_buider(repo_label):
    builder_kind = g.repo_cfgs[repo_label]['builder']
    unreg_func = AUTO_BUILDERS.get(builder_kind, {}).get('unregister')
    if unreg_func:
        repo = g.repos[repo_label]
        settings = g.repo_cfgs[repo_label][builder_kind]
        unreg_func(g, repo, settings)
    else:
        g.logger.warning('Cannot register repo {} in {} automatically'.format(
            repo_label, builder_kind))

def builder_event_hook(repo_label, event_type, event):
    builder_kind = g.repo_cfgs[repo_label]['builder']
    hook = AUTO_BUILDERS.get(builder_kind, {}).get(event_type)
    if hook:
        settings = g.repo_cfgs[repo_label][builder_kind]
        hook(g, event, settings)

# We ignore any errors here, and just log them
# This way we will be able, for example, to delete hooks manually
# from github and then unregister repo here
def unregister_in_github(repo_label):
    repo = g.repos[repo_label]
    settings = g.repo_cfgs[repo_label]['github']
    hook = utils.maybe_call(settings, 'webhook_id', repo.hook)
    if hook:
        utils.ignore(lambda: hook.delete(), logger=g.logger)

def forget_repo(repo_label):
    repo = g.repos[repo_label]
    del g.repo_cfgs[repo_label]
    del g.states[repo_label]
    del g.repo_labels[repo.owner.login, repo.name]
    del g.repos[repo_label]

def unregister_and_forget(repo_label):
    unregister_in_github(repo_label)
    unregister_in_buider(repo_label)
    forget_repo(repo_label)

def find_state(sha):
    for repo_label, repo_states in g.states.items():
        for state in repo_states.values():
            if state.merge_sha.startswith(sha):
                return state, repo_label

    raise ValueError('Invalid SHA')

@get('/')
def index():
    return g.tpls['index'].render(repos=sorted(g.repos))

@get('/queue/<repo_label>')
def queue(repo_label):
    logger = g.logger.getChild('queue')

    lazy_debug(logger, lambda: 'repo_label: {}'.format(repo_label))

    if repo_label == 'all':
        labels = g.repos.keys()
    else:
        labels = repo_label.split('+')

    states = []
    for label in labels:
        states += g.states[label].values()

    pull_states = sorted(states)

    rows = []
    for state in pull_states:
        rows.append({
            'status': state.get_status(),
            'status_ext': ' (try)' if state.try_ else '',
            'priority': 'rollup' if state.rollup else state.priority,
            'url': 'https://github.com/{}/{}/pull/{}'.format(state.repo.owner.login, state.repo.name, state.num),
            'num': state.num,
            'approved_by': state.approved_by,
            'title': state.title,
            'head_ref': state.head_ref,
            'mergeable': 'yes' if state.mergeable is True else 'no' if state.mergeable is False else '',
            'assignee': state.assignee,
        })

    return g.tpls['queue'].render(
        repo_label = repo_label,
        states = rows,
        oauth_client_id = g.cfg['github']['app_client_id'],
        total = len(pull_states),
        approved = len([x for x in pull_states if x.approved_by]),
        rolled_up = len([x for x in pull_states if x.rollup]),
        failed = len([x for x in pull_states if x.status == 'failure' or x.status == 'error']),
    )

@get('/rollup')
def rollup():
    logger = g.logger.getChild('rollup')

    response.content_type = 'text/plain'

    code = request.query.code
    state = json.loads(request.query.state)

    lazy_debug(logger, lambda: 'state: {}'.format(state))

    res = requests.post('https://github.com/login/oauth/access_token', data={
        'client_id': g.cfg['github']['app_client_id'],
        'client_secret': g.cfg['github']['app_client_secret'],
        'code': code,
    })
    args = urllib.parse.parse_qs(res.text)
    token = args['access_token'][0]

    repo_label = state['repo_label']
    repo = g.repos[repo_label]
    repo_cfg = g.repo_cfgs[repo_label]

    user_gh = github3.login(token=token)
    user_repo = user_gh.repository(user_gh.user().login, repo.name)
    base_repo = user_gh.repository(repo.owner.login, repo.name)

    nums = state.get('nums', [])
    if nums:
        try: rollup_states = [g.states[repo_label][num] for num in nums]
        except KeyError as e: return 'Invalid PR number: {}'.format(e.args[0])
    else:
        rollup_states = [x for x in g.states[repo_label].values() if x.rollup]
    rollup_states = [x for x in rollup_states if x.approved_by]
    rollup_states.sort(key=lambda x: x.num)

    if not rollup_states:
        return 'No pull requests are marked as rollup'

    master_sha = repo.ref('heads/' + repo_cfg.get('branch', {}).get('master', 'master')).object.sha
    utils.github_set_ref(
        user_repo,
        'heads/' + repo_cfg.get('branch', {}).get('rollup', 'rollup'),
        master_sha,
        force=True,
    )

    successes = []
    failures = []

    for state in rollup_states:
        merge_msg = 'Rollup merge of #{} - {}, r={}\n\n{}'.format(
            state.num,
            state.head_ref,
            state.approved_by,
            state.body,
        )

        try: user_repo.merge(repo_cfg.get('branch', {}).get('rollup', 'rollup'), state.head_sha, merge_msg)
        except github3.models.GitHubError as e:
            if e.code != 409: raise

            failures.append(state.num)
        else:
            successes.append(state.num)

    title = 'Rollup of {} pull requests'.format(len(successes))
    body = '- Successful merges: {}\n- Failed merges: {}'.format(
        ', '.join('#{}'.format(x) for x in successes),
        ', '.join('#{}'.format(x) for x in failures),
    )

    try:
        pull = base_repo.create_pull(
            title,
            repo_cfg.get('branch', {}).get('master', 'master'),
            user_repo.owner.login + ':' + repo_cfg.get('branch', {}).get('rollup', 'rollup'),
            body,
        )
    except github3.models.GitHubError as e:
        return e.response.text
    else:
        redirect(pull.html_url)

@post('/quay')
def quay():
    logger = g.logger.getChild('quay')
    response.content_type = 'text/plain'
    info = request.json
    lazy_debug(logger, lambda: 'info: {}'.format(utils.remove_url_keys_from_json(info)))

    trigger_metadata = info['trigger_metadata']
    commit_sha = trigger_metadata.get('commit_sha',
                                      trigger_metadata.get('commit'))
    try:
        state, repo_label = find_state(commit_sha)
    except ValueError:
        lazy_debug(logger,
                   lambda: 'Invalid commit ID from Quay: {}'.format(commit_sha))
        return 'OK'

    if 'quay' not in state.build_res:
        lazy_debug(logger,
                   lambda: 'quay is not a monitored target for {}'.format(state))
        return 'OK'

    secret = g.repo_cfgs[repo_label]['quay']['secret']
    username = g.repo_cfgs[repo_label]['quay']['username']
    auth_header = request.headers['Authorization']
    code = requests.auth._basic_auth_str(username, secret)
    if auth_header != code:
        logger.warn('authorization failed for {}; header = {}, computed = {}'
                    .format(state, auth_header, code))
        abort(401, 'Authorization failed')

    error_message = info.get('error_message')
    succ = error_message is None

    report_build_res(succ, info['homepage'], 'quay', repo_label,
                     state, logger, error_message)
    return 'OK'

@post('/github')
def github():
    logger = g.logger.getChild('github')

    response.content_type = 'text/plain'

    payload = request.body.read()
    info = request.json

    lazy_debug(logger, lambda: 'info: {}'.format(utils.remove_url_keys_from_json(info)))

    owner_info = info['repository']['owner']
    owner = owner_info.get('login') or owner_info['name']
    try:
        repo_label = g.repo_labels[owner, info['repository']['name']]
        repo_cfg = g.repo_cfgs[repo_label]
    except KeyError:
        abort(404, 'Not found repo {}/{}'.format(owner,
                                                 info['repository']['name']))

    hmac_method, hmac_sig = request.headers['X-Hub-Signature'].split('=')
    if hmac_sig != hmac.new(
        repo_cfg['github']['secret'].encode('utf-8'),
        payload,
        hmac_method,
    ).hexdigest():
        abort(400, 'Invalid signature')

    event_type = request.headers['X-Github-Event']

    if event_type == 'pull_request_review_comment':
        action = info['action']
        original_commit_id = info['comment']['original_commit_id']
        head_sha = info['pull_request']['head']['sha']

        if action == 'created' and original_commit_id == head_sha:
            pull_num = info['pull_request']['number']
            body = info['comment']['body']
            username = info['sender']['login']

            if parse_commands(
                body,
                username,
                repo_cfg,
                g.states[repo_label][pull_num],
                g.my_username,
                g.db,
                realtime=True,
                sha=original_commit_id,
            ):
                g.queue_handler()

    elif event_type == 'pull_request':
        action = info['action']
        pull_num = info['number']
        head_sha = info['pull_request']['head']['sha']

        if action == 'synchronize':
            state = g.states[repo_label][pull_num]
            state.head_advanced(head_sha)

        elif action in ['opened', 'reopened']:
            state = PullReqState(pull_num, head_sha, '', g.repos[repo_label], g.db, repo_label, g.mergeable_que)
            state.title = info['pull_request']['title']
            state.body = info['pull_request']['body']
            state.head_ref = info['pull_request']['head']['repo']['owner']['login'] + ':' + info['pull_request']['head']['ref']
            state.base_ref = info['pull_request']['base']['ref']
            state.set_mergeable(info['pull_request']['mergeable'])
            state.assignee = info['pull_request']['assignee']['login'] if info['pull_request']['assignee'] else ''

            found = False

            if action == 'reopened':
                # FIXME: Review comments are ignored here
                for comment in g.repos[repo_label].issue(pull_num).iter_comments():
                    found = parse_commands(
                        comment.body,
                        comment.user.login,
                        repo_cfg,
                        state,
                        g.my_username,
                        g.db,
                    ) or found

            g.states[repo_label][pull_num] = state

            if found:
                g.queue_handler()

        elif action == 'closed':
            del g.states[repo_label][pull_num]

            db_query(g.db, 'DELETE FROM state WHERE repo = ? AND num = ?', [repo_label, pull_num])
            db_query(g.db, 'DELETE FROM build_res WHERE repo = ? AND num = ?', [repo_label, pull_num])
            db_query(g.db, 'DELETE FROM mergeable WHERE repo = ? AND num = ?', [repo_label, pull_num])

            g.queue_handler()

        elif action in ['assigned', 'unassigned']:
            state = g.states[repo_label][pull_num]
            state.assignee = info['pull_request']['assignee']['login'] if info['pull_request']['assignee'] else ''

        else:
            lazy_debug(logger, lambda: 'Invalid pull_request action: {}'.format(action))

    elif event_type == 'push':
        ref = info['ref'][len('refs/heads/'):]

        for state in list(g.states[repo_label].values()):
            if state.base_ref == ref:
                state.set_mergeable(None, cause={
                    'sha': info['head_commit']['id'],
                    'title': info['head_commit']['message'].splitlines()[0],
                })

            if state.head_sha == info['before']:
                state.head_advanced(info['after'])

    elif event_type == 'issue_comment':
        body = info['comment']['body']
        username = info['comment']['user']['login']
        pull_num = info['issue']['number']

        state = g.states[repo_label].get(pull_num)

        if 'pull_request' in info['issue'] and state:
            state.title = info['issue']['title']
            state.body = info['issue']['body']

            if parse_commands(
                body,
                username,
                repo_cfg,
                state,
                g.my_username,
                g.db,
                realtime=True,
            ):
                g.queue_handler()
    # run custom buider hook
    builder_event_hook(repo_label, event_type, info)

    return 'OK'

def report_build_res(succ, url, builder, repo_label, state, logger, info=None):
    lazy_debug(logger,
               lambda: 'build result {}: builder = {}, succ = {}, current build_res = {}'
                            .format(state, builder, succ, state.build_res_summary()))

    state.set_build_res(builder, succ, url)

    if succ:
        if all(x['res'] for x in state.build_res.values()):
            state.set_status('success')
            desc = 'Test successful'
            utils.github_create_status(state.repo, state.head_sha, 'success', url, desc, context='homu')

            urls = ', '.join('[{}]({})'.format(builder, x['url']) for builder, x in sorted(state.build_res.items()))
            state.add_comment(':sunny: {} - {}'.format(desc, urls))

            if state.approved_by and not state.try_:
                try:
                    utils.github_set_ref(
                        state.repo,
                        'heads/' + g.repo_cfgs[repo_label].get('branch', {}).get('master', 'master'),
                        state.merge_sha,
                    )
                except github3.models.GitHubError as e:
                    state.set_status('error')
                    desc = 'Test was successful, but fast-forwarding failed: {}'.format(e)
                    utils.github_create_status(state.repo, state.head_sha, 'error', url, desc, context='homu')

                    state.add_comment(':eyes: ' + desc)

    else:
        if state.status == 'pending':
            state.set_status('failure')
            desc = 'Test failed'
            if info:
                full_desc = '{}: \n```{}```'.format(desc, info)
            else:
                full_desc = desc
            utils.github_create_status(state.repo, state.head_sha, 'failure',
                                       url, desc, context='homu')

            state.add_comment(':broken_heart: {} - [{}]({})'.format(full_desc,
                                                                    builder,
                                                                    url))

    g.queue_handler()

@post('/buildbot')
def buildbot():
    logger = g.logger.getChild('buildbot')

    response.content_type = 'text/plain'

    lazy_debug(logger, lambda: 'info: {}'.format(info))

    for row in json.loads(request.forms.packets):
        if row['event'] == 'buildFinished':
            info = row['payload']['build']
            props = dict(x[:2] for x in info['properties'])

            if 'retry' in info['text']: continue

            if not props['revision']: continue

            try: state, repo_label = find_state(props['revision'])
            except ValueError:
                lazy_debug(logger,
                           lambda: 'Invalid commit ID from Buildbot: {}'.format(props['revision']))
                continue

            lazy_debug(logger, lambda: 'state: {}, {}'.format(state, state.build_res_summary()))

            if info['builderName'] not in state.build_res:
                lazy_debug(logger,
                           lambda: 'Invalid builder from Buildbot: {}'.format(info['builderName']))
                continue

            repo_cfg = g.repo_cfgs[repo_label]

            if request.forms.secret != repo_cfg['buildbot']['secret']:
                abort(400, 'Invalid secret')

            build_succ = 'successful' in info['text'] or info['results'] == 0

            url = '{}/builders/{}/builds/{}'.format(
                repo_cfg['buildbot']['url'],
                info['builderName'],
                props['buildnumber'],
            )

            if 'interrupted' in info['text']:
                step_name = ''
                for step in reversed(info['steps']):
                    if 'interrupted' in step.get('text', []):
                        step_name = step['name']
                        break

                if step_name:
                    res = requests.get('{}/builders/{}/builds/{}/steps/{}/logs/interrupt'.format(
                        repo_cfg['buildbot']['url'],
                        info['builderName'],
                        props['buildnumber'],
                        step_name,
                    ))

                    mat = INTERRUPTED_BY_HOMU_RE.search(res.text)
                    if mat:
                        interrupt_token = mat.group(1)
                        if getattr(state, 'interrupt_token', '') != interrupt_token:
                            state.interrupt_token = interrupt_token

                            if state.status == 'pending':
                                state.set_status('')

                                desc = ':snowman: The build was interrupted to prioritize another pull request.'
                                state.add_comment(desc)
                                utils.github_create_status(state.repo, state.head_sha, 'error', url, desc, context='homu')

                                g.queue_handler()

                        continue

                else:
                    logger.error('Corrupt payload from Buildbot')

            report_build_res(build_succ, url, info['builderName'], repo_label, state, logger)

        elif row['event'] == 'buildStarted':
            info = row['payload']['build']
            props = dict(x[:2] for x in info['properties'])

            if not props['revision']: continue

            try: state, repo_label = find_state(props['revision'])
            except ValueError: pass
            else:
                if info['builderName'] in state.build_res:
                    repo_cfg = g.repo_cfgs[repo_label]

                    if request.forms.secret != repo_cfg['buildbot']['secret']:
                        abort(400, 'Invalid secret')

                    url = '{}/builders/{}/builds/{}'.format(
                        repo_cfg['buildbot']['url'],
                        info['builderName'],
                        props['buildnumber'],
                    )

                    state.set_build_res(info['builderName'], None, url)

            if g.buildbot_slots[0] == props['revision']:
                g.buildbot_slots[0] = ''

                g.queue_handler()

    return 'OK'

@post('/travis')
def travis():
    logger = g.logger.getChild('travis')

    info = json.loads(request.forms.payload)

    lazy_debug(logger, lambda: 'info: {}'.format(utils.remove_url_keys_from_json(info)))

    try: state, repo_label = find_state(info['commit'])
    except ValueError:
        lazy_debug(logger, lambda: 'Invalid commit ID from Travis: {}'.format(info['commit']))
        return 'OK'

    lazy_debug(logger, lambda: 'state: {}, {}'.format(state, state.build_res_summary()))

    if 'travis' not in state.build_res:
        lazy_debug(logger,
                   lambda: 'travis is not a monitored target for {}'.format(
                       state))
        return 'OK'

    token = g.repo_cfgs[repo_label]['travis']['token']
    auth_header = request.headers['Authorization']
    code = hashlib.sha256(('{}/{}{}'.format(state.repo.owner.login, state.repo.name, token)).encode('utf-8')).hexdigest()
    if auth_header != code:
        # this isn't necessarily an error, e.g. maybe someone is
        # fabricating travis notifications to try to trick Homu, but,
        # I imagine that this will most often occur because a repo is
        # misconfigured.
        logger.warn('authorization failed for {}, maybe the repo has the wrong travis token? ' \
                    'header = {}, computed = {}'
                    .format(state, auth_header, code))
        abort(400, 'Authorization failed')

    succ = info['result'] == 0

    report_build_res(succ, info['build_url'], 'travis', repo_label, state, logger)

    return 'OK'

# Admin methods are protected via Basic auth. To access them one may use curl:
# `curl -H"Authorization: <username> <secret>" "url"`.
# For better security one may setup nginx in front of this service and listen
# for /admin/* requestr only from certain ip (to prevent accessing this API from
# public network, for example)
def check_admin_requirements(json=False):
    def decorator(f):
        @functools.wraps(f)
        def wrapper(*args, **kwargs):
            logger = g.logger.getChild('admin')
            lazy_debug(logger, lambda: 'Got `{}` request for: {}'.format(
                request.method, request.path))
            auth_header = request.headers.get('Authorization')
            if not auth_header:
                logger.warning('Request for {} without Authorization header'.format(
                    request.path))
                return abort(401, 'Authorization required')
            check_header = '{} {}'.format(g.cfg['admin']['username'],
                                          g.cfg['admin']['secret'])
            if auth_header != check_header:
                logger.warning('authorization failed: have {}, want = {}'.format(
                    auth_header, check_header))
                return abort(401, 'Authorization failed')
            if json:
                try:
                    if request.json is None:
                        return abort(415, 'Content-type is not accepted')
                except ValueError:
                    return abort(400, 'Malformed json')
            return f(*args, **kwargs)
        return wrapper
    return decorator



@put('/admin/repo')
@check_admin_requirements(json=True)
def admin_add_repo():
    logger = g.logger.getChild('admin')
    response.content_type = 'text/plain'
    repo_cfg = dict(request.json)
    lazy_debug(logger, lambda: 'Request for {}; payload:{}'.format(request.path,
                                                                   repo_cfg))
    for key in ['owner', 'name', 'reviewers', 'github', 'builder']:
        if key not in repo_cfg:
            abort(422, 'Required parameter `{}` not found'.format(key))
    builder = repo_cfg['builder']
    if builder not in repo_cfg:
        abort(422, 'No settings specified for `{}` builder'.format(builder))
    repo_label = '{}/{}'.format(repo_cfg['owner'], repo_cfg['name'])
    if repo_label in g.repo_cfgs:
        response.status = 200
        return g.repo_cfgs[repo_label]
    repo_cfg['label'] = repo_label
    # Local bindings for useful names
    github = repo_cfg['github']
    builder_settings = repo_cfg[builder]
    # Always build master/develop/auto
    builder_settings['build_branches'] = builder_settings.get('build_branches',
                                                              []) + DEFAULT_BRANCHES
    repo_cfg[builder] = builder_settings
    # TODO: validate builder_settings? With hook? oO
    try:
        repo = g.gh.repository(repo_cfg['owner'], repo_cfg['name'])
    except github3.models.GitHubError as e:
        abort(e.code, e.msg)
    # register new configuration early, so we can accept `ping` webhook from gh
    g.repo_cfgs[repo_label] = repo_cfg
    g.repos[repo_label] = repo
    g.states[repo_label] = {}
    g.repo_labels[repo.owner.login, repo.name] = repo_label
    # ensure we have secret stored
    github['secret'] = gh_secret = github.get('secret', utils.random_string())
    gh_webhook = g.make_webhook_url('github')
    lazy_debug(logger, lambda: 'Going to register github webhook: {}'.format(
        gh_webhook))
    try:
        h = repo.create_hook('web', {'url': gh_webhook, 'secret': gh_secret,
                                     'content_type': 'json', 'insecure_ssl': 0},
                             ['push', 'pull_request',
                              'issue_comment', 'pull_request_review_comment'],
                             True)
    except github3.models.GitHubError as e:
        forget_repo(repo_label)
        abort(e.code, e.msg)
    # Save hook id so we can remove it later
    github['webhook_id'] = h.id
    # Register in builder
    try:
        # TODO: register for existing repo?
        register_in_buider(repo_label)
        lazy_debug(logger, lambda: 'Registered {} in builder {}: {}'.format(
            repo_label, repo_cfg['builder'], builder_settings))
    except Exception as e:
        unregister_and_forget(repo_label)
        # We want to return appropriate response codes when we can,
        # so we will catch github/requests errors
        try:
            raise e
        except requests.RequestException as e:
            abort(e.response.status_code, e.response.text)
        except github3.GitHubError as e:
            abort(e.code, e.msg)
    try:
        # save configuration to db
        db_query(g.db, '''INSERT INTO repo (label, owner, name,
                                            reviewers, github, branch,
                                            builder, builder_settings
                                           ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
                 [repo_label, repo_cfg['owner'], repo_cfg['name'],
                  json.dumps(repo_cfg['reviewers']), json.dumps(github),
                  json.dumps(repo_cfg['branch']) if 'branch' in repo_cfg else None,
                  builder, json.dumps(builder_settings)])
    except sqlite3.Error:
        unregister_and_forget(repo_label)
        raise
    # TODO: probably we want to fetch pull requests?
    response.status = 201
    return repo_cfg

@delete('/admin/repo/<repo_label:path>')
@check_admin_requirements()
def admin_delete_repo(repo_label):
    # TODO: unregister without removing a repo?
    response.content_type = 'text/plain'
    if repo_label in g.repo_cfgs:
        # TODO: maybe cancel build and all that?
        unregister_and_forget(repo_label)
        db_query(g.db, 'DELETE from repo where label = ?', [repo_label])
        lazy_debug(g.logger, lambda: 'Repo deleted and unregistered: {}'.format(
            repo_label))
        return repo_label
    else:
        abort(404, repo_label)

@get('/admin/repo/<repo_label:path>')
@check_admin_requirements()
def admin_ger_repo(repo_label):
    if repo_label in g.repo_cfgs:
        return utils.merge_dicts(g.repo_cfgs[repo_label], {'label': repo_label})
    else:
        abort(404, repo_label)

def start(cfg, states, queue_handler, repo_cfgs, repos, logger, buildbot_slots,
          my_username, db, repo_labels, mergeable_que, gh):
    env = jinja2.Environment(
        loader=jinja2.FileSystemLoader(pkg_resources.resource_filename(__name__, 'html')),
        autoescape=True,
    )
    tpls = {}
    tpls['index'] = env.get_template('index.html')
    tpls['queue'] = env.get_template('queue.html')

    def make_webhook_url(path, username=None, password=None):
        return utils.make_url(**utils.merge_dicts(g.cfg['external'],
                                                  path=path,
                                                  username=username,
                                                  password=password))
    # XXX: this smells
    g.cfg = cfg
    g.states = states
    g.queue_handler = queue_handler
    g.repo_cfgs = repo_cfgs
    g.repos = repos
    g.logger = logger.getChild('server')
    g.buildbot_slots = buildbot_slots
    g.tpls = tpls
    g.my_username = my_username
    g.db = db
    g.gh = gh
    g.make_webhook_url = make_webhook_url
    g.repo_labels = repo_labels
    g.mergeable_que = mergeable_que

    run(host=cfg['web'].get('hostname', ''),
        port=cfg['web']['port'],
        server='waitress')
