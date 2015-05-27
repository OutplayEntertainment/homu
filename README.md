# Homu

[![Hommando]][Akemi Homura]

Homu is a bot that integrates with GitHub and your favorite continuous
integration service, such as [Buildbot] or [Travis CI].

[Hommando]: https://i.imgur.com/j0jNvHF.png
[Akemi Homura]: https://wiki.puella-magi.net/Homura_Akemi
[Buildbot]: http://buildbot.net/
[Travis CI]: https://travis-ci.org/

## Why is it needed?

Let's take Travis CI as an example. If you send a pull request to a repository,
Travis CI instantly shows you the test result, which is great. However, after
several other pull requests are merged into the `master` branch, your pull
request can *still* break things after being merged into `master`. The
traditional continuous integration solutions don't protect you from this.

In fact, that's why they provide the build status badges. If anything pushed to
`master` is completely free from any breakage, those badges will **not** be
necessary, as they will always be green. The badges themselves prove that there
can still be some breakages, even when continuous integration services are used.

To solve this problem, the test procedure should be executed *just before the
merge*, not just after the pull request is received. You can manually click the
"restart build" button each time before you merge a pull request, but Homu can
automate this process. It listens to the pull request comments, waiting for an
approval comment from one of the configured reviewers. When the pull request is
approved, Homu tests it using your favorite continuous integration service, and
only when it passes all the tests, it is merged into `master`.

Note that Homu is **not** a replacement of Travis CI or Buildbot. It works on
top of them. Homu itself doesn't have the ability to test pull requests.

## Influences of bors

Homu is largely inspired by [bors]. The concept of "tests should be done just
before the merge" came from bors. However, there are also some differences:

1. Stateful: Unlike bors, which intends to be stateless, Homu is stateful. It
   means that Homu does not need to retrieve all the information again and again
   from GitHub at every run. This is essential because of the GitHub's rate
   limiting. Once it downloads the initial state, the following changes are
   delivered with the [Webhooks] API.
2. Pushing over polling: Homu prefers pushing wherever possible. The pull
   requests from GitHub are retrieved using Webhooks, as stated above. The test
   results from Buildbot are pushed back to Homu with the [HttpStatusPush]
   feature. This approach improves the overall performance and the response
   time, because the bot is informed about the status changes immediately.

And also, Homu has more features, such as `rollup`, `try`, and the Travis CI
support.

[bors]: https://github.com/graydon/bors
[Webhooks]: https://developer.github.com/webhooks/
[HttpStatusPush]: http://docs.buildbot.net/current/manual/cfg-statustargets.html#httpstatuspush

## Usage

### How to install

```sh
sudo apt-get install python3-venv

pyvenv .venv
. .venv/bin/activate

# Stable version

pip install homu

# Development version

git clone https://github.com/barosl/homu.git
pip install -e homu
```

### How to configure

1. Copy `cfg.sample.toml` to `cfg.toml`, and edit it accordingly.

2. Create a GitHub account that will be used by Homu. You can also use an
   existing account. In the [account settings][settings], register a new
   application and generate a new access token (with the `repo` permission).
   The OAuth Callback URL should be `http://HOST:PORT/rollup`, the homepage URL
   isn't needed and can be anything, for example `http://HOST:PORT/`.

3. Add a Webhook to your repository:

 - Payload URL: `http://HOST:PORT/github`
 - Content type: `application/json`
 - Secret: The same as `repo.NAME.github.secret` in cfg.toml
 - Events: Issue Comment, Pull Request, Push

4. Add a Webhook to your continuous integration service:

 - Buildbot

   Insert the following code to the `master.cfg` file:

    ```python
    from buildbot.status.status_push import HttpStatusPush

    c['status'].append(HttpStatusPush(
        serverUrl='http://HOST:PORT/buildbot',
        extra_post_params={'secret': 'repo.NAME.buildbot.secret in cfg.toml'},
    ))
    ```

 - Travis CI

   Add [your Travis token][travis] as `repo.NAME.travis.token` in cfg.toml.
   Insert the following code to the `.travis.yml` file:

    ```yaml
    notifications:
        webhooks: http://HOST:PORT/travis

    branches:
        only:
            - auto
    ```

[settings]: https://github.com/settings/applications
[travis]: https://travis-ci.org/profile/info

### How to run

```sh
. .venv/bin/activate

homu
```

### How to use admin interface

Homu provides admin interface to add and auto-register repos in github and specified builder. Currently
homu can only autoregister repo in Quay.io.

To add repo to homu and register it within github & quay:

```sh
$ curl -XPUT -H"Authorization: {ADMUSER} {ADMTOKEN}" -H"Content-type: application/json" -d'{"owner": "{gh_owner}", "name": "{gh_repo}", "reviewers": ["{gh_reviewer}"], "github": {}, "builder": "quay", "quay": {"public": true}}' "http://{HOMU_IP}:{HOMU_PORT}/admin/repo"'
{"quay": {"secret": "{secr}", "username": "{user}", "name": "{gh_repo}", "build_branches": ["master", "develop", "auto"], "ssh": {deploy_key_id}, "public": true, "url": "{quay_repo_url}", "webhooks": "{quay_webhook}"}, "owner": "{gh_owner}", "reviewers": ["{gh_reviewer}"], "builder": "quay", "name": "{gh_repo}", "github": {"secret": "{gh_secret}", "webhook_id": {gh_webhook_id}}, "label": "{repo_label}"}
```

This command will add repo to homu, store it to db for persistence, create hook on github, create repo
on Quay.io, and register all necessary hooks there. One can add repos using other builders, but autoregistration is not supported for them.

If you want to register existing quay repo in homu, add `"existing_repo"` key to `"quay"` settings and set it to name of your quay repo.

To delete repo and unregister it send DELETE request to `admind/repo/{repo_label}`. To keep quay repo undeleted after unregistering, pass `?keep_repo=True`.

```sh
$ curl -XDELETE -H"Authorization: {ADMUSER} {ADMTOKEN}" "http://{homu_ip}:{homu_port}/admin/repo/{repo_label}"
{repo_label}
```

For builders other than Quay.io auto unregistration is not supported.
