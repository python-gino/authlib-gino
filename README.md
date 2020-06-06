# Authlib-GINO

This experimental and transitional library provides:

* `starlette_oauth2` - OAuth2 Provider using Starlette
* `gino_oauth2` - OAuth2 model mixins using GINO
* `async_grants` - Asynchronous Authlib grants for OAuth2 and OpenID Connect
* `fastapi_session` - A GINO App extension for session management using
  OpenID Connect / public client / PKCE

**CAUTION**: Code is copy'n'pasted from Authlib and modified for async.
**CAUTION**: `fastapi_session` contains lots of assumptions.

## Async OAuth2 Provider

README TBD


## GINO App

GINO App is a loosely-defined FastAPI application that can be built with extensions from
multiple repositories. A GINO App should provide these entry points under `gino.app`
section:

* `db` - a global `gino.Gino` instance
* `config` - a global `starlette.config.Config` instance

They will be used in extensions to add more config, define additional models and run
queries. An example GINO App looks like this `example/app.py`:

```python
from gino.ext.starlette import Gino
from starlette.config import Config

db = Gino(...)
config = Config(...)
```

Then define the entry points in `pyprorject.toml` if Poetry is used:

```toml
[tool.poetry.plugins."gino.app"]
"db" = "example.app:db"
"config" = "example.app:config"
```

## FastAPI Session

```bash
$ poetry add authlib-gino -E app
```

FastAPI Session module provides these GINO App extensions as entry points under
`gino.app.extensions` section:

* `session.oidc` - Includes OpenID Connect endpoints, model implementation and migration
* `session.admin` - Includes session management endpoints
* `session.demo` - A demo login endpoint

In order to utilize these extensions, create a FastAPI application and feed it to:

```python
from importlib.metadata import entry_points
from fastapi import FastAPI

ENABLED_EXTENSIONS = {"session.oidc", "session.admin"}

app = FastAPI(...)
for ep in entry_points()["gino.app.extensions"]:
    if ep.name in ENABLED_EXTENSIONS:
        ep.load()(app)
```

Extension defines database schema migrations with entry points of the same name under
`gino.app.migrations` section. To include them in your project, initialize an Alembic
environment and add this to `env.py`:

```python
from importlib.metadata import entry_points
from importlib.resources import path
from example.app import ENABLED_EXTENSIONS

for ep in entry_points()["gino.app.migrations"]:
    if ep.name in ENABLED_EXTENSIONS:
        with path(*ep.value.split(":", maxsplit=1)) as loc:
            context.script.version_locations.append(str(loc / "versions"))
```

As we are appending to `version_locations`, `alembic.ini` also needs the initial local
location (change example below to match your layout):

```ini
[alembic]
version_locations = migrations/versions
```

Then run `alembic upgrade heads` (not `head`) to apply the migrations. Read more about
[working with multiple bases in Alembic](
https://alembic.sqlalchemy.org/en/latest/branches.html#working-with-multiple-bases).
