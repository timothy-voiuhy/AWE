# Tool images and execution prerequisites

The Docker Images tab has compact All, Installed, Uninstalled, and Outdated filters. Counts represent unique image references; several tools may share one image. Installed includes outdated images. The lower inventory follows the filter and contains actual installed images.

Availability checks resolve the required Docker reference exactly. An omitted tag means `latest`; another version in the same repository does not satisfy the requirement.

Use **Check updates** to compare installed registry images against their registry digests. This checks metadata without pulling or replacing images. Shared references are checked once, with four concurrent requests and a 15-second Docker request timeout. Registry results are cached for 15 minutes in the backend process and reset on backend restart. Successful pulls invalidate the affected cache entry. Access errors, rate limits, and missing digest provenance appear as unknown, never current or outdated guesses.

Local builds performed through AWE carry a fingerprint of their Docker build context, respecting `.dockerignore`. Source changes mark them outdated. Older images without this label show unknown until rebuilt. Matching build sources do not establish that upstream base images or packages are current. Rebuild explicitly to refresh those dependencies; AWE build operations request fresh base images. Pull/Build buttons update one tool's shared image and show operation logs.

Opening a transform run checks every dependent tool, including composite stages. Checks cover registration, exact image availability/Docker access, required structured-output parsers, and custom parser-file existence and Python syntax. Logs-only tools and interactive tools without structured output do not require a parser.

Missing dependencies block execution with Build/Pull actions or a link to manage the tool definition. Image setup logs stay in the run interface, and prerequisites refresh when setup finishes. Recheck after repairing a parser. Known outdated images warn but remain runnable. Update checks and image setup do not execute the transform against its target.

The backend repeats preflight before starting a graph transform, resuming a transform, or launching a tool directly. Resume checks happen before interrupted-container cleanup. UI checks are advisory; backend checks enforce readiness even for direct API callers. Scope, credentials, inputs, and active-operation approval remain subject to the existing run validation.

API endpoints:

- `POST /api/v1/docker/images/check-updates`: check shared image references and return their states.
- `GET /api/v1/docker/tools/{key}/preflight`: inspect one tool's execution prerequisites.
- `GET /api/v1/projects/{project_id}/transform-preflight?transform_id=…`: inspect all tools in a transform.

Registry inspection uses the [Docker SDK registry metadata API](https://docker-py.readthedocs.io/en/stable/images.html#docker.models.images.ImageCollection.get_registry_data).
