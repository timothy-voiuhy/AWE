# Research PoC registrations

These definitions pin the source commits for [Nginx Rift](https://github.com/depthfirstdisclosures/nginx-rift) and [php2shell](https://github.com/timothy-voiuhy/php2shell-poc). The Dockerfiles package the Python clients, without starting either repository's vulnerable lab services. Both use Python's standard library.

To build and register both through the real browser dialog:

```sh
cd awe-frontend
AWE_REGISTER_RESEARCH_POCS=1 npx playwright test e2e/research-poc-registration.spec.ts
```

Use the existing `.env.e2e.local` credentials and optionally set `AWE_POC_PROJECT_ID` to select the project that owns the build history. Otherwise the test creates or reuses a project named `PoC registrations`. Registrations are global and intentionally retained after this opt-in test. Repeating it rebuilds the pinned images and updates those two custom tool keys. It never launches a PoC against a target.

Find the registered tools under **Graph Tools**. Execution requires the normal high-risk approval. Set the lab host/URL explicitly; container `127.0.0.1` refers to the runner itself.

- **Nginx Rift** runs the upstream `Nginx-Rift/poc.py` command mode, retaining its console output. The upstream reproducer assumes its supplied lab layout and disabled ASLR. This registration does not configure callback networking or the other PoCs in that repository.
- **php2shell** offers Chains A and C and opens their upstream interactive console as a managed AWE session. These require the LFI/session handler/gadget conditions described upstream. Chain E uses `docker exec` to plant its session in the upstream lab and is not offered by this runner, which has no Docker socket. Transcripts are retained; files must be written to `/output` to become artifacts.

Registration and CLI help checks validate packaging, not exploit behavior or the upstream vulnerability claims.
