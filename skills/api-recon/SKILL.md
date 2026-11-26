---
name: api-recon
description: Use this skill when collecting a website's API endpoints.
---

# API Recon (frontend API reconnaissance)

On an **authorized** target, discover as completely as possible: the **backend API** (paths, methods, parameters, response bodies), the **frontend routes**, and the **UI feature trigger points** (tabs, dialogs, table actions, etc.).

---

## Boundaries and prohibitions (Agent must read - violating them is out of scope)

This skill **only does API / parameter-surface reconnaissance**. It is not a vulnerability discovery or exploitation phase.

### Task boundaries

| Scope | Allowed | Prohibited |
|---|---|---|
| **Target** | Enumerate paths, methods, parameters, routes, UI trigger points | SQLi/XSS/privilege escalation/brute force/fuzz vulnerabilities, request tampering attacks, destructive operations |
| **Authentication** | Hook + stub/mock to bypass the **client-side** login gate | Asking the user for or guessing account passwords; submitting a real login form |
| **Runtime** | Without credentials, hook the endpoints and use mock responses to let the SPA enter the post-login shell | Flows that depend on a real backend session to continue |

### Dynamic analysis without credentials (default for Phase 3)

1. Use `preload.js` / `runtime_harvest.js` to **intercept and stub** bootstrap endpoints such as login, permissions and menus;
2. For business query endpoints, return a mock body with **correct structure, a successful business code, and possibly empty data**;
3. Let the frontend render post-login pages even with no backend or in a 401 environment, so that more XHR/fetch/WebSocket requests are triggered;
4. **Empty data, blank tables and placeholder UI are all expected** - do not switch to real login or vulnerability testing because of them.

**In one sentence**: use mocks to get frontend routes and components mounted, and **only record outbound requests**. What the backend returns does not matter; what matters is **which other endpoints** the frontend will call.

### Hard process prohibitions

| Prohibited | Do this instead |
|---|---|
| Before Phase 1 is complete, grep/curl/Read the main entry `index-*.js` to extract API paths | Run `OUTDIR/harvest_static.py` |
| Hand-write scripts such as `extract_apis.py` to replace harvest | Edit `OUTDIR/harvest_static.py` and rerun |
| Repeat the same grep/command after it has failed 2 or more times | Change strategy: read tool_logs, edit harvest, check reference |
| Skip gates A/B and run the original `scripts/` directly | Copy to OUTDIR and adapt to the target |
| Real usernames/passwords, OTP, OAuth or other authentication | stub/mock (see above) |
| Skip stubs "to get real data" and do privilege escalation/injection testing | Only record outbound; this is within the recon boundary |
| Irreversible operations such as deleting, exporting sensitive data, bulk writes | The same applies to coverage clicks |
| Claim that all pages and endpoints have been obtained without completing runtime + dynamic enumeration | See "Definition of done" or note the limitation |
| Claim that all parameters are known without completing the parameter trigger matrix + diff | Phase 3b matrix + Phase 5 diff |
| Infer required/optional from a single runtime sample | Multi-sample diff, or infer from validation rules/errors |

---

## Two-layer model + run modes

| Layer | Output | Limit |
|---|---|---|
| **Static** (JS bundle) | Full endpoint paths, draft routes, candidate fields at payload-assembly points | No HTTP method; parameters need Phase 1b; misses URLs built at runtime |
| **Runtime** (live session) | Method + body + response + dynamic URLs + WS/SSE; multi-sample diff completes parameters | Requests are only sent if the page actually renders; a single sample is not enough to decide required/optional |

| Run mode | Engine | Suited for |
|---|---|---|
| **depth** | `runtime_harvest.js` (Puppeteer) | API inventory, METHOD/params/response bodies, WS/SSE, reproducible batch runs |
| **coverage** | browser + `preload.js` | Clicking tabs/dialogs/tables; deeper feature-point coverage |
| **both** | depth first, then coverage | Most complete, takes longest |

**Parameter methodology** (no universal script): use harvest/regex for paths; for parameters use **anchor window expansion + UI binding chain + multi-sample diff + error-based inference** (grep recipes in [reference.md](reference.md) section J).

---

## Definition of done

Only claim recon is complete when all of these are met:

- [ ] **Static**: Phase 1 harvest produced `api_static.txt`, `routes.txt`, `js/`
- [ ] **Runtime**: at least one of depth or coverage; coverage/both require **working Hook + dynamic enumeration loop**
- [ ] **Entered the shell**: visiting a business path does not land on `/login` (mind hash routing)
- [ ] **Parameters**: coverage/both completed the parameter trigger matrix + `param_samples.json`; Phase 5 merged `params_merged.json`
- [ ] **Depth** (if module pages are blank): Phase 4 permission tree restored and rerun, until **module-level APIs** appear (not just locale/bootstrap)
- [ ] **Delivery**: Phase 5 outputs complete (see the Phase 5 output table); `insert_assets` has written the services and endpoint assets

---

## Scripts and gates

`scripts/` contains reference templates only. It is **prohibited** to run the originals directly and treat the result as final.

**Rule**: read first -> adapt to the target -> write into `OUTDIR` (e.g. `recon/`) -> record in `CHANGES.md`; if a script does not match, rewrite it following the methodology and borrow only its structure.

| Gate | When | Reference script -> OUTDIR copy | Common required changes |
|---|---|---|---|
| **A (static)** | After Phase 0, before the **first** run of harvest/spider | `harvest_static.py` / `spider_mpa.py` | **The default regex runs as is on most sites**; only change the endpoint regex, webpack/Vite `publicPath`, MPA exclude/cookie when the manifest/dialect does not match |
| **B (runtime)** | After Phase 2, before running depth/coverage | `runtime_harvest.js` / `preload.js` + `config.json` | Cookie/localStorage keys, neutralize success value, stubs, login regex, api prefix, hash/history |

**Mandatory SPA order** (not interchangeable; Phase numbering takes priority over "explore first, then script"):

| Step | Required | Prohibited |
|---|---|---|
| After Phase 0 is complete | The next Bash = `python3 OUTDIR/harvest_static.py <URL> OUTDIR` | curl/grep/Read the main entry `index-*.js` (usually >500KB) |
| Gate A | Copy the script -> small edits as needed -> **run immediately** | Extract APIs by hand first and then decide whether to run harvest |
| Before Phase 1 is complete | Verify output with `wc -l`; on 404, edit harvest and retry | Hand-write extract scripts; repeatedly grep URLs that were not downloaded |
| From Phase 1b | grep only `OUTDIR/js/*.js` | Use the main bundle in place of harvest |

- OK: copy `harvest_static.py` -> (optionally) edit regex -> **run immediately**
- NOT OK: curl the main bundle -> grep many times -> write a temporary extract -> run harvest last
- **MPA**: after Phase 0 the next Bash = `python3 OUTDIR/spider_mpa.py ...`

---

## Tool and output constraints

| Constraint | Description |
|---|---|
| Large files | **Do not** Read/grep an `index-*.js` over 100KB into context; batch-process it with OUTDIR scripts |
| grep output | Must use `\| head -20` or `-m 5`; keep only path summaries in the conversation, do not paste bundle fragments |
| Verification | Use `wc -l`, `ls \| wc -l`; do not Read a whole directory |
| Initial regex probe | Optional, at most once, only on small chunks <=50KB or HTML; for the formal static result harvest is authoritative |
| reference | For recipes/templates/troubleshooting see [reference.md](reference.md); do not repeat its full text inline |

---

## Execution roadmap

```
Phase 0 classify + OUTDIR
  -> Gate A -> Phase 1 harvest (* run immediately *)
  -> Phase 1b parameter reverse engineering
  -> Phase 2 three authentication gates -> config.json
  -> Gate B -> Phase 3 runtime + parameter matrix
  -> Phase 4 permission tree (if needed) -> rerun Phase 3
  -> Phase 5 merge report + insert_assets bulk-inserts all discovered service and endpoint API assets; under no circumstances may a discovered asset be left out of the insert
```

Check items off in order; **do not enter the next Phase until the previous one is complete**.

1. [ ] **Phase 0**: initial probe of SPA/MPA; create `OUTDIR` -> [Phase 0](#phase-0--分类)
2. [ ] **Gate A + Phase 1**: copy script -> **run harvest immediately** -> verify with `wc -l` -> [Phase 1](#phase-1--静态)
3. [ ] **Phase 1b**: anchor window expansion + binding layer -> `param_candidates.json` -> [Phase 1b](#phase-1b--参数逆向)
4. [ ] **Phase 2**: three authentication gates -> `config.json` -> [Phase 2](#phase-2--鉴权三道门)
5. [ ] **Gate B**: adapt the runtime scripts -> [Phase 3](#phase-3--运行时)
6. [ ] **Phase 3**: depth / coverage / both; confirm shell entry; parameter trigger matrix -> `param_samples.json`
7. [ ] **Phase 4** (if needed): permission tree -> patch stubs -> rerun Phase 3 -> [Phase 4](#phase-4--权限树还原)
8. [ ] **Phase 5**: merged outputs + report + `insert_assets` -> [Phase 5](#phase-5--合并与报告)

---

## Phase 0 - Classification

Fetch the entry HTML and **create `OUTDIR`** (do not modify `scripts/` inside the skill):

- **SPA**: empty shell + `<div id=app>` + chunks -> Phase 1-5
- **MPA**: SSR + `<form>`, no endpoint bundle -> after Gate A:

```bash
python3 recon/spider_mpa.py <BASE_URL> <OUTDIR> [--cookie "session=..."] [--max 300] [--depth 5] [--exclude "logout|delete|destroy"]
```

Outputs `forms.txt`, `links.txt`, `api_inline.txt`. If an SPA has forms ~ 0 -> switch to Phase 1.

---

## Phase 1 - Static

Follow [Scripts and gates](#脚本与门禁) and [Tool and output constraints](#工具与输出约束).

```bash
python3 recon/harvest_static.py <BASE_URL> <OUTDIR>
```

harvest: parses the HTML scripts -> webpack/Vite manifest -> downloads all lazy chunks -> produces `js/`, `api_static.txt`, `routes.txt`, `chunkmap.txt`.

```bash
wc -l OUTDIR/api_static.txt OUTDIR/routes.txt
ls OUTDIR/js | wc -l
```

- Chunk count vs manifest: on 404, edit harvest and retry; do not curl chunks one by one by hand
- If `api_static.txt` is too small -> loosen the endpoint regex in OUTDIR and rerun (see reference)

### Phase 1b - Parameter reverse engineering

Paths come from Phase 1; parameter fields need separate recon. For grep rules see [Tool and output constraints](#工具与输出约束).

**Completion standard**: for important endpoints you can answer: field name, transport location, inferred type, required or not, sample value, confidence.

#### 1b.0 - Transport form

| Form | Where parameters are | Look at first in static code |
|---|---|---|
| REST JSON | body + query | `(params\|data\|body)\s*:\s*\{` next to the path anchor |
| GraphQL | `variables` | gql templates, `$page: Int` |
| Traditional form | urlencoded | `<form>`, `FormData` |
| File upload | multipart | `FormData.append` |
| Path parameters | `/user/:id` | route table + `useParams` / `$route.params` |
| Encrypted/signed | wrapped into `sign`/`data` | Hook the encryption function's input (reference section D) |

Output: annotate each endpoint with `transport: query|json|form|graphql|encrypted`.

#### 1b.1 - Anchor window expansion

Use a known path as the anchor and widen the window to find the payload-assembly object:

```bash
grep -n '"/api/user/list"' OUTDIR/js/*.js | head -20
grep -rhoaE '.{0,120}("/api[^"]+").{0,200}' OUTDIR/js/*.js | head -20
grep -rhoaE '(params|data|body|payload)\s*:\s*\{' OUTDIR/js/*.js | head -20
```

| Wrapper layer | Parameter clue |
|---|---|
| axios instance | `data` / `params` |
| Unified request | Global fields injected by interceptors |
| OpenAPI client | Generated method signatures |
| React Query / SWR | Second argument of the hook |
| Vue composable | Composable input arguments |

Type remnants: `yup`/`zod`/rules, `Form.Item name=`, embedded Swagger.

-> `param_candidates.json`: `{ path, fields[], source: "static-callsite", confidence }`

#### 1b.2 - Binding layer

```
Form field -> onFinish/handleSubmit -> transform -> API payload
```

| Binding source | Technique |
|---|---|
| Form submit | Follow submit -> transform -> API |
| Table search | `getFieldsValue()` -> `params` |
| Route | `:id` / `?tab=` |
| Interceptor | Global `tenantId`, pagination, sign |
| Enum select | `options` -> API enum values |

In the DevTools call stack, trace upward from `fetch`/`XHR.send` to the payload-assembly function.

#### 1b.3 - Three payload questions (not the same as the Phase 2 three authentication gates)

| Question | What to answer |
|---|---|
| **Assembly** | Where the payload is built, traces of transforms |
| **Validation** | required, pattern, enum |
| **Transport** | path / query / body / multipart / headers |

The interceptor gate (Phase 2) also reads the globally injected fields (Authorization, `X-Tenant-Id`, sign).

#### 1b.4 - Link to Phase 3

Candidate fields come from the static/binding layers; **required/optional/conditional dependencies** need the Phase 3 parameter matrix + diff + Phase 5 error-based inference.

---

## Phase 2 - Three authentication gates

grep in `OUTDIR/js/` (with `head`) and write the results into `config.json` (recipes in reference):

| Gate | Question | Keywords |
|---|---|---|
| **Render gate** | How is "logged in" determined? | `isLogin`, `getToken`, Cookie/localStorage |
| **Interceptor gate** | What triggers the redirect to `/login`? | `response_code`, `errno`, axios interceptor |
| **Content gate** | Where do menus/permissions come from? | `menu`, `permission`, `role`, `acl`, `routes` |

Do not treat a localStorage key name as a credential - confirm it from the chunk/request chain.

**Exit = Gate B**: land the conclusions in `config.json`, and edit `OUTDIR/runtime_harvest.js` / `preload.js`.

### Phase 2b - API observation (optional)

Use the `preload.js` in OUTDIR to confirm session key names, Authorization, and nested API URLs:

| Config | Output |
|---|---|
| `recordDetail: true` | `__API_RECON_DETAIL__` |
| `observe.xhrHeaders: true` | headers observation |
| `extractUrlsFromResponse: true` | sub-APIs inside responses |
| `observe.storageReads/cookieReads: true` | back-fill config |
| `neutralizeVueRouter: true` | `__API_RECON_ROUTES__` |

Export after each coverage round: `__API_RECON_LOG__`, `__API_RECON_DETAIL__`, `__API_RECON_ROUTES__`, `__API_RECON_OBSERVE__`.

---

## Phase 3 - Runtime

Gate B must already be passed; follow [Boundaries and prohibitions](#边界与禁止agent-必读--违反即越界) and the no-credential mock strategy.

Set `"runtimeMode": "depth" | "coverage" | "both"` in `config.json` (template in reference).

### Hook and stub (shared by depth + coverage)

| Layer | Scope | Purpose |
|---|---|---|
| L1 exact | auth/permission/bootstrap stubs | Pass first-screen authentication |
| L2 negative correction | All JSON responses | Not-logged-in code -> success |
| L3 fallback | `/api` etc. that did not hit L1 | Empty success body, to prop up the UI |

- **depth**: fake auth + `forward` rewrites business codes + `stubs`; iterate over `routes` (hash/history); produces `runtime_api.json`
- **coverage**: inject `preload.js` at **document-start** (CDP `addScriptToEvaluateOnNewDocument` or Userscript)

Verify: `window.__API_RECON_PRELOAD__` exists; business paths do not return to `/login`.

```bash
cd recon && npm install
node runtime_harvest.js config.json
```

### 3b - coverage dynamic enumeration (mandatory)

1. Main navigation/sidebar - click every item, wait 1-3s for the network
2. Tabs - `role=tab`, `.ant-tabs-tab`
3. Tables - first row view/edit/details
4. Toolbar - export, filter, create (**avoid irreversible deletes**)
5. After entering each module - merge APIs/routes
6. SPA - controlled `pushState` to paths not covered by `routes.txt` (prohibited for MPA)

**Parameter trigger matrix** (mandatory): for each module record once per operation type, and **diff the multiple samples**:

| Operation | Parameters usually added |
|---|---|
| List first screen | Pagination + default filters |
| Click search | keyword, filter |
| Advanced filter | More optional fields |
| Create/edit | Full entity |
| Batch/export/sort | `ids[]`, `exportType`, `sortField` |

**Under stubs the outbound body/headers are still real** - rely on the request. Recordings -> `scan_raw.json`, `param_samples.json`, `api_detail.json`.

- **Vue**: `neutralizeVueRouter: true` + document-start preload
- **React**: `routes.txt` + sidebar clicks + `pushState`
- **both**: first 3a depth, then 3b coverage

---

## Phase 4 - Permission tree restoration

**Trigger**: module pages are blank / each route has only bootstrap (e.g. locale) -> the content gate was not passed.

| Symptom | Meaning |
|---|---|
| Shell entry succeeds | Render gate + interceptor gate passed |
| Sidebar items missing / click shows blank | Stub shape or permission codes incomplete |
| Same, very few APIs on every route | `v-if permission` not passed |
| `routes.txt` far smaller than the bundle | Must be completed from the auth module |

```bash
grep -rhoaE '"/api[^"]*(permission|perm|role|menu|acl)[^"]*"' OUTDIR/js/*.js | sort -u | head -30
grep -rhoaE 'userRouteAuth|getResultTree|routeMap|routeLink|menuList|authList' OUTDIR/js/*.js | head -20
```

Typical chain: `role_permissions` (flat codes) + `permissions/all` (tree) -> `getResultTree` -> `userRouteAuth[CODE].url`.

```bash
python3 recon/extract_route_map.py recon/js recon/
python3 recon/build_perm_tree.py recon/js recon/ --config recon/config.json
```

Intermediate outputs: `route_map.json`, `userRouteAuth.json`, `permissions_tree.json`, `*_stub.json`, `perm_codes_all.txt`.

Stub checks: the outer `response_code` matches the interceptor gate; flat codes align with the tree; `routes` covers all links in `route_map`.

After updating `config.json`, **rerun Phase 3**. For large SPAs you can tune `waitUntil`, `routeTimeout`, `perRouteMs` (see reference sections A3/I).

---

## Phase 5 - Merge and report

### Output table

| File | Stage | Content |
|---|---|---|
| `js/`, `api_static.txt`, `routes.txt`, `chunkmap.txt` | 1 | Static bundle and paths |
| `param_candidates.json` | 1b | Candidate static parameter fields |
| `config.json` | 2 | Three gates + runtime config |
| `runtime_api.json` | 3a | Detailed depth recording (including WS/SSE) |
| `param_samples.json`, `scan_raw.json`, `api_detail.json` | 3b | Multiple samples, click log, detail |
| `route_map.json` etc. | 4 | Permission tree intermediate files (if performed) |
| `params_merged.json` | 5 | Merged parameter fields + confidence |
| `api_merged.txt` | 5 | `METHOD /path [params] [static\|runtime\|both]` |
| `site_map.json` | 5 | Routes, APIs, params, feature points, limitations |
| **insert_assets** | 5 | Write all service and endpoint assets into the asset store |

### 5b - Parameter merge

Diff from `param_samples.json`; there is **no universal merge script**. For confidence rules see reference J7 (high/medium/low/pending trigger).

### 5c - Error-based inference

Within the authorized scope you may send incomplete requests and read the 400 (**this is parameter recon, not vulnerability testing**): `field 'x' is required`, enum errors, etc. Watch for the `data` wrapper, `variables`, and the pre-encryption `bizData`.

The report must state: runtimeMode, the static/runtime API counts, parameter confidence, uncovered modules, and a `CHANGES.md` summary against the reference scripts.

Suggested `site_map.json` structure:

```json
{
  "site": "https://example.com",
  "runtimeMode": "both",
  "appType": "vue-spa",
  "routeGuardStrategy": ["nav-neutralize", "L1-auth", "L2-patch", "forward"],
  "apisFromStatic": [],
  "apisFromRuntime": [],
  "apis": [],
  "params": [{ "method": "POST", "path": "/api/user/list", "transport": "json", "fields": [] }],
  "frontendRoutes": [],
  "routesVerifiedByClick": [],
  "featuresTriggered": [],
  "limitations": ""
}
```

For more fields and grep recipes see [reference.md](reference.md).

---

## General notes

- **Framework-agnostic**: webpack/Vite/Angular lazy loading works the same way
- **Transport**: REST/JSON, GraphQL, WebSocket, SSE; gRPC-web is out of scope
- **SSR**: client-side fetch can be recorded; RSC/Server Actions are not fully enumerable
- **Blind spots**: JSVMP, WASM, HMAC/mTLS strong validation -> static + note the limitation
- **Parameter blind spots**: conditional linkage, hidden params, WASM payload assembly -> "pending trigger" / "unreachable"
- **Static is the safety net**: when runtime is blocked, static can still enumerate endpoints

---

## Additional resources

- Grep recipes, `config.json` template, troubleshooting, Hook, parameter reverse engineering section J, site_map template: **[reference.md](reference.md)**
- For reference script paths see the [Scripts and gates](#脚本与门禁) table
