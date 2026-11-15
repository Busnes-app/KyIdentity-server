# Forward-auth: protecting an app behind the edge

A **proxy app** lets KyIdentity protect any web app that sits behind your nginx edge, including
an app with no single sign-on of its own. nginx asks KyIdentity about every request
(`auth_request`). KyIdentity answers with the signed-in user, or tells nginx to send the browser
to sign in.

Each protected host gets its own host-only cookie, `__Host-ky_fwd`. No cookie is shared across
a parent domain. A sign-in on one app does not open another: each host gets its own cookie
through a one-time code.

Design and threat model: [superpowers/specs/2026-11-15-forward-auth-design.md](superpowers/specs/2026-11-15-forward-auth-design.md).

## Set up a proxy app

1. In KyIdentity, open **App connections**, then **Proxy apps**, then **Add proxy app**. Enter
   the following:
   - **Name.** This is the launcher card's name.
   - **Exact host,** such as `grafana.example.com`. Wildcards, ports and paths are not allowed.
   - **Login header.** The default is `X-Ky-User`. See "How the app takes the sign-in" below.
   - **Bypass path prefixes,** if any. They are empty by default.
   - **Session length.** The default is 12 hours. You can set 5 minutes to 7 days.
2. Copy the **edge secret**. It is shown once and only its hash is stored. If you lose it, use
   **Replace secret**; the old secret stops working within 30 seconds.
3. On **App connections**, use **Manage access** to assign users and groups. A new proxy app
   admits assigned users only. Administrators are not exempt.
4. Use **Authentication** to choose the policy. A new proxy app requires MFA (`factor=mfa`).
   Fresh sign-in on every request and refresh tokens cannot apply at the edge, so they are
   refused.
5. Add the nginx configuration below for that host and reload nginx.

The app appears on the launcher for its assigned users. Access reviews (**Manage access**), the
access explanation and the audit log treat it like any other app.

### From an installer

An installer such as KyQuickStart registers a proxy app from inside the container, with no
administrator session:

```sh
kyidentity proxy-app --owner <installation ID> --host grafana.example.com --name Grafana \
  --login-header X-WEBAUTH-USER [--bypass /api/health]... [--session-hours 12] [--rotate-secret]
```

It prints one JSON line, `{"schema":"kyidentity.proxy-app/1","host":…,"id":…,"status":…}`,
where `status` is `created`, `updated` or `unchanged`:

- The first run creates the app and adds `edgeSecret`.
- A rerun updates the login header, bypass paths and session length. It never creates a second
  app or secret.
- `--rotate-secret` replaces the secret and prints the new one.
- The command refuses a host whose proxy app an administrator or another owner created.

`apply-setup --capabilities` lists `proxy-apps` when the command exists. The installer must
keep the secret out of its logs and output. Assignments and the policy are still set in
KyIdentity.

## How the app takes the sign-in

- **Header login.** The app trusts a header that the edge sets. Set the proxy app's login header
  to the name the app reads, such as `X-WEBAUTH-USER` or `Remote-User`. This is only safe when
  the app cannot be reached except through the edge. Anyone who reaches the app directly can
  send the header and sign in as anyone. KyIdentity cannot see how the app is deployed.
- **OIDC.** If the app supports OpenID Connect, register an OAuth client for it and let it sign
  in directly. Do not put a proxy app in front of it.
- **Gate only.** KyIdentity decides who reaches the app, and the user still signs in to the app
  itself. Leave the login header at `X-Ky-User`; the app ignores it.

## What KyIdentity answers

`GET /api/forward/check` is called only by nginx, with these headers:

- `X-Ky-Edge-Secret`, the per-app secret.
- `X-Forwarded-Host`, the exact host.
- `X-Original-URI`, the raw request URI.
- The browser's `Cookie` header.

It answers as follows:

| Answer | When | Headers |
|---|---|---|
| 200 | The request path is under a bypass prefix. | None. |
| 200 | The forward session is live and bound to this host, the user is active and assigned, and the sign-in meets the app's policy. | `X-Ky-User`, the login header, `X-Ky-Email` and `X-Ky-Groups` (the user's groups that are assigned to this app, comma-separated) |
| 401 | No session or an invalid one, another host's cookie, a disabled user, a policy the sign-in no longer meets, or a wrong or missing edge secret. | None. |
| 403 | A signed-in user who is not assigned. | None. |

An answer for a session is cached in KyIdentity for at most 30 seconds. Disabling a user,
removing their assignment, signing them out everywhere or changing the policy therefore takes
effect within 30 seconds. Changing the host ends every session for the app at once.

A bypass applies only when the raw path is the prefix or starts with the prefix followed by
`/`. A path that contains `%`, `;`, `..`, `//` or a backslash is never bypassed; it gets the
full check. **KyIdentity does not check bypass paths at all:** anyone can open them, and they
carry no user headers.

## Sign-in flow

1. A browser without a valid cookie gets a 401 from the check. nginx sends it to
   `/.ky/start` on the app host.
2. `/.ky/start` sets `__Host-ky_fwd_n`, a random nonce cookie that lasts 10 minutes. It then
   redirects to `https://<KyIdentity>/forward/start` with these parameters:
   - `rd`, the original `https://<host><path>`.
   - `n`, the nonce's SHA-256.
3. `/forward/start` checks `rd`:
   - It must be an absolute `https://` URL with no userinfo, port or fragment.
   - Its host must exactly equal a registered proxy app's host.

   Anything else gets an error page and no redirect. The user signs in with the normal
   password, MFA and KyAuth flow, then KyIdentity checks access and the policy.
4. KyIdentity redirects to `https://<host>/.ky/callback?code=…`. The code is random,
   single-use, valid for 60 seconds, and bound to that host, that login and the nonce.
5. `/.ky/callback` redeems the code. It sets `__Host-ky_fwd`, a host-only cookie with
   `Secure`, `HttpOnly`, `SameSite=Lax` and `Path=/`. It then redirects to the original path.
6. `/.ky/logout` ends that host's forward session, clears the cookie and goes to KyIdentity.

Signing out of KyIdentity, **Sign out everywhere**, revoking a session, a password change and
disabling the account all end the forward sessions made from those logins. Forward sessions are
database rows, so every replica sees them.

## nginx configuration

Use one `server` block per protected host. Replace these placeholders:

- `grafana.example.com`, the host.
- `http://grafana:3000`, the app.
- `kyidentity:8080`, KyIdentity's address as the edge reaches it.
- `EDGE_SECRET`, the secret.
- `X-WEBAUTH-USER`, the login header, or delete that line if it is `X-Ky-User`.

The edge must reach KyIdentity as a trusted proxy (`TRUSTED_PROXY_CIDRS`), so that rate
limits and the audit log see the browser's address.

```nginx
upstream kyidentity { server kyidentity:8080; }

server {
    listen 443 ssl;
    server_name grafana.example.com;
    # ssl_certificate ...;

    # Keep nginx's default: headers with underscores (X_WEBAUTH_USER) are dropped, so a
    # client cannot reach an app that maps "-" and "_" to the same name.
    underscores_in_headers off;

    # The check. internal: browsers cannot call it directly.
    location = /.ky/check {
        internal;
        rewrite ^ /api/forward/check? break;
        proxy_pass http://kyidentity;
        proxy_pass_request_body off;
        proxy_set_header Content-Length "";
        proxy_set_header Host kyidentity;
        proxy_set_header X-Forwarded-Host grafana.example.com;
        proxy_set_header X-Original-URI $request_uri;
        proxy_set_header X-Ky-Edge-Secret "EDGE_SECRET";
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Forwarded-Proto https;
    }

    # KyIdentity's routes on this host: start, callback and logout.
    location = /.ky/start    { rewrite ^ /forward/begin break;    proxy_pass http://kyidentity; include /etc/nginx/ky-edge-grafana.conf; }
    location = /.ky/callback { rewrite ^ /forward/callback break; proxy_pass http://kyidentity; include /etc/nginx/ky-edge-grafana.conf; }
    location = /.ky/logout   { rewrite ^ /forward/logout? break;  proxy_pass http://kyidentity; include /etc/nginx/ky-edge-grafana.conf; }

    # A browser without a valid cookie: start sign-in, keeping the original URI.
    location @ky_login {
        rewrite ^ /forward/begin? break;
        proxy_pass http://kyidentity;
        include /etc/nginx/ky-edge-grafana.conf;
        proxy_set_header X-Original-URI $request_uri;
    }

    location / {
        auth_request /.ky/check;
        auth_request_set $ky_user   $upstream_http_x_ky_user;
        auth_request_set $ky_email  $upstream_http_x_ky_email;
        auth_request_set $ky_groups $upstream_http_x_ky_groups;
        error_page 401 = @ky_login;

        # Every Ky header and the login header is set here, so the client's copies never
        # reach the app; an empty value (a bypass path) removes the header.
        proxy_set_header X-Ky-User   $ky_user;
        proxy_set_header X-Ky-Email  $ky_email;
        proxy_set_header X-Ky-Groups $ky_groups;
        proxy_set_header X-WEBAUTH-USER $ky_user;
        proxy_set_header X-Ky-Edge-Secret "";

        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Forwarded-Proto https;
        proxy_pass http://grafana:3000;
    }
}
```

`/etc/nginx/ky-edge-grafana.conf` holds the headers that the start, callback and logout routes
share:

```nginx
proxy_set_header Host kyidentity;
proxy_set_header X-Forwarded-Host grafana.example.com;
proxy_set_header X-Ky-Edge-Secret "EDGE_SECRET";
proxy_set_header X-Forwarded-For $remote_addr;
proxy_set_header X-Forwarded-Proto https;
```

How this configuration keeps the headers safe:

- `proxy_set_header` in a `location` replaces every inherited one, and nginx never forwards
  the client's copy of a header it sets itself. Every Ky header and the login header is set in
  `location /`, so whatever the client sent is gone before the app sees the request.
- The check's answer is the only source of those values. A bypass path gets empty values, so
  those headers are removed.
- `X-Forwarded-Host` is a fixed string, not `$host`, so a client's `Host` header cannot name
  another proxy app. The secret already ties each request to one app.
- Keep the edge secret file readable only by nginx. Do not put the secret in logs: nginx does
  not log request headers by default.

## Not covered

- The app can still be reached around the edge, for example through a published port or
  another network path. For a header-login app, closing that is the operator's job.
- The app receives `__Host-ky_fwd` in its `Cookie` header, like any cookie on its host. That
  cookie opens only that same host.
- `/.ky/logout` is a GET, so another site can sign a user out of one app. It cannot sign
  anyone in.
- Non-HTTP services, wildcard hosts, a parent-domain cookie and native-app token flows are not
  supported.
