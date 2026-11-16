#!/usr/bin/env bash
# Run only inside a disposable Ubuntu container, with source copied to /source.
# No host mounts, credentials, ports, or privileged mode are needed.
# From a committed checkout:
# git archive HEAD | docker run --rm -i ubuntu:24.04 bash -c \
#   'mkdir /source && tar -xf - -C /source && cd /source && bash smoke_install.sh'
set -euo pipefail
[[ -f /.dockerenv && $PWD == /source && ! -e /opt/telemax/current ]] || exit 1
bash install.sh --prepare-only
cd /opt/telemax/current/app
/opt/telemax/current/venv/bin/python - <<'PY'
import asyncio
import ssl
from aiohttp import ClientSession, TCPConnector
from bridge import Bridge, MaxError, PublicResolver, ssl_context

async def check():
    context = ssl_context()
    assert context.check_hostname and context.verify_mode == ssl.CERT_REQUIRED
    async with ClientSession(connector=TCPConnector(ssl=context, resolver=PublicResolver())) as http:
        bridge = Bridge({'max_bot_token': ''}, None)
        bridge.http = http
        try:
            await asyncio.wait_for(bridge.api('GET', '/me'), 30)
        except MaxError as error:
            assert error.status == 401, error.status
            print('Installed API path: verified TLS, GET /me without a token returned 401')
        else:
            raise AssertionError('Expected 401')
asyncio.run(check())
PY
cd /source
# This container has no real systemd. Simulate service control only; use the
# real installer, dependency installation, release switches and rollback wrapper.
mkdir -p /run/systemd/system /tmp/service-mock
cat > /tmp/service-mock/systemctl <<'MOCK'
#!/usr/bin/env bash
set -eu
echo "$*" >> /tmp/service-calls
case "$1" in
is-active) [[ $(cat /tmp/active) == true ]] ;;
is-enabled) [[ $(cat /tmp/enabled) == true ]] ;;
daemon-reload) ;;
restart)
    case $(cat /tmp/restart-result) in
    success) echo true > /tmp/active ;;
    inactive) echo false > /tmp/active ;;
    error) echo false > /tmp/active; exit 1 ;;
    esac ;;
stop) echo false > /tmp/active ;;
start) echo true > /tmp/active ;;
*) echo "Unexpected systemctl: $*" >&2; exit 2 ;;
esac
MOCK
chmod 755 /tmp/service-mock/systemctl
export PATH=/tmp/service-mock:$PATH
echo 'synthetic private state' > /var/lib/telemax/smoke-state
for active in true false; do
    for enabled in true false; do
        for outcome in success inactive error; do
            echo "$active" > /tmp/active
            echo "$enabled" > /tmp/enabled
            echo "$outcome" > /tmp/restart-result
            : > /tmp/service-calls
            before=$(readlink /opt/telemax/current)
            result=0
            bash install.sh --update > /tmp/install-update.log 2>&1 || result=$?
            if [[ $active == true && $outcome != success ]]; then
                [[ $result != 0 && $(readlink /opt/telemax/current) == "$before" ]]
                grep -qx 'start telemax' /tmp/service-calls
            else
                [[ $result == 0 && $(readlink /opt/telemax/current) != "$before" ]]
            fi
            [[ $(cat /tmp/active) == "$active" && $(cat /tmp/enabled) == "$enabled" ]]
            if [[ $active == false ]]; then
                ! grep -Eq '^(restart|start|stop) ' /tmp/service-calls
                # Manual rollback must preserve the stopped state, too.
                /usr/local/bin/telemax rollback
                [[ $(cat /tmp/active) == false && $(readlink /opt/telemax/current) == "$before" ]]
            fi
            ! grep -Eq '^(enable|disable|reenable|preset) ' /tmp/service-calls
            [[ $(cat /var/lib/telemax/smoke-state) == 'synthetic private state' ]]
            test -f /opt/telemax/current/app/russian_trusted_root_ca.pem
            echo "Update checked: active=$active enabled=$enabled restart=$outcome"
        done
    done
done
echo 'Clean install and isolated update/rollback checks passed'
