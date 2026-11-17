#!/usr/bin/env bash
set -euo pipefail
umask 077
# Never run this installer against the publisher's working server for a smoke test.
mode=${1:-install}
case "$mode" in install|--prepare-only|--update) ;; *) echo 'Использование: sudo bash install.sh [--prepare-only|--update]'; exit 1;; esac
[[ $EUID == 0 ]] || { echo 'Нужен запуск через sudo.'; exit 1; }
source /etc/os-release
case "$ID:$VERSION_ID" in ubuntu:22.04|ubuntu:24.04|debian:12|debian:13) ;; *) echo 'Нужны Ubuntu 22.04/24.04 или Debian 12/13.'; exit 1;; esac
[[ $(uname -m) == x86_64 ]] || { echo 'Нужен сервер x86-64.'; exit 1; }
if [[ $mode != --prepare-only && ! -d /run/systemd/system ]]; then
    echo 'На сервере должен работать systemd. Для проверки в контейнере есть --prepare-only.'; exit 1
fi
src=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
[[ $src != /opt/telemax/current/app ]] || { echo 'Обновляйте командой sudo telemax update.'; exit 1; }
if [[ $mode == install && -e /opt/telemax/current ]]; then
    echo 'Уже установлено. Используйте sudo telemax update.'; exit 1
fi
was_active=false
if [[ $mode == --update ]] && systemctl is-active --quiet telemax; then
    was_active=true
fi
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq python3 python3-venv ffmpeg ca-certificates curl git iproute2 qrencode
id telemax >/dev/null 2>&1 || useradd --system --home-dir /var/lib/telemax --create-home --shell /usr/sbin/nologin telemax
install -d -m 700 -o telemax -g telemax /var/lib/telemax
install -d -m 755 /opt/telemax/releases
release=$(mktemp -d /opt/telemax/releases/build-XXXXXXXX)
chmod 755 "$release"
trap 'if [[ -n ${release:-} ]]; then rm -rf -- "$release"; fi' EXIT
install -d -m 755 "$release/app"
# Explicit allowlist: never package the caller's configuration or session files.
for name in vpn_access.py bridge.py russian_trusted_root_ca.pem cloud_copies.py manage.py test_bridge.py test_setup.py test_vpn_access.py requirements.txt telemax install.sh README.md GUIDE_RU.md SECURITY.md; do
    install -m 644 "$src/$name" "$release/app/$name"
done
chmod 755 "$release/app/telemax" "$release/app/install.sh"
python3 -m venv "$release/venv"
"$release/venv/bin/pip" --disable-pip-version-check install -q -r "$release/app/requirements.txt"
(cd "$release/app" && "$release/venv/bin/python" -m unittest -q test_bridge test_setup test_vpn_access)
"$release/venv/bin/python" "$release/app/bridge.py" --help >/dev/null
"$release/venv/bin/python" "$release/app/manage.py" --help >/dev/null
chown -R root:root "$release"
chmod -R go-w "$release"
chmod -R go+rX "$release"
# Install code only after checks. Settings and state never move into a release.
if [[ -L /opt/telemax/current ]]; then
    ln -sfn "$(readlink /opt/telemax/current)" /opt/telemax/previous
fi
ln -s "$release" /opt/telemax/current.next
mv -Tf /opt/telemax/current.next /opt/telemax/current
release=''
install -m 755 /opt/telemax/current/app/telemax /usr/local/bin/telemax
install -m 755 /opt/telemax/current/app/vpn_access.py /usr/local/bin/telemax-vpn
cat > /etc/systemd/system/telemax.service <<'UNIT'
[Unit]
Description=Personal Telegram to MAX bridge
Wants=network-online.target
After=network-online.target telemax-web.service
StartLimitIntervalSec=0
[Service]
User=telemax
Group=telemax
UMask=0077
WorkingDirectory=/var/lib/telemax
ExecStart=/opt/telemax/current/venv/bin/python /opt/telemax/current/app/bridge.py
Restart=on-failure
RestartSec=20
TimeoutStopSec=30
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/telemax
RestrictSUIDSGID=true
[Install]
WantedBy=multi-user.target
UNIT
if [[ $mode != --prepare-only ]]; then
    systemctl daemon-reload
    if [[ $mode == --update && $was_active == true ]]; then
        restart_ok=true
        systemctl restart telemax || restart_ok=false
        sleep 3
        if [[ $restart_ok != true ]] || ! systemctl is-active --quiet telemax; then
            echo 'Новая версия не запустилась. Возвращаем прежнюю программу.'
            /usr/local/bin/telemax rollback --restore-active
            exit 1
        fi
    fi
fi
echo 'Программа установлена. Дальше: sudo telemax configure — следуйте русской инструкции.'
if [[ $mode == --prepare-only ]]; then echo 'Только подготовка: запуск служб и перезагрузка здесь НЕ проверены.'; fi
