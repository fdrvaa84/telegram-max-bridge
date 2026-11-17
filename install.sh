#!/usr/bin/env bash
set -euo pipefail
umask 077
# Never run this installer against the publisher's working server for a smoke test.
project=''
args=()
while [[ $# -gt 0 ]]; do
    if [[ $1 == --project ]]; then project=${2:?Укажите имя проекта}; shift 2
    else args+=("$1"); shift; fi
done
mode=${args[0]:-install}
[[ ${#args[@]} -le 1 ]] || { echo 'Лишние параметры.'; exit 1; }
root=/opt/telemax
data=/var/lib/telemax
owner=telemax
unit=telemax
if [[ -n $project ]]; then
    [[ $project =~ ^[a-z][a-z0-9-]{0,19}$ ]] || { echo 'Имя проекта: 1–20 строчных латинских букв, цифр и дефисов, начиная с буквы.'; exit 1; }
    root=/opt/telemax/projects/$project
    data=/var/lib/telemax-projects/$project
    owner=telemax-$project
    unit=telemax-$project
fi
case "$mode" in install|--prepare-only|--update) ;; *) echo 'Использование: sudo bash install.sh [--project ИМЯ] [--prepare-only|--update]'; exit 1;; esac
[[ $EUID == 0 ]] || { echo 'Нужен запуск через sudo.'; exit 1; }
# One lock covers allocation, shared dependencies and command publication.
if [[ ${TELEMAX_INSTALL_LOCKED:-} != 1 ]]; then
    install -d -m 700 -o root -g root /run/telemax
    exec 9>/run/telemax/install.lock
    flock -x 9
fi
source /etc/os-release
case "$ID:$VERSION_ID" in ubuntu:22.04|ubuntu:24.04|ubuntu:26.04|debian:12|debian:13) ;; *) echo 'Нужны Ubuntu 22.04/24.04/26.04 или Debian 12/13.'; exit 1;; esac
[[ $(uname -m) == x86_64 ]] || { echo 'Нужен сервер x86-64.'; exit 1; }
if [[ $mode != --prepare-only && ! -d /run/systemd/system ]]; then
    echo 'На сервере должен работать systemd. Для проверки в контейнере есть --prepare-only.'; exit 1
fi
src=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
[[ $src != $root/current/app ]] || { echo 'Обновляйте командой sudo telemax update.'; exit 1; }
if [[ $mode == install && -e $root/current ]]; then
    echo "Уже установлено. Используйте sudo telemax ${project:+--project $project }update."; exit 1
fi
if [[ -n $project && ! -f $root/project.json ]]; then
    if id "$owner" >/dev/null 2>&1 || [[ -e $data || -e $root ]]; then
        echo 'Имя или место проекта уже занято. Выберите другое имя, существующие данные сохранены.'
        exit 1
    fi
fi
was_active=false
if [[ $mode == --update ]] && systemctl is-active --quiet "$unit"; then
    was_active=true
fi
export TELEMAX_INSTALL_LOCKED=1
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq python3 python3-venv ffmpeg ca-certificates curl git iproute2 iptables qrencode
install -d -m 755 "$root"
if [[ -n $project ]]; then python3 "$src/project.py" allocate "$project"; fi
id "$owner" >/dev/null 2>&1 || useradd --system --home-dir "$data" --create-home --shell /usr/sbin/nologin "$owner"
install -d -m 700 -o "$owner" -g "$owner" "$data"
install -d -m 755 $root/releases
release=$(mktemp -d $root/releases/build-XXXXXXXX)
chmod 755 "$release"
trap 'if [[ -n ${release:-} ]]; then rm -rf -- "$release"; fi' EXIT
install -d -m 755 "$release/app"
# Explicit allowlist: never package the caller's configuration or session files.
for name in project.py vpn_access.py bridge.py russian_trusted_root_ca.pem cloud_copies.py manage.py test_bridge.py test_setup.py test_vpn_access.py test_projects.py requirements.txt telemax install.sh README.md GUIDE_RU.md SECURITY.md; do
    install -m 644 "$src/$name" "$release/app/$name"
done
chmod 755 "$release/app/telemax" "$release/app/install.sh"
python3 -m venv "$release/venv"
"$release/venv/bin/pip" --disable-pip-version-check install -q -r "$release/app/requirements.txt"
(cd "$release/app" && "$release/venv/bin/python" -m unittest -q test_bridge test_setup test_vpn_access test_projects)
"$release/venv/bin/python" "$release/app/bridge.py" --help >/dev/null
"$release/venv/bin/python" "$release/app/manage.py" --help >/dev/null
chown -R root:root "$release"
chmod -R go-w "$release"
chmod -R go+rX "$release"
# Install code only after checks. Settings and state never move into a release.
if [[ -L $root/current ]]; then
    ln -sfn "$(readlink $root/current)" $root/previous
fi
ln -sfn "$release" $root/current.next
mv -Tf $root/current.next $root/current
release=''
install -d -m 755 /usr/local/lib/telemax
install -m 644 "$root/current/app/project.py" /usr/local/lib/telemax/project.py
install -m 755 $root/current/app/telemax /usr/local/bin/telemax
install -m 755 $root/current/app/vpn_access.py /usr/local/bin/telemax-vpn
cat > "/etc/systemd/system/$unit.service" <<UNIT
[Unit]
Description=Personal Telegram to MAX bridge
Wants=network-online.target
After=network-online.target telemax-web.service
StartLimitIntervalSec=0
[Service]
User=$owner
Group=$owner
UMask=0077
WorkingDirectory=$data
ExecStart=$root/current/venv/bin/python $root/current/app/bridge.py --config $data/config.json
Restart=on-failure
RestartSec=20
TimeoutStopSec=30
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$data
RestrictSUIDSGID=true
[Install]
WantedBy=multi-user.target
UNIT
if [[ $mode != --prepare-only ]]; then
    systemctl daemon-reload
    if [[ $mode == --update && $was_active == true ]]; then
        restart_ok=true
        systemctl restart "$unit" || restart_ok=false
        sleep 3
        if [[ $restart_ok != true ]] || ! systemctl is-active --quiet "$unit"; then
            echo 'Новая версия не запустилась. Возвращаем прежнюю программу.'
            TELEMAX_INSTALL_LOCKED=1 /usr/local/bin/telemax ${project:+--project "$project"} rollback --restore-active
            exit 1
        fi
    fi
fi
echo "Программа установлена. Дальше: sudo telemax ${project:+--project $project }configure — следуйте русской инструкции."
if [[ $mode == --prepare-only ]]; then echo 'Только подготовка: запуск служб и перезагрузка здесь НЕ проверены.'; fi
