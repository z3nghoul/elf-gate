# Лаборатория для исследования TUN (этап 5.1)

Воспроизводимые опыты, на которых основан `../../tun-research.md`. Всё выполняется
**без root и без sudo** в одноразовых namespace (`unshare -Urnmpf --mount-proc`):
пользовательское + сетевое + mount + pid пространство. Сеть, DNS, маршруты и настройки хоста
не затрагиваются, а при выходе ядро убивает все процессы лаборатории.

```
  netns A ("ваша машина")             netns B ("интернет + VPS")
  vA 10.0.0.1/24  <---- veth ---->  vB 10.0.0.2/24
  TUN-клиент (xray / sing-box)        VLESS-сервер (xray) 0.0.0.0:8443
  curl, socat, python3                web+UDP-эхо 203.0.113.80:8080/5000/443
                                      "публичный VPS" 198.51.100.2, DNS 203.0.113.53
```

Ответ сервера содержит адрес клиента: `peer=10.0.0.1` значит «напрямую», `peer=203.0.113.80`
значит «через VPN-сервер» (сервер ходит к цели со своего адреса).

## Запуск

Нужны `bin/xray` (см. README проекта), `python3`, `curl`, `socat`, `openssl`, `ip`, `unshare`.
Для сценария 05 ещё `sing-box` (`SB=/путь/к/sing-box`).

```bash
docs/tun-research/lab/run.sh 01-tun-all
docs/tun-research/lab/run.sh 02-process-routing
docs/tun-research/lab/run.sh 03-loop-protection
docs/tun-research/lab/run.sh 04-reality-udp
SB=bin/sing-box-1.14.4/sing-box-1.14.4-linux-amd64/sing-box docs/tun-research/lab/run.sh 05-singbox-chain
docs/tun-research/lab/run.sh 06-dns-routing
cargo build && docs/tun-research/lab/run.sh 07-elfgate-e2e   # the real elf-gate drives TUN
```

Сценарий 07 запускает настоящий `target/debug/elf-gate` на pty внутри лаборатории: включение TUN, правила по процессам
(`include` и `exclude`), DNS по доменам, выход, `kill -9`, очистка при следующем запуске, сторож (`--supervise`).
Переменная `ELF_GATE_LAB_TRUST_ALL` (только в debug-сборке) отключает проверку «ядро принадлежит root»:
в user namespace настоящий root не сопоставлен, и проверка всегда бы падала.

Рабочие файлы и логи (`*.out`, `server-access.log`) лежат в `$WORK` (по умолчанию временная папка).
Ключи генерируются при каждом запуске (`xray x25519`, `xray vlessenc`), в репозиторий ничего секретного не попадает.

## Оговорки лаборатории

- `net.ipv4.conf.*.rp_filter=2` (как у вашей машины: `all=1`, интерфейс `wlan0=2`, итог loose).
  При строгом `1` ответы на «прямые» соединения через TUN отбрасываются (см. отчёт).
- Метрика маршрута по умолчанию 100 (как у DHCP/NetworkManager), иначе маршрут Xray с метрикой 1 не побеждает.
- На сервере `freedom` разрешает цели в своих адресах (`finalRules: allow`), иначе Xray 26.x их блокирует.
