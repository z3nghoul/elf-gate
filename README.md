# elf-gate

TUI-клиент для Xray-core под Windows и Linux: серверы и подписки, системный прокси или TUN, правила по сайтам, IP и
процессам (например, «только Discord через VPN»), основной и запасной сервер, статистика. Спецификация: [SPEC.md](SPEC.md),
принятые решения: [docs/decisions.md](docs/decisions.md).

## Как это устроено

Две программы в одной папке:

- `elf-gate` - интерфейс в терминале. Его вы и запускаете.
- `elf-gated` - фоновая часть без окна: держит ядро Xray, системный прокси, TUN и значок в трее. `elf-gate` сам запускает её,
  если она не работает. Закрытие интерфейса (`q`) VPN **не отключает**; `Q` останавливает и фоновую часть.

Связь между ними: unix-сокет (`$XDG_RUNTIME_DIR/elf-gate.sock`, права 0600) или именованный канал Windows. Ссылки на серверы
и ключи через неё не передаются.

## Установка

Положите в одну папку: `elf-gate`, `elf-gated` (на Windows с `.exe`), ядро `xray`, `geoip.dat`, `geosite.dat`
(релизы: https://github.com/XTLS/Xray-core/releases), для TUN на Windows ещё `wintun.dll` (лежит в архиве Xray для Windows).
Готовая тестовая сборка для Windows собирается в CI (`elf-gate-windows-test.zip`, всё уже внутри).

**Linux, TUN без root.** Нужна копия Xray, принадлежащая root, с правом создавать интерфейсы; программа покажет точные команды
(`docs/linux-tun-setup.md`), примерно:

```bash
sudo install -o root -g root -m 755 xray /usr/local/lib/elf-gate/xray
sudo setcap cap_net_admin+ep /usr/local/lib/elf-gate/xray
```

**Windows, TUN.** Нужны права администратора: фоновая часть сама перезапустится через UAC (интерфейс останется обычным).

## Клавиши

Полный список и подсказки: `?` в программе (справка строится из той же таблицы, что и обработчик клавиш).
Главное: `Enter` подключиться, `d` отключиться, `t` PROXY/TUN, `a` добавить ссылку или подписку, `p` пинг, `o` сортировка,
`u` обновить подписки, `r` правила, `s` настройки, `l` журнал, `f` fp, `b` роль (основной/запасной), `z` фрагментация TLS,
`q` закрыть интерфейс, `Q` остановить всё.

## Типовые сценарии

- **Только Discord.** `t` (TUN), `Enter`; при первом запуске TUN ответьте `y` на вопрос про пресет `discord-only`.
  Через VPN идёт только Discord (голос и стримы по UDP тоже), остальное напрямую.
- **Всё, кроме игр.** Режим `exclude`, на экране правил (`r`) включите `games-direct` и `torrents-direct`.
- **Два сервера.** Выберите основной, нажмите `b` -> «основной»; запасной -> «запасной». Подключайтесь к основному: при его отказе
  трафик уйдёт на запасной (проверка средствами Xray, около 10 с) и вернётся сам.
- **Если провайдер ломает рукопожатие.** Программа сама перебирает fp (firefox, chrome, ...); вручную `f`; ещё `z` (фрагментация).

## Настройки

Экран `s`: пути, порты, режимы, пинг и автопинг, User-Agent и интервал подписок, тема (тёмная/светлая), «подключаться при
запуске» и «запускать при входе в систему». Файл `config.toml` вручную править не обязательно.

## Для разработчика

### Сборка и проверки

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo run            # TUI
```

### Бинарник Xray для тестов

Бинарники и `.dat`-файлы в git не коммитятся (`/bin` в `.gitignore`).
Скачайте релиз с https://github.com/XTLS/Xray-core/releases и положите в `bin/`:
`xray` (на Windows `xray.exe`), `geoip.dat`, `geosite.dat`.

Тесты, которым нужен настоящий Xray, ищут его так:

1. переменная окружения `XRAY_PATH`;
2. иначе `bin/xray` (`bin/xray.exe` на Windows);
3. иначе тест печатает `SKIPPED` и завершается успешно, поэтому CI без бинарника остаётся зелёным.

```bash
XRAY_PATH=/path/to/xray cargo test xray::integration_tests -- --nocapture
```

Предупреждения Xray про deprecated тесты печатают, но не считают ошибкой.

В CI на ubuntu Xray v26.11.9 скачивается автоматически, SHA256 архива сверяется с хешем,
зашитым в `.github/workflows/ci.yml`; там же проверяется, что xray-тесты не были пропущены.
При смене версии обновите версию и хеш вместе.

### Кросс-сборка под Windows с Linux

Официальная проверка Windows-сборки - CI на `windows-latest`. Локально достаточно
`cargo check --target x86_64-pc-windows-gnu` (линковщик не нужен). Для полной сборки
`.exe` нужен `mingw-w64` и таргет Rust:

```bash
# Arch / CachyOS
sudo pacman -S mingw-w64-gcc
# Debian / Ubuntu
sudo apt install mingw-w64
# Fedora
sudo dnf install mingw64-gcc

rustup target add x86_64-pc-windows-gnu
cargo build --release --target x86_64-pc-windows-gnu
# результат: target/x86_64-pc-windows-gnu/release/elf-gate.exe
```

Запуск и проверка самого `.exe` возможны только на Windows, непроверенные пункты
ведутся в [docs/windows-checklist.md](docs/windows-checklist.md).
