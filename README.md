# elf-gate

TUI-клиент для Xray-core под Windows и Linux. Спецификация: [SPEC.md](SPEC.md).
Проект в разработке, полноценный README (установка, сценарии) появится на этапе 8.

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
