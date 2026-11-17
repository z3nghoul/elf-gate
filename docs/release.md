# Как выпустить версию

Релиз собирает `.github/workflows/release.yml` по пушу тега `v*`. Результат - черновик (draft) релиза с двумя
архивами и `SHA256SUMS`. Публикуете черновик вручную.

## Порядок

1. В `CHANGELOG.md` добавьте раздел `## X.Y.Z` (для пользователя, без внутренних кодов). Его текст станет текстом
   релиза; без раздела job `check` красный.
2. Поднимите версию в `Cargo.toml` и `Cargo.lock` (`cargo build` обновит lock). Версия должна совпадать с тегом
   без буквы `v`, иначе job `check` красный.
3. Прогоните `main` на CI: `git push origin main:release-check`, дождитесь зелёных workflow (`gh run watch`),
   затем `git push origin main` и удалите ветку `release-check`.
4. Создайте аннотированный тег и отправьте его: `git tag -a vX.Y.Z -m "vX.Y.Z"`, `git push origin vX.Y.Z`.
5. Дождитесь workflow `Release` (`gh run watch`). Он делает: проверку версии и CHANGELOG, на Linux и Windows -
   `cargo test` (с настоящим Xray), релизную сборку с `ELF_GATE_COMMIT` = хэш коммита, упаковку, черновик релиза.
6. Откройте черновик: оба архива (`elf-gate-linux-x86_64.tar.gz`, `elf-gate-windows-x86_64.zip`), `SHA256SUMS`,
   текст из CHANGELOG. Pre-release выставляется сам, если в теге есть `-` (например `v1.1.0-rc1`).
7. Опубликуйте черновик (`gh release edit vX.Y.Z --draft=false` или кнопка Publish).

Для тестового выпуска без `-` в теге: Actions, Release, Run workflow, выбрать тег в "Use workflow from",
включить `prerelease`. Запуск не из тега отклоняется. Если релиз для тега уже существует (повторный запуск),
удалите его (`gh release delete vX.Y.Z`) перед повтором.

Проверка без релиза: Actions, Release, Run workflow, включить `dry_run` (запускать можно с любой ветки).
Собираются оба архива и `SHA256SUMS`, всё загружается как артефакты запуска (`archive-linux-x86_64`,
`archive-windows-x86_64`, `SHA256SUMS`), релиз не создаётся, проверка "версия = тег" и разбор CHANGELOG
пропускаются.

Прежний workflow `windows-test.yml` по тегам `v*` больше не срабатывает: он остался для ручной тестовой сборки
(`windows-test-*` или запуск вручную).

## Минимальная версия glibc

Linux-сборки (`ci.yml` и `release.yml`) идут на образе `ubuntu-22.04`, а не на `ubuntu-latest`: бинарнику нужна
glibc той машины, где он собран, или новее. У Ubuntu 22.04 это glibc 2.35, поэтому `elf-gate` и `elf-gated` запускаются на
дистрибутивах с glibc 2.35 и новее (Ubuntu 22.04+, Debian 12+, Fedora 36+, Arch и производные). Лежащий рядом `xray` -
статический бинарник Go и от glibc не зависит. Поднимать образ (на `ubuntu-24.04` и новее) можно только осознанно:
минимум для пользователей вырастет. Тест `tests/workflows.rs` не даёт вернуть `ubuntu-latest` в матрицу сборки.

## Состав архивов

Состав задан в одном месте: `packaging/archive-files.txt` (строка `<архив> <файл>`, причина - в комментарии над
файлом). Шаги упаковки в `release.yml` собирают папку и запускают `packaging/scripts/check-archive.sh <архив> <папка>`:
лишний файл, недостающий файл или подпапка делают job красным. Новый файл попадает в архив только через этот список с
объяснением, зачем он. Файл остаётся, только если программа читает его при работе, его требует лицензия или без него
нельзя запустить программу так, как описано в README.

| Файл | Linux | Windows | Зачем |
|---|---|---|---|
| `elf-gate`, `elf-gated` (`.exe`) | да | да | интерфейс и фоновая часть; больше ничего они не читают: строки (`locales/`) и встроенные пресеты (`presets.toml`) вшиты в бинарник |
| `xray` (`xray.exe`) | да | да | ядро; `elf-gate` ищет его рядом с собой (папку `bin/` не смотрит) |
| `geoip.dat`, `geosite.dat` | да | да | данные правил маршрутизации; ядро ищет их рядом с собой |
| `wintun.dll` | нет | да | библиотека драйвера TUN, ядро грузит её из своей папки |
| `elf-gate-tun.sh` | да | нет | права для TUN без root на Linux (по README); на Windows фоновая часть сама перезапускается через UAC |
| `LICENSE`, `LICENSE-Xray` | да | да | AGPL-3.0 (elf-gate) и MPL-2.0 (ядро просит текст рядом с бинарником) |
| `LICENSE-Wintun` | нет | да | лицензия Wintun |

Не кладём: `locales/` и `presets.toml` (вшиты через `include_str`), `bin/` с ссылками (поиск Xray его не использует;
`elf-gate-tun.sh` берёт ядро из своей папки, а в папке разработки из `bin/`), `README.md` (он на GitHub), `SHA256SUMS`
внутри архива (суммы самих архивов лежат в `SHA256SUMS` релиза), `elf-gate-tun.bat` (README: на Windows права для TUN
запрашивает сама программа).

Версия Xray и хэши его архивов - в `.github/xray.env`; скачанный архив проверяется по хэшу до сборки.

## Как проверить скачанное

```
sha256sum -c SHA256SUMS            # Linux, оба архива рядом с файлом
Get-FileHash -Algorithm SHA256 elf-gate-windows-x86_64.zip   # Windows, сравнить со строкой в SHA256SUMS
```

Хэш сборки: `elf-gate --version` (Windows: `elf-gate.exe --version`) печатает
`elf-gate X.Y.Z (commit abcdef0, release)`. `abcdef0` - первые 7 символов хэша коммита, на который указывает тег
(`git rev-parse --short=7 vX.Y.Z^{commit}`).
