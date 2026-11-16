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

## Состав архивов

- `elf-gate-linux-x86_64.tar.gz`: `elf-gate`, `elf-gated`, `xray`, `geoip.dat`, `geosite.dat`, `bin/` (ссылки на
  xray и dat-файлы), `locales/`, `presets.toml`, `elf-gate-tun.sh`, `README.md`, `LICENSE`, `LICENSE-Xray`,
  `SHA256SUMS` (суммы файлов внутри).
- `elf-gate-windows-x86_64.zip`: `elf-gate.exe`, `elf-gated.exe`, `xray.exe`, `geoip.dat`, `geosite.dat`,
  `wintun.dll`, `elf-gate-tun.bat`, `LICENSE`, `LICENSE-Xray`, `LICENSE-Wintun`, `SHA256SUMS.txt`.

Версия Xray и хэши его архивов - в `.github/xray.env`; скачанный архив проверяется по хэшу до сборки.

## Как проверить скачанное

```
sha256sum -c SHA256SUMS            # Linux, оба архива рядом с файлом
Get-FileHash -Algorithm SHA256 elf-gate-windows-x86_64.zip   # Windows, сравнить со строкой в SHA256SUMS
```

Хэш сборки: `elf-gate --version` (Windows: `elf-gate.exe --version`) печатает
`elf-gate X.Y.Z (commit abcdef0, release)`. `abcdef0` - первые 7 символов хэша коммита, на который указывает тег
(`git rev-parse --short=7 vX.Y.Z^{commit}`).
