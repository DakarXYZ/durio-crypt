# Чек-лист внутреннего ревью крипто-ядра (O8)

Внешнего аудита нет (решение O8): вместо него — этот чек-лист. E2EE остаётся «бета», пока каждый пункт не
отмечен и T1–T19 не прогнаны на стенде (CR-15). Ревью повторяется перед каждым MINOR-выпуском ядра
(`docs/versioning.md`) и при обновлении `matrix-sdk-crypto`.

**Как проходить.** Каждый пункт: прочитать указанный код, найти тест, записать вывод — ✅ (выполнено, есть
тест или прямое доказательство), ⚠️ (принятое ослабление или открытый вопрос — в «Открыто»), ❌ (дефект —
исправить отдельным коммитом с тестом и перечислить в «Находки»). Ссылки `файл:строка` — на состояние
прохода (коммит в заголовке прохода). Принятые ослабления прошлых этапов — `docs/security-review.md` §3,
отличия протокола от Matrix — `docs/protocol.md`, решения — ADR 0001.

## 1. Чек-лист

### 1.1 Адаптер (CR-20, ADR 0001)

- A1. Ни один ruma/matrix-sdk-тип не выходит в публичный API ядра и FFI.
- A2. Правила адаптера: to_device по одному в порядке сервера; `get_missing_sessions(∅)` в каждом проходе;
  трекаются я и все участники; `sender_key` не уходит в конверт; `device_id` конверта — подсказка, сверяется.
- A3. Таблица `map_megolm_error` полна; перенос сообщения сервером → `ChannelMismatch` или ожидание ключа,
  никогда не обычное сообщение.
- A4. Щит: ключ из бэкапа/файла/пересылки — не выше `Unauthenticated`; `Verified` — только локальное
  доверие после SAS; несовпадение отправителя или устройства → `Mismatch` и `is_clean() == false`.
- A5. SAS: протокол — библиотеки; автопринятие `start` — только внутри запроса в состоянии Ready (его принял
  пользователь); `mismatch` никого не делает проверенным.

### 1.2 Привязка к контексту и повтор (CR-19)

- B1. (session, index) → message_id: повтор под другим id помечается, перерасшифровка того же — нет.
- B2. Правки: `edit_of` = id несущего сообщения, `edit_seq` монотонен, откат помечается.
- B3. `in_reply_to` сверяется с открытыми `replies`.
- B4. Таблицы ограничены, переживают рестарт, хранятся под `StoreCipher`; цена вытеснения записана.
- B5. `type`/`room_id` открытого текста проверяются (тип — нами, комната — библиотекой).

### 1.3 Хранилище и ключ хоста (CR-09, CR-17)

- C1. Ключ хранилища — 32 байта от платформы, `Zeroizing`, `Debug` скрыт, ядро его не сохраняет.
- C2. Файловый замок берётся до открытия SQLite; второй экземпляр → `StoreLocked`; `destroy` — под замком.
- C3. Свои значения (`stoat.*`) — в `custom_value` под `StoreCipher`; ключи значений с версией.
- C4. Неверный ключ/чужой аккаунт → ошибка, не новая учётка поверх старой.
- C5. Хранилище N−1 открывается в N (CR-23).

### 1.4 Ящик to_device (C2)

- D1. Множество обработанных id коммитится в той же транзакции, что изменения библиотеки (`next_batch_token`).
- D2. Дубли (в пачке и между пачками) отбрасываются до библиотеки, но подтверждаются (`ack_ids`).
- D3. Сбой посреди пачки не теряет обработанное и не обрабатывает его дважды.
- D4. Повторы при полном ящике ограничены (попытки, очередь), сдавшиеся устройства видны UI.
- D5. Запросы ключей — только при своём проверенном устройстве, после паузы, не для отозванных и чужих каналов.

### 1.5 FFI (CR-13)

- E1. Каждый экспорт — за забором паник (async — задача на рантайме, sync — `catch_unwind`).
- E2. Ошибки — плоские коды, фиксированный текст, ввод не повторяется.
- E3. Секреты из Kotlin — `ByteArray`, копия ядра обнуляется.
- E4. Объекты с машиной освобождаются в контексте рантайма.
- E5. Записи Kotlin (`data class`) с секретами перечислены в документации («не логировать»).

### 1.6 Секреты в логах и диагностике

- F1. Ядро не логирует; `Debug`/`Display` типов ядра и FFI без ключей, текста и шифротекста.
- F2. `debug_report` (CR-22) — только счётчики и коды; тест против всех секретов аккаунта.
- F3. Библиотека пишет через `tracing`; подписчика ядро не ставит, хост — не ниже `warn` в релизе; Sentry выключен.

### 1.7 Обнуление (zeroize)

- G1. Наши секреты (ключ хранилища, ключ восстановления, ключ секретного хранилища, ключи вложений, пароли из
  FFI) — `Zeroizing`/`ZeroizeOnDrop`; ключи vodozemac/библиотеки обнуляются ими самими.

### 1.8 Сравнения за константное время

- H1. Наши сравнения секретных значений (хеш вложения) — `subtle`; MAC секретов, бэкапа, файла экспорта, SAS —
  библиотеки (HMAC `verify`). Чётность ключа восстановления — открытая контрольная сумма, не секрет.

### 1.9 `unsafe`

- I1. `unsafe_code = "forbid"` во всём workspace; `unsafe` — только в коде, который генерирует UniFFI.

### 1.10 Ввод из недоверенных источников

- J1. Всё, что приходит от сервера или из файла, ограничено до дорогих операций: размер конверта, раунды
  PBKDF2 (описание ключа хранилища, файл экспорта), длина файла экспорта.
- J2. Парсеры конверта, payload, `/e2ee/*`, ключа восстановления — под fuzz (CR-16).

### 1.11 Зависимости

- K1. `cargo deny check` (advisories, лицензии, источники) зелёный; пины `=0.19.1`; новых крейтов в
  продуктовом графе нет без записи в ADR.

## 2. Проход 1 — блок 5A, 2026-10-18 (коммиты до `e745394` + этот)

| Пункт | Итог | Где | Доказательство |
| --- | --- | --- | --- |
| A1 | ✅ | `lib.rs` реэкспорты, `types.rs`, `export.rs`, FFI `types.rs` — только свои типы и строки | компиляция FFI без ruma; `ids.rs:1-3` |
| A2 | ✅ | `machine.rs:543-560` (по одному, `in_batch`/`processed`), `:357` и `:842` (`get_missing_sessions`), `:167`, `:688`, `:974` (трекинг), `:923` (конверт без `sender_key`), `:1047` (подсказка ≠ устройство сессии → `Mismatch`) | `scenarios.rs`, `property.rs`, `delivery.rs` |
| A3 | ✅ | `machine.rs:1211` (таблица), `:1120-1150` (поиск сессии в других каналах, ≤ 512) | `megolm_error_table`, `s07_server_tampering` |
| A4 | ✅ | `machine.rs:1035-1055`: `imported`/`forwarder_data` → `Unauthenticated`, `Verified` = `is_verified()` после SAS | `s03_backup_restore_with_recovery_key`, `export_import_into_fresh_store`, `import_does_not_downgrade_known_sessions` |
| A5 | ✅ | `verification.rs:526` автопринятие; библиотека принимает `start` только в Ready (`requests.rs::receive_start` 0.19.1) | `sas_mismatch_cancels_and_trusts_nothing`, `sas_through_handles` |
| B1–B5 | ✅ | `binding.rs:87-157`, `:171`, `binding::reply_mismatch` (множества, O-4); `payload.rs::from_value` (тип) | `replay_and_rollback`, `tables_are_bounded`, `cr19_*` в `scenarios.rs`, `store_v010_opens_in_current_version` (таблицы после обновления) |
| C1 | ✅ | `store.rs:36-60`; FFI `types.rs:49-60` (обнуление копии) | `wrong_key_or_account_is_refused`, `store_key_and_attachment_keys_are_redacted` |
| C2 | ✅ | `store.rs:100` (замок до `open_with_key`), `:140` | `one_writer_per_store`, `exclusive_until_dropped` |
| C3 | ✅ | `binding.rs:28-29`, `backup.rs:56-60`, `outbox.rs` (`stoat.outbox.retries.v1`), `machine.rs` (`stoat.channel.*`, `stoat.channels.v1`) | `channel_state_and_replay_table_persist` |
| C4 | ✅ | `store.rs::build_error` | `wrong_key_or_account_is_refused` |
| C5 | ✅ | `fixtures/stores/v010`, `v016` | `store_v010_opens_in_current_version`, `store_016_migrates_to_019` |
| D1 | ✅ | `machine.rs:515-521` (токен в `EncryptionSyncChanges`) | `s12_crash_between_processing_and_ack`, `duplicated_and_reordered_mailbox` |
| D2–D3 | ✅ | `machine.rs:543-575`: `processed` обновляется после каждого события; ошибка прерывает пачку, уже обработанное — дубль при повторе | `delivery.rs`, `property.rs` (дубли, краш до ack) |
| D4 | ✅ | `outbox.rs` (`MAX_RETRIES` 256, `to_device_retry_attempts` 8, `gave_up`; свои запросы — пауза и отказ, O-2) | `full_mailboxes_are_retried_then_given_up`, `own_requests_refused_for_good_are_dropped` |
| D5 | ✅ | `gossip.rs:144` (своё проверенное устройство), `machine.rs` `decrypt_failed` (чужой канал → `ChannelMismatch` без запроса) | `scenarios.rs` (CR-08) |
| E1 | ✅ | FFI `runtime.rs` `run`, `run_blocking` (O-1), `guard` | `panics_become_typed_errors`, `async_panics_become_typed_errors`, `blocking_work_leaves_the_workers_free` |
| E2 | ✅ | FFI `error.rs` (текст из `Display` ядра), ядро `error.rs` | `recovery_key_never_in_debug_or_errors`, `wrong_passphrase_or_broken_file` |
| E3 | ✅ | FFI `types.rs:731` (`secret_string`), `:54` | `backup_errors_are_typed`, `key_export_and_import` |
| E4 | ✅ | FFI `runtime.rs:99` (`InRuntime`) | `close_outside_any_runtime`, `BindingsJvmTest.sqliteStore` |
| E5 | ❌→✅ | список был неполон: `EncryptedAttachment.fileJson` (ключ AES), `DecryptResult.Decrypted` (оборачивает `DecryptedMessage`), `KeyExport` — находка R2 | документация FFI `lib.rs`, `types.rs` |
| F1 | ❌→✅ | `Debug` машины выводил всё состояние (id участников и ящика, шифротекст повторов и ожидающих ключа событий) — находка R1 | `machine_debug_names_the_account_only` |
| F2 | ✅ | `diagnostics.rs` | `debug_report_has_no_secrets`, `key_export_and_import` (FFI) |
| F3 | ✅/⚠️ | подписчика `tracing` в ядре и FFI нет; уровень в хосте — задача 5B (см. O-6) | — |
| G1 | ✅ | `store.rs` (`StoreKey`), `backup.rs:84-92` (`RecoveryState: ZeroizeOnDrop`), `:450`, `:568`, `proto/recovery_key.rs`, `attachments.rs`, FFI `secret_string` | `debug_has_no_key`, `setup_debug_has_no_key` |
| H1 | ✅ | `attachments.rs:169` (`ct_eq`); MAC — `matrix-sdk-crypto` (`verify_mac`, `SecretStorageKey::decrypt`) | `swapped_or_truncated_blob_yields_no_plaintext` |
| I1 | ✅ | `Cargo.toml` `[workspace.lints.rust] unsafe_code = "forbid"`; у всех крейтов `lints.workspace = true` | компиляция |
| J1 | ✅ | `envelope.rs` (`MAX_CIPHERTEXT_LEN` до разбора), `backup.rs:287` (≤ 1 000 000 раундов), `proto/key_export.rs` (≤ 64 МиБ, версия, длина, раунды 1…1 000 000; O-7, O-8) | `absurd_pbkdf2_rounds_are_refused_before_hashing`, `header_fields_are_checked`, `oversized_files_are_refused_first` |
| J2 | ✅ | `fuzz/`: `envelope`, `payload`, `api`, `recovery_key`, `key_export` — по 60 с на проходе: 1,34 M / 1,25 M / 0,68 M / 6,0 M / 11,9 M запусков, падений нет | ночной `fuzz.yml` |
| K1 | ✅ | `cargo deny check`: advisories ok, bans ok, licenses ok, sources ok (19 предупреждений о дублях версий, один новый — `hashbrown 0.16` через dev-зависимость `rusqlite` теста CR-23, только wasm-ветка) | — |

## 3. Находки

| # | Что | Итог |
| --- | --- | --- |
| R1 | `#[derive(Debug)]` у `CryptoMachine` (и пробрасывающий его FFI-объект) печатал внутреннее состояние: id участников каналов, id ящика, тела повторов to_device и зашифрованные события, ждущие запроса ключа | исправлено `e745394`, тест `machine_debug_names_the_account_only` |
| R2 | Документация FFI называла «не логировать» только `DecryptedMessage`, `StoreConfig`, `RecoverySetup`; `toString()` Kotlin-записей `EncryptedAttachment` (ключ AES в `fileJson`), `DecryptResult.Decrypted` и `KeyExport` тоже нельзя логировать | исправлено (документация, этот коммит); правило линтера в Android — O-5 |

## 4. Открытые пункты прохода 1 — закрыты (блок 5A, дополнение, 2026-10-18)

| # | Решение | Коммит | Тест |
| --- | --- | --- | --- |
| O-1 | ✅ PBKDF2-тяжёлые вызовы FFI (`export_room_keys`, `import_room_keys`, `unlock_backup`, `create_recovery` с паролем) — на блокирующем пуле рантайма (`runtime.rs::run_blocking`), оба рабочих потока свободны | `76498ae` | `blocking_work_leaves_the_workers_free` |
| O-2 | ✅ Свои запросы ядра после неудачи — пауза `own_retry_ms` (1 с ×2, ≤ 15 мин, в `wakeup_in_ms`); после 3 постоянных отказов (4xx кроме 401/408/429) — выброшены, `RequestRejected`, `debug_report.requests.rejected`; выброшенный `SecretPut` уходит и из очереди в хранилище; повтор полного ящика при постоянном отказе сдаёт устройства. ADR A8, контракт хоста в документации крейта | `31fa59b`, `ff0b20f` | `own_requests_back_off_then_are_dropped`, `retries_refused_for_good_give_up_their_devices`, `own_requests_refused_for_good_are_dropped` |
| O-3 | ⚠️ оставлено: `set_device_trust(Verified)` нужен тестам; контракт хоста, ядро и FFI явно говорят — хост ставит только `Unverified`/`Blocked`, `Verified` даёт SAS `Done`; Android закрепляет в `:core:crypto` (5B) | `c6e463d` | — |
| O-4 | ✅ `in_reply_to` и `replies` сравниваются как множества: бэкенд убирает повторы id (`stoatchat` `messages/model.rs`, первое вхождение), порядок сохраняет — повтор id в `in_reply_to` давал ложный `reply_mismatch`; лишний/пропавший id по-прежнему помечается. `protocol.md` дополнен | `d6a583e` | `replies_compare_as_sets`, `s07_server_tampering` |
| O-5 | ⚠️ без изменений: защита — документация и правило в Android (5B) | — | — |
| O-6 | ⚠️ без изменений: уровень логов — у хоста (5B) | — | — |
| O-7 | ✅ Разбор заголовка — `proto::key_export::parse` (нормализация base64 без паддинга), ядро вызывает его до библиотеки; fuzz-цель `key_export` (+ в `fuzz.yml`): 60 с, 11,9 M запусков, падений нет | `7208cc8` | `header_fields_are_checked`, `overlapping_armor_is_refused` |
| O-8 | ✅ Предел файла экспорта 64 МиБ (`key_export::MAX_FILE_LEN`, ≈ 90 000 сессий): длиннее — `InvalidKeyFile` до любой обработки; экспорт сверх предела не пишется (`InvalidKeyFile`: экспортировать меньше каналов) | `2d02958` | `oversized_files_are_refused_first`, `wrong_passphrase_or_broken_file` |

Строки таблицы §2 обновлены: E1 (`run_blocking`), J1 (`key_export.rs`, предел файла), J2 (цель `key_export`),
D4 (отказы своих запросов), B1–B5 (ответы как множества).

## 5. Открыто (решения, не дефекты)

- **O-3, O-5, O-6** — см. §4: закрываются на стороне Android (5B).
- Ослабления прошлых этапов (вытеснение таблиц CR-19, ≤ 512 каналов при поиске переноса, запросы ключей
  только к своим проверенным устройствам, подделываемость бэкапа v1, PBKDF2 для пароля, таймауты SAS) —
  `docs/security-review.md` §3, без изменений.
