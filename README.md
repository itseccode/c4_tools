# Континент 4 - Инструменты

Репозиторий содержит инструменты для решения различных сервисных задач при использовании продукта Континент 4:

- `c4_lib` - библиотека для работы с API Континент 4, который используется для поддержки связи МК-ЦУС.
- `c4_config_exporter` - инструмент для экспорта конфигурации УБ для сторонних compliance-систем (например, для Efros).
- `c4_rules_maker` - инструмент для генерации правил по заданным директивам через API Континент 4.
- `c4_backup_tool` - инструмент для создания и выгрузки резервной копии БД ЦУС (например, по расписанию).
- `c4_config_transfer` - инструмент для переноса политики в ограниченном объеме между разными ЦУС.
- `c4_policy_install` - инструмент для подачи ЦУС команды на установку политики (например, по расписанию).
- `convert_с3_to_c4` - инструмент для конвертации конфигурации из контейнера `*.xml` Континент 3.9.3 и последующего ее импорта (миграции) в Континент 4.1.7 и выше.
- `convert_cp_to_c4` - инструмент для конвертации конфигурации из контейнеров `*.fws` (правила) и `*.c` (объекты) Check Point R77.30 / R80.20 и последующего ее импорта (миграции) в Континент 4.1.7 и выше.
- `convert_cp_json_to_c4` - инструмент для конвертации конфигурации из контейнеров `*.json` (правила) и `*.json` (объекты) Check Point R81.10 и последующего ее импорта (миграции) в Континент 4.1.7 и выше.
