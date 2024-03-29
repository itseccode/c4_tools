# Используемые обозначения

ЦУС - Центр управления сетью.

УБ - Узел безопасности.

СД - Сервер доступа.

МК - Менеджер конфигурации.

АРМ - Автоматизированное рабочее место.

# Континент 4 - Инструменты

**Важно!** Последние изменения представлены в файле `patch_notes.txt`.

Репозиторий содержит инструменты для решения различных сервисных задач при использовании продукта Континент 4:

| Инструмент              | Назначение                                                                                                  | Формат  | Комментарий                                                                        |
|-------------------------|-------------------------------------------------------------------------------------------------------------|---------|------------------------------------------------------------------------------------|
| `c4_lib`                | Библиотека для работы с API Континент 4                                                                     | Online  | Нет                                                                                |
| `c4_config_exporter`    | Инструмент для экспорта конфигурации УБ для сторонних compliance-систем                                     | Online  | Только совместно с `c4_lib`                                                        |
| `c4_rules_maker`        | Инструмент для генерации правил по заданным директивам                                                      | Online  | Только совместно с `c4_lib`                                                        |
| `c4_vlan_maker`         | Инструмент для генерации логических интерфейсов VLAN по заданному списку                                    | Online  | Только совместно с `c4_lib`                                                        |
| `c4_xls_rules_maker`    | Инструмент для создания правил фильтрации (FW) и трансляции (NAT) по заданному шаблону                      | Online  | Только совместно с `c4_lib`, в том числе для миграции данных из Palo Alto Networks |
| `c4_backup_tool`        | Инструмент для создания и выгрузки резервной копии БД ЦУС                                                   | Online  | Только совместно с `c4_lib`                                                        |
| `c4_config_transfer`    | Инструмент для переноса в ограниченном объеме политики между разными ЦУС                                    | Online  | Только совместно с `c4_lib`                                                        |
| `c4_policy_install`     | Инструмент для подачи ЦУС команды на установку политики                                                     | Online  | Только совместно с `c4_lib`                                                        |
| `c4_ioc_importer_rv`    | Инструмент для импорта объектов IoC (Indicator of Compromise) от вендора R-Vision                           | Online  | Только совместно с `c4_lib`, Континент 4.1.9 и выше                                |
| `c4_ioc_importer_sv`    | Инструмент для импорта объектов IoC (Indicator of Compromise) от вендора Security Vision                    | Online  | Только совместно с `c4_lib`, Континент 4.1.9 и выше                                |
| `aserv_c4_importer`     | Инструмент для переноса (миграции) данных с СД Континент 3 на СД Континент 4                                | Online  | Только совместно с `c4_lib`, Континент 3.9.4 &rarr; Континент 4.1.9 и выше         |
| `convert_с3_to_c4`      | Инструмент для конвертации конфигурации из `*.xml` Континент 3 и последующего импорта в Континент 4         | Offline | Континент 3.9.3 &rarr; Континент 4.1.7 и выше                                      |
| `convert_cp_to_c4`      | Инструмент для конвертации конфигурации из `*.fws` и `*.c` Check Point и последующего импорта в Континент 4 | Offline | Check Point R77.30 / R80.20 &rarr; Континент 4.1.7 и выше                          |
| `convert_cp_json_to_c4` | Инструмент для конвертации конфигурации из `*.json` Check Point и последующего импорта в Континент 4        | Offline | Check Point R81.10 &rarr; Континент 4.1.7 и выше                                   |
| `convert_forti_to_c4`   | Инструмент для конвертации конфигурации из `*.conf` FortiGate и последующего импорта в Континент 4          | Offline | FortiGate 5.0.4 / 7.2.0 &rarr; Континент 4.1.7 и выше                              |
| `convert_cisco_to_c4`   | Инструмент для конвертации активной (running) конфигурации Cisco ASA и последующего импорта в Континент 4   | Offline | Cisco ASA 8.3 / 8.4 / 9.1 &rarr; Континент 4.1.7 и выше                            |

> В комментариях указана версия системы-источника, на которой проверялась работа. Для других версий результаты работы инструментов и функции импорта данных в Континент 4 могут отличаться.

> Инструменты, работающие с API Континент 4 могут устанавливаться на одной рабочей станции пользователя в любой комбинации при условии предварительной установки библиотеки `c4_lib`.
