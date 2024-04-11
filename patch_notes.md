# История изменений

> Изменения представлены списком от последних к ранним.

**UPD 11/04/24**

- Доработана утилита `c4_config_exporter` (игнорируется пустое значение hwserial для случаев с кластером).
- Доработана утилита `c4_ioc_importer_sv` (учитываются изменения API после добавления функциональности SNI).
- Доработана утилита `c4_ioc_importer_rv` (учитываются изменения API после добавления функциональности SNI).
- Новая утилита `convert_ug_to_c4` для переноса данных из UserGate.

**UPD 06/03/24**

- Поправлен баг в утилите `convert_cisco_to_c4` (опечатка в парсере при обработке группы сервисов из одного элемента).

**UPD 05/03/24**

- Поправлен баг в утилите `convert_cp_to_c4` в части агрегации правил FW и NAT.
- Доработана утилита `convert_cisco_to_c4` в части поддержки конфигураций, выгруженных с решений Firepower.

**UPD 04/03/24**

- Поправлен баг в утилите `convert_forti_to_c4` (ранее создавалась пустая группа, если в ней присутствовал только один сервис).

**UPD 16/02/24**

- Скорректирована утилита `convert_forti_to_c4` в части чтения нескольких политики из одного конфигурационного файла.

**UPD 07/02/24**

- Скорректирована утилита `convert_forti_to_c4` в части агрегации правил NAT.

**UPD 30/01/24**

- Новая утилита `c4_xls_rules_maker` для автоматизированного создания правил фильтрации (FW) и трансляции (NAT) по заданному шаблону, в том числе при миграции данных из Palo Alto Networks.

**UPD 26/12/23**

- Новая утилита `c4_vlan_maker` для автоматизированного создания логических интерфейсов VLAN в привязке к УБ/кластеру по данным из файла Excel.

**UPD 02/11/23**

- Новая утилита `aserv_c4_importer` для переноса (миграции) данных с СД Континент 3 на СД Континент 4.

**UPD 30/10/23**

- Обновлена библиотека `c4_lib` (добавлена поддержка методов в рамках доработок инструментов)
- Обновлена утилита `c4_backup_tool`. Учет дубликатов и одинаковых имен бэкапов, удаление бэкапов по заданному имени.

**UPD 26/10/23**

- Скорректированы общие сведения о репозтории.
- Исправлены ошибки в описаниях к утилитам.
- Обновлена библиотека `c4_lib` (добавлена поддержка методов для новых инструментов).
- Обновлена утилита `convert_cp_to_c4`. Учтена валидация на стороне Континент 4 в части типов/кодов сообщений ICMP.
- Обновлена утилита `convert_cp_json_to_c4`. Учтена валидация на стороне Континент 4 в части типов/кодов сообщений ICMP.
- Новая утилита `convert_forti_to_c4` для переноса данных из FortiGate.
- Новая утилита `convert_cisco_to_c4` для переноса данных из Cisco ASA.
- Новая утилита `c4_ioc_importer_sv` для импорта объектов IoC от вендора Security Vision (начиная с версии Континент 4.1.9).
- Новая утилита `с4_ioc_importer_rv` для импорта объектов IoC от вендора R-Vision (начиная с версии Континент 4.1.9).

**UDP 28/07/23**

- Новая утилита `c4_backup_tool` для создания резервной копии БД конфигурации ЦУС через API.
- Утилита `с4_api` заменена на библиотеку c4_lib для работы с API. Теперь она необходима для работы других утилит.
- Утилита `c4_api` заменена на утилиту `c4_config_exporter`. Теперь она отвечает за экспорт конфигурации, но без установки политики.
- Новая утилита `c4_config_transfer` для переноса правил и объектов с одного ЦУС на другой в универсальном формате (JSON).
- Доработана утилита `c4_rules_maker`. Теперь можно добавлять правила трансляции, использовать сервисы, добавлять несколько хостов в одну ячейку.
- Новая утилита `c4_policy_install` для подачи ЦУС команды на установку политики.
- Доработана утилита `convert_cp_to_c4`. Добавлена нарезка результирующего файла (JSON), исправлена проблема с переносом сервисов ICMP.
- Новая утилита `convert_cp_json_to_c4` для переноса данных из Check Point R81.