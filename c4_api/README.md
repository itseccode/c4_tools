# Используемые обозначения

ЦУС - Центр управления сетью.

УБ - Узел безопасности.

МК - Менеджер конфигурации.

# Назначение инструмента

1. Экспорт конфигурации всех или выбранных УБ под управлением отдельного ЦУС путем эксплуатации его API.
2. Команда ЦУС на установку политики путем эксплуатации его API.

# Основные функции инструмента

1. Вывод на экран списка УБ под управлением отдельного ЦУС с указанием `HW ID`.
2. Экспорт конфигурации для всех УБ под управлением отдельного ЦУС.
3. Экспорт конфигурации для выбранных УБ под управлением отдельного ЦУС (выбор по `HW ID`).
4. Команда ЦУС на установку политики.
5. Вывод на экран справки по использованию инструмента.

# Основные характеристики инструмента

1. Инструмент представлен набором скриптов на языке Python.
2. Инструмент предоставляет пользователю интерфейс - CLI.
3. Инструмент поставляется в виде архива `*.tar.gz`.
4. Инструмент поставляется в комплекте с дополнительным компонентом `gost.so`, необходимым для его работы.
5. Инструмент содержит встроенную справку по использованию (ключи, параметры).
6. Инструмент доустанавливает дополнительный компонент `pycurl`, необходимый для его работы. 
7. Инструмент извлекает конфигурацию УБ, отмеченную как `master`.
8. Инструмент использует встроенную учетную запись - `admin` (роль - "Главный администратор").
9. Инструмент использует компонент `curl` для взаимодействия с API ЦУС.
10. Инструмент взаимодействует с ЦУС по анонимному TLS соединению (ГОСТ).
11. Инструмент использует компонент `openssl` в качестве криптографической оснатски.
12. Инструмент сопровождается технической спецификацией `*.html`.
13. Инструмент может использовать в качестве библиотеки в составе других инструментов.

# Системные требования 

1. Рабочая станция пользователя под управлением ОС Linux.
2. Физический и логический сетевой доступ рабочей станции пользователя к ЦУС.
3. Установленный интерпретатор Python последней версии.
4. Установленный компонент `curl` для формирования HTTP запросов.
5. Установленный компонент `openssl` версии 3.0.
6. Наличие IP адреса рабочей станции пользователя в списке разрешенных для подключения МК к ЦУС.

# Справка по использованию инструмента

```
usage: 

c4_api [-h] -u CREDS --ip IP [--port PORT] [--output_path OUTPUT_PATH] [--hwserial HWSERIAL] [--with_confidential_data | --no-with_confidential_data]
                 {get_all_cgw_configs,get_cgw_config_by_hwserial,print_cgws,install_policy_all}

Утилита для экспорта конфигурации из Континент 4.
	print_cgws - вывести список УБ с их hwserial.
	get_all_cgw_configs - получить конфигурации всех УБ.
	get_cgw_config_by_hwserial - получить конфигурацию УБ по hwserial.
	install_policy_all - установить политику на все узлы конфигурации.

positional arguments:
  {get_all_cgw_configs,get_cgw_config_by_hwserial,print_cgws,install_policy_all}

options:
  -h, --help            Показать текущее сообщение помощи и выйти.
  -u CREDS, --creds CREDS
                        Реквизиты в формате user:pass
  --ip IP               IP сервера.
  --port PORT           Порт сервера.
  --output_path OUTPUT_PATH
                        Путь до папки для сохранения конфигураций.
                        (get_all_cgw_configs, get_cgw_config_by_hwserial)
  --hwserial HWSERIAL   hwserial для получения конфигурации конкретного УБ. (get_cgw_config_by_hwserial)
  --with_confidential_data, --no-with_confidential_data
                        Выгружать конфигурацию с чувствительной информацией. По умолчанию выключено.

example: c4_api -u user:pass --ip 172.16.10.1 print_cgws
example: c4_api -u user:pass --ip 172.16.10.1 get_all_cgw_configs --output_path /path/to/folder
example: c4_api -u user:pass --ip 172.16.10.1 get_cgw_config_by_hwserial --hwserial 1 --output_path /path/to/folder
example: c4_api -u user:pass --ip 172.16.10.1 install_policy_all
```