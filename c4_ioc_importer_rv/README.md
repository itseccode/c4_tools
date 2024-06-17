# Назначение инструмента

Импорт через API Континент 4 объектов IoC (Indicator of Compromise) от вендора [R-Vision](https://rvision.ru/), включая IP адреса, URL и домены (FQDN), из контейнера `*.json` в следующем формате:

```
[
    {
        "type": "ip",
        "value": "10.10.10.10",
        "created_at": null,
        "modified_at": null,
        "collected_at": "YYYY-MM-DDTHH:MM:SS.MSS+TZ"
    },
    {
        "type": "domain",
        "value": "sample.com",
        "created_at": null,
        "modified_at": null,
        "collected_at": "YYYY-MM-DDTHH:MM:SS.MSS+TZ"
    },
    {
        "type": "url",
        "value": "https://sample.com/resource",
        "created_at": null,
        "modified_at": null,
        "collected_at": "YYYY-MM-DDTHH:MM:SS.MSS+TZ"
    }
]
```

# Основные функции

1. Использование библиотеки `c4_lib` для работы с API Континент 4.
2. Импорт IP адресов в качестве объектов ЦУС типа "Хост" и помещение их в соответствующую группу.
3. Импорт URL в качестве Web/FTP фильтров и помещение их в соответствующие группы.
4. Импорт доменов (FQDN) в качетсве объектов ЦУС типа "DNS имя" и помещение их в соответствующую группу.
5. Вывод на экран справки по использованию инструмента.
6. Соблюдение следующего порядка именования созданных при импорте объектов:

```
    --- IPs ---
    IoC_RV_AAA.BBB.CCC.DDD                      // Вредоносный хост
    IoC_RV_IP_Group                             // Группа вредоносных хостов
    --- Domains ---
    IoC_RV_sample.com                           // Вредоносный домен
    IoC_RV_Domain_Group                         // Группа вредоносных доменов
    --- URLs ---
    IoC_RV_URL_HTTP_Group                       // Группа URL-ов со схемой HTTP
    IoC_RV_URL_HTTPS_Group                      // Группа URL-ов со схемой HTTPS
    --- Profiles ---
    IoC_RV_HTTPS_Profile                        // Профиль Web/FTP со схемой HTTPS
        > IoC_RV_URL_HTTP_Group                 // См. выше
        > IoC_RV_URL_HTTPS_Group                // См. выше
```
