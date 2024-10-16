# Назначение инструмента

Импорт через API Континент 4 объектов IoC (Indicator of Compromise) от вендора [Security Vision](https://www.securityvision.ru/), включая IP адреса, URL, хэши файлов и домены (FQDN), из контейнера `*.json` в следующем формате:

```
{
	"ioc":
	{
		"hashes":
		[
			{
				"md5": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
				"filename": "sample.txt",
				"filesize": 12345
			}
		],
		"ips":
		[
			{
				"ip": "10.10.10.10"
			}
		],
		"domains":
		[
			{
				"domain": "sample.com"
			}
		],
		"urls":
		[
			{
				"url": "http://sample.com/resource"
			}
		]
	}
}
```

# Основные функции

1. Использование библиотеки `c4_lib` для работы с API Континент 4.
2. Импорт IP адресов в качестве объектов ЦУС типа "Хост" и помещение их в соответствующую группу.
3. Импорт URL в качестве Web/FTP фильтров и помещение их в соответствующие группы.
4. Импорт доменов (FQDN) в качетсве объектов ЦУС типа "DNS имя" и помещение их в соответствующую группу.
5. Импорт хэшей файлов в качестве пользовательской базы для потокового антивируса через репозиторий обновлений ЦУС.
6. Вывод на экран справки по использованию инструмента.
7. Соблюдение следующего порядка именования созданных при импорте объектов:

```
    --- IPs ---
    IoC_SV_AAA.BBB.CCC.DDD                      // Вредоносный хост
    IoC_SV_IP_Group                             // Группа вредоносных хостов
    --- Domains ---
    IoC_SV_sample.com                           // Вредоносный домен
    IoC_SV_Domain_Group                         // Группа вредоносных доменов
    --- URLs ---
    IoC_SV_URL_HTTP_Group                       // Группа URL-ов со схемой HTTP
    IoC_SV_URL_HTTPS_Group                      // Группа URL-ов со схемой HTTPS
    --- ECAPs ---
    IoC_SV_ECAP                                 // ECAP сервис (потоковый антивирус)
    --- Profiles ---
    IoC_SV_HTTPS_Profile                        // Профиль HTTPS
        > IoC_SV_URL_HTTP_Group                 // См. выше
        > IoC_SV_URL_HTTPS_Group                // См. выше
        > IoC_SV_ECAP                           // См. выше
```

> Расписание доставки на УБ списка импортированных хэшей файлов администратор настраивает самостоятельно.
