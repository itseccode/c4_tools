# Назначение инструмента

Конвертация конфигурации Check Point из форматов `*.fws` и `*.c` с кодировкой UTF-8 в универсальный формат `*.json` для последующего импорта в Континент 4 (далее - К4) в объеме:

  - правила фильтрации сетевого трафика;
  - правила трансляции сетевых адресов;
  - сетевые объекты, используемые в правилах;
  - сервисы, используемые в правилах;
  - временные интервалы, используемые в правилах.

Для получения конфигурации Check Point в форматах `*.fws` и `*.c` необходимо подключиться к шлюзу (серверу управления) по SFT и скачать соответствующие файлы.

При большом количестве правил и связанных в объектов в исходной конфигурации подразумевается создание нескольких файлов в универсальном формате `*.json` c нумерацией в имени, исходя:

  - либо из заданного пользователем ограничение на количество обрабатываемых объектов;
  - либо из максимально допустимого количества объектов (20000), которое может быть обработано при импорте на ЦУС.

С учетом ограничения на количество обрабатываемых объектов в результате конвертации может быть создано несколько файлов в универсальном формате `*.json`, а именно:

  - несколько файлов с суффиксом `-fw`, содержащих правила фильтрации сетевого трафика и связанные с ними объекты;
  - несколько файлов с суффиксом `-nat`, содержащих правила трансляции сетевых адресов и связанные с ними объекты.

Вложенные правила (при наличии таковых в конфигурации Check Point) попадают в файл без номера с суффиксом `-fw` или `-nat` соответственно.

# Замечания для правил фильтрации

1. Все импортированные правила на стороне К4 будут отключены вне зависимости от оригинального значения параметра "Disabled" в Check Point.
2. В описании каждого правила будут отражены следующие параметры:

    - описание объекта системы из Check Point;
    - значения параметров, которые не переносятся из Check Point в К4 или каким либо-образом трансформируются;
    - информация о наличии связей между объектами системы и сетевыми устройствами.

3. Если в качестве "Source" на стороне Check Point не указано ни одного сетевого объекта, на стороне К4 для "Отправителя" будет установлено значение "Любой" / "Any".
4. Если в качестве "Destination" на стороне Check Point не указано ни одного сетевого объекта, на стороне К4 для "Получателя" будет установлено значение "Любой" / "Any".
5. При импорте правил из Check Point в К4 не осуществляется перенос сетевых объектов, тип которых отличается от `host` / `network` / `machines_range` / `group`.
6. Если в качестве "Service" на стороне Check Point не указано ни одного объекта, на стороне К4 для "Сервиса" будет установлено значение "Любой" / "Any".
7. При импорте правил из Check Point в К4 не осуществляется перенос сервисов с типом `DceRpc` или `icmpv6`.
8. При импорте правил из Check Point в К4 не осуществляется перенос других сервисов с протоколами `0` / `41` / `43` / `44` / `45` / `46` / `50` / `51` / `58` / `59` / `60`.
9. При импорте правил из Check Point в К4 не осуществляется перенос ICMP сервисов если их тип и код не входят в список поддерживаемых.
10. При импорте правил из Check Point в К4 параметр "Действие" / "Action" переносится согласно следующим правилам:

    - если в качестве "Action" на стороне Check Point указано значение "Accept", на стороне К4 для "Действия" будет установлено значение "Пропустить" / "Accept";
    - если в качестве "Action" на стороне Check Point указано значение "Reject", на стороне К4 для "Действия" будет установлено значение "Отбросить" / "Drop";
    - если в качестве "Action" на стороне Check Point указано значение "Drop", на стороне К4 для "Действия" будет установлено значение "Отбросить" / "Drop".

11. При импорте правил из Check Point в К4 не осуществляется перенос правил фильтрации, действие которых отличается от `accept` / `reject` / `drop`.
12. Если в качестве "Time" на стороне Check Point не указано ни одного объекта, на стороне К4 для "Временного интервала" будет установлено значение "Всегда" / "Always".
13. При импорте правил из Check Point в К4 не осуществляется перенос временных объектов с типом `scheduled_event` или `group`. 
14. При импорте правил из Check Point в К4 не осуществляется перенос временных объектов, содержащих значение месяца и порядкового дня месяца в качестве старта или окончания временного интервала.
15. При импорте правил из Check Point в К4 не осуществляется перенос временных объектов, содержащих значение месяца и порядкового дня месяца в качестве периода повторения работы временного интервала.
16. При импорте правил из Check Point в К4 параметр "Track" / "Лог" ("Log") переносится согласно следующим правилам:

    - если в качестве "Track" на стороне Check Point указано значение "Alert", на стороне К4 будет автоматически включено логирование работы правила;
    - если в качестве "Track" на стороне Check Point указано значение "Log", на стороне К4 будет автоматически включено логирование работы правила;
    - если в качестве "Track" на стороне Check Point указано значение "None", на стороне К4 не будет автоматически включено логирование работы правила (логирование выключено).

17. При импорте правил из Check Point в К4 не осуществляется перенос правил фильтрации, для которых параметр "Track" равен "Account".
18. В К4 не переносится параметр "VPN".
19. При импорте правил из Check Point в К4 будут добавлены следующие необходимые для корректной работы системы параметры (для этих параметров на стороне К4 будут установлены значения по умолчанию):

    - Профиль Web/FTP фильтрации;
    - Приложение;
    - СОВ.

20. Для сетевых объектов типа `host` при импорте правил из Check Point в К4 не осуществляется перенос следующих параметров:

    - NAT;
    - SNMP;
    - Color;
    - FIreWall-1 GX;
    - IPv6 address;
    - OS.

21. Для сетевых объектов типа `network` при импорте правил из Check Point в К4 не осуществляется перенос следующих параметров:

    - NAT;
    - Broadcast;
    - Color;
    - Network address (IPv6);
    - Prefix (IPv6).

22. Для сетевых объектов типа `machines_range` при импорте правил из Check Point в К4 не осуществляется перенос следующих параметров:

    - NAT;
    - Color;
    - First IPv6 address;
    - Last IPv6 address.

23. Для сервисов типа `tcp` / `udp` при импорте правил из Check Point в К4 не осуществляется перенос следующих параметров: 

    - Color;
    - Enable Aggressive Aging;
    - Aggressive Aging Timeout;
    - Protocol type;
    - Accept Peplies;
    - Match for "Any";
    - Synchronize connections on Cluster;
    - Start synchronizing;
    - Enable for TCP resource.

24. Для сервисов типа `other` при импорте правил из Check Point в К4 не осуществляется перенос следующих параметров: 

    - Color;
    - Enable Aggressive Aging;
    - Aggressive Aging Timeout;
    - Protocol type;
    - Accept Peplies;
    - Synchronize connections on Cluster.

25. Для сервисов типа `icmp` при импорте правил из Check Point в К4 не осуществляется перенос следующих параметров: 
    - Color;
    - Protocol type.

# Замечания для правил трансляции

1. Все импортированные правила на стороне К4 будут отключены вне зависимости от установленного значения параметра "Disabled" в Check Point.
2. В описании каждого правила будут отражены следующие параметры:

    - описание объекта системы из Check Point;
    - значения параметров, которые не переносятся из Check Point в К4 или каким либо-образом трансформируются;
    - информация о наличии связей между объектами системы и сетевыми устройствами.

3. Если в качестве "Source (Original)" на стороне Check Point не указано ни одного сетевого объекта, на стороне К4 для "Отправителя (Исходный пакет)" будет установлено значение "Любой" / "Any".
4. Если в качестве "Destination (Original)" на стороне Check Point не указано ни одного сетевого объекта, на стороне К4 для "Получателя (Исходный пакет)" будет установлено значение "Любой" / "Any".
5. При импорте правил из Check Point в К4 не осуществляется перенос сетевых объектов, тип которых отличается от `host` / `network` / `machines_range` / `group`.
6. Не осуществляется перенос правил, содержащих инвертированные сетевые объекты в качестве значения "Source (Original)" и/или "Destination (Original)".
7. Если в качестве "Service (Original)" на стороне Check Point не указано ни одного объекта, на стороне К4 для "Сервиса (Исходный пакет)" будет установлено значение "Любой" / "Any".
8. При импорте правил из Check Point в К4 не осуществляется перенос сервисов с типом `DceRpc` или `icmpv6`.
9. При импорте правил из Check Point в К4 тип трансляции переносится согласно следующим правилам:

    - если на стороне Check Point значения "Source (Original)", "Destination (Original)" и "Service (Original)" соответственно равны значениям "Source (Translated)", "Destination (Original)", "Service (Translated)", на стороне К4 для "Трансляция" будет установлено значение "Не транслировать" / "No NAT";
    - если на стороне Check Point значения "Source (Original)" и "Source (Translated)" между собой не равны и значения "Destination (Original)" и "Destination (Translated)" равны, на стороне К4 для "Трансляция" будет установлено значение "Отправителя" / "Source";
    - если на стороне Check Point значения "Destination (Original)" и "Destination (Translated)" не равны и значения "Source (Original)" и "Source (Translated)" между собой не равны, на стороне К4 для "Трансляция" будет установлено значение "Получателя" / "Destination".

10. Не осуществляется перенос правил, для которых на стороне Check Point значения "Source (Original)" и "Source (Translated)" между собой не равны и значения "Destination (Original)" и "Destination (Translated)" между собой не равны.
11. Не осуществляется перенос правил, для которых на стороне Check Point значение "Service (Original)" равно "ANY" и значение "Service (Translated)" не равно "ANY".
12. Если в качестве "Service (Translated)" на стороне Check Point не указано ни одного объекта на стороне К4 для "Сервиса (Преобразованный пакет)" будет установлено значение "Любой" / "Any".
13. Не осуществляется перенос правил, для которых на стороне Check Point значения "Service (Original)" содержит протокол который отличается от `6` (TCP) или `17` (UDP).
14. Не осуществляется перенос правил, для которых на стороне Check Point значения "Service (Translated)" содержит протокол который отличается от `6` (TCP) или `17` (UDP).
15. Для сетевых объектов типа `host` при импорте правил из Check Point в К4 не осуществляется перенос следующих параметров: 

    - NAT;
    - SNMP;
    - Color;
    - FIreWall-1 GX;
    - IPv6 adress;
    - OS.

16. Для сетевых объектов типа `network` при импорте правил из Check Point в К4 не осуществляется перенос следующих параметров: 

    - NAT;
    - Broadcast;
    - Color;
    - Network address (IPv6);
    - Prefix (IPv6).

17. Для сетевых объектов типа `machines_range` при импорте правил из Check Point в К4 не осуществляется перенос следующих параметров: 

    - NAT;
    - Color;
    - First IPv6 address;
    - Last IPv6 address.

18. Для сервисов типа `tcp` / `udp` при импорте правил из Check Point в К4 не осуществляется перенос следующих параметров: 

    - Color;
    - Enable Aggressive Aging;
    - Aggressive Aging Timeout;
    - Protocol type;
    - Accept Peplies;
    - Match for "Any";
    - Synchronize connections on Cluster;
    - Start synchronizing;
    - Enable for TCP resource.

19. Для сервисов типа `other` при импорте правил из Check Point в К4 не осуществляется перенос следующих параметров: 

    - Color;
    - Enable Aggressive Aging;
    - Aggressive Aging Timeout;
    - Protocol type;
    - Accept Peplies;
    - Synchronize connections on Cluster.

20. Для сервисов типа `icmp` при импорте правил из Check Point в К4 не осуществляется перенос следующих параметров: 

    - Color;
    - Protocol type.

# Приложения

К инструменту прилагаются следующие материалы:

- `c4_unified_json.svg` - описание структуры (схема) импортируемых данных.
