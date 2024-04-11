#!/usr/bin/env python3
import json
from os.path import basename
import sys
import argparse
import logging
import pathlib
import copy

OUTPUT_FILENAME = "{}-{}-{}.json"
MAX_DESCR_LEN = 1024
MAX_OBJECTS_BORDER = 20000

if sys.version_info.major == 3 and sys.version_info.minor < 9:
    logging.basicConfig(level=logging.INFO,
    format='%(asctime)s %(levelname)-8s %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
else:
    logging.basicConfig(encoding='utf-8', level=logging.INFO,
    format='%(asctime)s %(levelname)-8s %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
log = logging.getLogger(__name__)

error_counter = {}
section_dict = {
    'NetObjects': 'Сетевые объекты',
    'NetObjectGroups': 'Группы сетевых объектов',
    'Services': 'Сервисы',
    'ServiceGroups': 'Группы сервисов',
    'TimeIntervals': 'Временные интервалы',
    'FilterRules': 'Правила фильтрации',
    'NatRules': 'Правила трансляции'
}

stats_header_dict = {
    'done': 'Извлечено успешно:',
    'warning': 'Извлечено с предупреждениями:',
    'error': 'Извлечено с ошибками:',
    'output': 'Записано итого:'
}

transport_protocols = {
    'tcp': 6,
    'udp': 17,
    'sctp': 132
}

ip_proto = {
    'ip': 0,
    'icmp': 1,
    'igmp': 2,
    'ggp': 3,
    'ipip': 4,
    'st': 5,
    'egp': 8,
    'igp': 9,
    'pup': 11,
    'hmp': 20,
    'xns-idp': 22,
    'rdp': 27,
    'iso-tp4': 29,
    'dccp': 33,
    'xtp': 36,
    'ddp': 37,
    'idpr-cmtp': 38,
    'ipv6': 41,
    'ipv6-route': 43,
    'ipv6-frag': 44,
    'idrp': 45,
    'rsvp': 46,
    'gre': 47,
    'esp': 50,
    'ah': 51,
    'skip': 57,
    'ipv6-icmp': 58,
    'ipv6-nonxt': 59,
    'ipv6-opts': 60,
    'vmtp': 81,
    'eigrp': 88,
    'ospf': 89,
    'ax.25': 93,
    'nos': 94,
    'etherip': 97,
    'encap': 98,
    'pim': 103,
    'ipcomp': 108,
    'snp': 109,
    'vrrp': 112,
    'l2tp': 115,
    'isis': 124,
    'sctp': 132,
    'fc': 133,
    'mobility-header': 135,
    'udplite': 136,
    'mpls-in-ip': 137,
    'manet': 138,
    'hip': 139,
    'shim6': 140,
    'wesp': 141,
    'rohc': 142
}
tcp_alias = [ 'tcpmux', 'echo-tcp', 'discard-udp', 'systat', 'daytime-tcp', 'netstat', 'qotd', 'chargen-tcp', 'ftp-data', 'ftp-control', 'ssh', 'telnet', 'smtp', 'time-tcp', 'whois', 'tacacs-tcp', 'dns-tcp', 'dhcp-tcp', 'gopher', 'finger', 'http', 'kerberos-tcp', 'iso-tsap', 'acr-nema', 'poppassd', 'pop2', 'pop3', 'rpc portmapper-tcp', 'auth tap ident', 'nntp', 'epmap', 'netbios session service', 'imap', 'snmp-tcp', 'snmptrap-tcp', 'https', 'smb', 'smtps', 'rsync', 'imaps', 'pop3s', 'openvpn-tcp', 'ms sql', 'citrix', 'netmeeting', 'radius-tcp', 'vpn pptp - tcp', 'mail agent', 'scada', 'citrix', 'firebird', 'mysql', 'rdp', 'svn-tcp', 'radmin', 'upnp', 'rtp-tcp', 'sip-tcp-5090', 'sip auth', 'sip-tcp', 'icq', 'xmpp-client', 'xmpp-server', 'postgres sql', 'irc', 'torrents-tcp', 'checkpoint proxy', 'http proxy', 'https proxy', 'dns proxy-tcp', ]
udp_alias = [ 'echo-udp', 'discard-udp', 'daytime-udp', 'chargen-udp', 'time-udp', 'tacacs-udp', 'dns-udp', 'dhcp bootps', 'dhcp bootpc', 'tftp', 'quick udp internet connections (port 80)', 'client-bank sberbank', 'kerberos-udp', 'rpc portmapper-udp', 'ntp', 'netbios name service', 'netbios datagram service', 'snmp-udp', 'snmptrap-udp', 'quick udp internet connections (port 443)', 'openvpn-udp', 'radius-udp', 'svn-udp', 'ipsec-udp', 'rtp-udp', 'sip-udp', 'vipnet client (port 5777)', 'torrents-udp', 'dns proxy-udp', 'vipnet client (port 55777)', ]

def get_minutes(time_str):
    colon_index = time_str.find(':')
    if colon_index >= 0:
        hours = time_str[:colon_index]
        mins = time_str[colon_index + 1:]
        return int(hours) * 60 + int(mins)
    else:
        return int(time_str)


def make_outpath(path_str):
    path = path_str
    if not path:
        home = pathlib.Path.home()
        if pathlib.Path(home / 'Загрузки').exists():
            path = home / 'Загрузки' / 'Continent' / 'Import'
        else:
            path = home / 'Downloads' / 'Continent' / 'Import'

    if not path.exists():
        log.info("Папка не существует, создание")
        pathlib.Path(path).mkdir(parents=True, exist_ok=True)
    return path


# Проверка описания на длину
def description_check(objs, members_sections):
    if not objs:
        return

    def check(obj):
        if not type(obj) == dict:
            return
        description = obj.get('description')
        if description:
            if len(description) > MAX_DESCR_LEN:
                log.warning(f'Слишком длинное описание: {obj}')
                section = obj['__internal_type']
                error_counter[section]['done'] -= 1
                error_counter[section]['warning'] += 1
                obj['description'] = description[:MAX_DESCR_LEN]
        for members_section in members_sections:
            if members_section in obj.keys():
                description_check(obj[members_section], members_sections)

    if not type(objs) == list:
        check(objs)
    else:
        for obj in objs:
            check(obj)


# Формирование отчёта по непереносимой информации
def print_report(filepath, objects, sections, members_sections):
    filename = filepath / "report.txt"

    def walk(objs, section, index, report_file):
        if not objs:
            return index

        for object in objs:
            if not type(object) == dict:
                continue

            if section == object['__internal_type']:
                error_counter[section]['output'] += 1
                write_object(object, report_file, index)
                index += 1

            for members_section in members_sections:
                if not members_section in object.keys():
                    continue

                if not type(object[members_section]) == list:
                    continue

                index = walk(object[members_section], section, index, report_file)

        return index

    def write_object(obj, report_file, index):
        report_file.write(f"{index}. Имя: {obj['name']}\n")
        report_file.write(f"Оригинальное описание: {obj['original_description']}\n")
        report_file.write("\n")

    with open(filename, "w", encoding="utf8") as report_file:
        report_file.write("Система-источник: UserGate\n")
        report_file.write("Система-назначение: Континент 4\n")
        for section in sections:
            index = 1
            report_file.write(f"\n{section_dict[section]}:\n")
            walk(objects, section, index, report_file)

    log.info(f"Сформирован отчёт: {filename}")


def add_to_list(list_object: list, added_object) -> list:
    out_list = list_object
    if type(added_object) == list:
        out_list.extend(added_object)
    elif not added_object == None:
        out_list.append(added_object)

    return out_list


def print_stats():
    for header in stats_header_dict.keys():
        log.info(stats_header_dict[header])
        for section in error_counter.keys():
            log.info(f'\t{section_dict[section]}: {error_counter[section][header]}')


# Удаление служебных полей из итоговой структуры
def remove_fields(objs, fields, members_sections):
    if not objs:
        return

    def remove_fields_internal(obj):
        if not type(obj) == dict:
            return

        for field in fields:
            if field in obj.keys(): del obj[field]

        for members_section in members_sections:
            if members_section in obj.keys():
                remove_fields(obj[members_section], fields, members_sections)

    if not type(objs) == list:
        remove_fields_internal(objs)
    else:
        for obj in objs:
            remove_fields_internal(obj)


def path_iterate(directory, command):
    """
    Вызывает функцию для каждого json файла из директории
    Возвращает список из данных, собранных от command
    """
    data_out = []
    if pathlib.Path(directory).exists():
        for pth in directory.iterdir():
            if pth.suffix == '.json':
                add_to_list(data_out, command(pth))
    else:
        log.debug(f'Не существует путь: {directory}')

    return data_out


def create_netobject(name = '', description = '', ip = ''):
    return {
        'name': name,
        'description': description,
        'original_description': description,
        '__internal_type': 'NetObjects',
        'type': 'netobject',
        'ip': ip
    }


def parse_IPAddresses(pth):
    input_data = {}
    with open(pth, 'r', encoding="utf8") as f:
        input_data = json.load(f)

    name = input_data.get('name', '')
    description = input_data.get('description', '')
    content = input_data.get('content', [])
    if len(content) == 1:
        first_value = content[0]
        ip = first_value.get('value')
        error_counter['NetObjects']['done'] += 1
        return create_netobject(name, description, ip)

    if len(content) > 1:
        group = {
            'name': name,
            'description': description,
            'subtype': 'netobject',
            'type': 'group',
            'members': [],
            'original_description': description,
            '__internal_type': 'NetObjectGroups'
        }
        error_counter['NetObjectGroups']['done'] += 1

        for val in content:
            ip = val.get('value')
            ip_name = ip.replace('/', '_')
            netobj = create_netobject(f"{name}: {ip_name}", description, ip)
            group['members'].append(netobj)
            error_counter['NetObjects']['done'] += 1

        return group


def create_service(name = '', description = '', service_data = {}):
    service = {
        'name': name,
        'description': description,
        'type': 'service',
        'proto': 0,
        'requires_keep_connections': False,
        'original_description': description,
        '__internal_type': 'Services'
    }
    proto = service_data.get('proto', '')
    proto = proto.lower()

    if proto in tcp_alias:
        proto = 'tcp'

    if proto in udp_alias:
        proto = 'udp'

    if proto in transport_protocols.keys():
        service['proto'] = transport_protocols[proto]
        service['src'] = service_data.get('source_port', '')
        service['dst'] = service_data.get('port', '')
    elif proto == 'icmp':
        service['proto'] = 1
        service['icmp_type'] = None
        service['icmp_code'] = None
    else:
        if proto in ip_proto.keys():
            service['proto'] = ip_proto[proto]
        else:
            log.error(f"Сервис некорректный: {service_data}")
            error_counter['Services']['error'] += 1
            return

    error_counter['Services']['done'] += 1
    return service


def parse_Services(pth):
    input_data = []
    out_data = []
    with open(pth, 'r', encoding="utf8") as f:
        input_data = json.load(f)

    for service in input_data:
        name = service.get('name', '')
        description = service.get('description', '')
        protocols = service.get('protocols', [])

        if len(protocols) == 1:
            first_value = protocols[0]
            out_data.append(create_service(name, description, first_value))

        if len(protocols) > 1:
            group = {
                'name': name,
                'description': description,
                'subtype': 'service',
                'type': 'group',
                'members': [],
                'original_description': description,
                '__internal_type': 'ServiceGroups'
            }
            error_counter['ServiceGroups']['done'] += 1

            for val in protocols:
                parts = []
                proto = val.get('proto', '')
                if not proto == '':
                    parts.append(proto)

                source_port = val.get('source_port', '')
                if not source_port == '':
                    parts.append(source_port)

                port = val.get('port', '')
                if not port == '':
                    parts.append(port)

                service_name = ' '.join(parts)
                service = create_service(f"{name}: {service_name}", description, val)
                group['members'].append(service)

            out_data.append(group)

    return out_data


def parse_TimeSets(pth):
    input_data = []
    out_data = []
    with open(pth, 'r', encoding="utf8") as f:
        input_data = json.load(f)

    for interval in input_data:
        name = interval.get('name', '')
        description = interval.get('description', '')
        interval_object = {
            'name': name,
            'description': description,
            'type': 'timeinterval',
            'intervals': [],
            'original_description': description,
            '__internal_type': 'TimeIntervals'
        }

        content = interval.get('content', [])
        for value in content:
            days = value.get('days', [])
            start = get_minutes(value.get('time_from', '00:00'))
            finish = get_minutes(value.get('time_to', '23:59'))
            for day in days:
                interval = {
                    'day': day,
                    'start': start,
                    'finish': finish
                }
                interval_object['intervals'].append(interval)

        error_counter['TimeIntervals']['done'] += 1
        out_data.append(interval_object)

    return out_data


def parse_Firewall(pth):
    input_data = []
    out_data = []
    with open(pth, 'r', encoding="utf8") as f:
        input_data = json.load(f)

    for rule in input_data:
        name = rule.get('name', '')
        description = rule.get('description', '')
        action = rule.get('action', 'drop')
        fw_rule = {
            'name': name,
            'description': description,
            'is_enabled': False,
            'rule_action': 'pass' if action == 'accept' else 'block',
            'src': rule.get('src_ips', []),
            'dst': rule.get('dst_ips', []),
            'service': rule.get('services', []),
            'params': rule.get('time_restrictions', []),
            'install_on': [],
            'passips': False,
            'rule_applications': [],
            'is_inverse_src': rule.get('src_ips_negate') == True,
            'is_inverse_dst': rule.get('dst_ips_negate') == True,
            'logging': rule.get('log') == True,
            'original_description': description,
            '__internal_type': 'FilterRules',
        }

        error_counter['FilterRules']['done'] += 1
        out_data.append(fw_rule)

    return out_data


def fill_nat_ports(rule, port_mapping):
    proto = port_mapping.get('proto')
    port = port_mapping.get('src_port')
    service = create_service( service_data={'proto': proto, 'port': port})
    rule['service'] = [service]

    port = port_mapping.get('dst_port')
    service = create_service( service_data={'proto': proto, 'port': port})
    rule['port_value'] = [service]
    rule['port_type'] = 'service'
    return rule


def parse_NATandRouting(pth):
    input_data = []
    out_data = []
    with open(pth, 'r', encoding="utf8") as f:
        input_data = json.load(f)

    for rule in input_data:
        status = 'done'
        name = rule.get('name', '')
        description = rule.get('description', '')
        nat_rule = {
            'name': name,
            'description': description,
            'original_description': description,
            'is_enabled': False,
            '__internal_type': 'NatRules',
            'src': rule.get('source_ip', []),
            'dst': rule.get('dest_ip', []),
            'service': rule.get('service', []),
            'install_on': [],
            'port_value': [],
            'port_type': [],
            'value': [],
            'address_type': [],
            'interface': None
        }

        # action - nat, dnat, port_mapping, route
        action = rule.get('action', '')
        if action == 'nat':
            nat_rule['nat_type'] = 'dynamic'
            target_ip = rule.get('snat_target_ip', '')
            if not target_ip == '':
                value = create_netobject(f"{name}: {target_ip}", '', target_ip)
                nat_rule['value'] = [value]
                nat_rule['address_type'] = 'netobject'
            else:
                nat_rule['nat_type'] = 'masquerade'

        elif action in ['dnat', 'port_mapping']:
            nat_rule['nat_type'] = 'dnat'
            if rule.get('target_snat', False):
                status = 'warning'
                log.warning(f"{name} - SNAT в правиле DNAT не поддерживается!")

            target_ip = rule.get('target_ip', '')
            if not target_ip == '':
                value = create_netobject(f"{name}: {target_ip}", '', target_ip)
                nat_rule['value'] = [value]
                nat_rule['address_type'] = 'netobject'

            port_mappings = rule.get('port_mappings', [])
            if not port_mappings == []:
                if not nat_rule.get('service', []) == []:
                    log.debug(f"{name} - {action} в правиле NAT port_mappings и service!")

                if len(port_mappings) == 1:
                    first_value = port_mappings[0]
                    nat_rule = fill_nat_ports(nat_rule, first_value)
                else:
                    for mapping in port_mappings:
                        copied_rule = copy.deepcopy(nat_rule)
                        copied_rule = fill_nat_ports(copied_rule, mapping)
                        error_counter['NatRules']['done'] += 1
                        out_data.append(copied_rule)
                    continue

        elif action == 'netmap':
            nat_rule['nat_type'] = 'static'
            target_ip = rule.get('target_ip', '')
            if not target_ip == '':
                value = create_netobject(f"{name}: {target_ip}", '', target_ip)
                nat_rule['value'] = [value]
                nat_rule['address_type'] = 'netobject'

        else:
            log.warning(f"{name} - {action} правило не поддерживается!")
            continue

        # в правиле NAT может быть только один сервис
        if len(nat_rule['service']) > 1:
            for srv in nat_rule['service']:
                copied_rule = copy.deepcopy(nat_rule)
                copied_rule['service'] = [srv]
                error_counter['NatRules'][status] += 1
                out_data.append(copied_rule)
            continue

        error_counter['NatRules'][status] += 1
        out_data.append(nat_rule)

    return out_data


def main():
    parser = argparse.ArgumentParser(
        formatter_class = argparse.RawTextHelpFormatter,
        prog = f"\n\npython {basename(sys.argv[0])}",
        description = 'Преобразование конфигурации UserGate в Континент 4.',
        epilog = f'''example: python {basename(sys.argv[0])} -i config_data -o output_folder_path
        ''',
        add_help = False
    )
    parser.add_argument('-h', '--help', action='help', default=argparse.SUPPRESS, help='Показать текущее сообщение помощи и выйти.')
    parser.add_argument('-i', '--input', help='Пути до директории с конфигурацией для преобразования', type=pathlib.Path, required=True)
    parser.add_argument('-o', '--output_path', help='Путь до папки для выходного файла', type=pathlib.Path)
    parser.add_argument('--log_file', help='Имя файла логирования', type=str)
    parser.add_argument('--name', help='Префикс имени выходного файла', type=str)
    parser.add_argument('--num_rule', help='Ограничение по количеству правил в файле.', type=int, default=0)
    args = parser.parse_args(args=None if sys.argv[1:] else ['--help'])
    outpath = make_outpath(args.output_path)

    # Настройка вывода логов в файл
    if args.log_file:
        fh = logging.FileHandler(outpath / args.log_file)
        formatter = logging.Formatter('%(asctime)s %(levelname)-8s %(message)s')
        fh.setFormatter(formatter)
        log.addHandler(fh)

    # Инициализация структуры данных для отчёта
    for section in section_dict.keys():
        error_counter[section] = {}
        for severity in stats_header_dict.keys():
            error_counter[section][severity] = 0

    # Парсинг
    log.info(f'Загрузка сетевых объектов')
    netobjects_path = args.input / 'Libraries' / 'IPAddresses'
    netobjects = path_iterate(netobjects_path, parse_IPAddresses)

    log.info(f'Загрузка сервисов')
    services_path = args.input / 'Libraries' / 'Services'
    services = path_iterate(services_path, parse_Services)

    log.info(f'Загрузка временных интервалов')
    time_intervals_path = args.input / 'Libraries' / 'TimeSets'
    time_intervals = path_iterate(time_intervals_path, parse_TimeSets)

    log.info(f'Загрузка правил фильтрации')
    firewall_path = args.input / 'NetworkPolicies' / 'Firewall'
    fw_rules = path_iterate(firewall_path, parse_Firewall)

    log.info(f'Загрузка правил трансляции')
    nat_path = args.input / 'NetworkPolicies' / 'NATandRouting'
    nat_rules = path_iterate(nat_path, parse_NATandRouting)

    log.info(f'Загрузка завершена')

    # Сохранение промежуточного представления при отладке
    if log.root.level <= logging.DEBUG:
        with open(outpath / 'netobjects.json', 'w') as f:
            json.dump(netobjects, f, indent=4, ensure_ascii=False)

        with open(outpath / 'services.json', 'w') as f:
            json.dump(services, f, indent=4, ensure_ascii=False)

        with open(outpath / 'time_intervals.json', 'w') as f:
            json.dump(time_intervals, f, indent=4, ensure_ascii=False)

        with open(outpath / 'fw_rules.json', 'w') as f:
            json.dump(fw_rules, f, indent=4, ensure_ascii=False)

        with open(outpath / 'nat_rules.json', 'w') as f:
            json.dump(nat_rules, f, indent=4, ensure_ascii=False)

    # Заполнение объектов в правилах фильтрации
    for rule in fw_rules:
        src = []
        dst = []
        for netobj in netobjects:
            for src_obj in rule['src']:
                type_obj, name_obj = src_obj
                if not type_obj == 'list_id':
                    continue

                if netobj.get('name') == name_obj:
                    src.append(copy.deepcopy(netobj))

            for dst_obj in rule['dst']:
                type_obj, name_obj = dst_obj
                if not type_obj == 'list_id':
                    continue

                if netobj.get('name') == name_obj:
                    dst.append(copy.deepcopy(netobj))

        rule['src'] = src
        rule['dst'] = dst

        service = []
        for srv in services:
            for srv_obj in rule['service']:
                type_obj, name_obj = srv_obj

                if srv.get('name') == name_obj:
                    service.append(copy.deepcopy(srv))

        rule['service'] = service

        intervals = []
        for interval in time_intervals:
            for name_obj in rule['params']:
                if interval.get('name') == name_obj:
                    intervals.append(copy.deepcopy(interval))

        rule['params'] = intervals

    # Заполнение объектов в правилах трансляции
    filled_nat_rules = []
    for rule in nat_rules:
        src = []
        dst = []
        for netobj in netobjects:
            for src_obj in rule['src']:
                type_obj, name_obj = src_obj
                if not type_obj == 'list_id':
                    continue

                if netobj.get('name') == name_obj:
                    src.append(copy.deepcopy(netobj))

            for dst_obj in rule['dst']:
                type_obj, name_obj = dst_obj
                if not type_obj == 'list_id':
                    continue

                if netobj.get('name') == name_obj:
                    dst.append(copy.deepcopy(netobj))

        rule['src'] = src
        rule['dst'] = dst

        if rule['nat_type'] == 'dnat':
            for dst_netobj in dst:
                if dst_netobj.get('type') == 'group':
                    log.warning(f"{rule.get('name')} - группа сетевых объектов в назначении правила DNAT не поддерживается")
                    error_counter['NatRules']['done'] -= 1
                    error_counter['NatRules']['warning'] += 1
                    continue

                dst_ip = dst_netobj.get('ip')
                if '-' in dst_ip:
                    log.warning(f"{rule.get('name')} - диапазон в назначении правила DNAT не поддерживается")
                    error_counter['NatRules']['done'] -= 1
                    error_counter['NatRules']['warning'] += 1
                    continue

        if rule['nat_type'] == 'static':
            if src == [] or rule.get('value', []) == []:
                log.warning(f"{rule.get('name')} - в правиле типа \"отобразить\" должны быть прописаны значения источника и транслированного пакета")
                error_counter['NatRules']['done'] -= 1
                error_counter['NatRules']['warning'] += 1
                continue

            for src_netobj in src:
                if src_netobj.get('type') == 'group':
                    log.warning(f"{rule.get('name')} - группа сетевых объектов в источнике правила \"отобразить\" не поддерживается")
                    error_counter['NatRules']['done'] -= 1
                    error_counter['NatRules']['warning'] += 1
                    continue

                src_ip = src_netobj.get('ip')
                if '-' in src_ip:
                    log.warning(f"{rule.get('name')} - диапазон в источнике правила \"отобразить\" не поддерживается")
                    error_counter['NatRules']['done'] -= 1
                    error_counter['NatRules']['warning'] += 1
                    continue

        # у правил nat только один сервис или отсутствует
        if len(rule['service']) > 0:
            first_service = rule['service'][0]
            if type(first_service) == list:
                for srv in services:
                    type_obj, name_obj = first_service
                    if srv.get('name') == name_obj:
                        found_service = copy.deepcopy(srv)

                        if found_service.get('type') == 'group':
                            log.warning(f"{rule.get('name')} - группа сервисов в правиле NAT не поддерживается")
                            error_counter['NatRules']['done'] -= 1
                            error_counter['NatRules']['warning'] += 1
                            break

                        if not found_service.get('proto') in transport_protocols.values():
                            log.warning(f"{rule.get('name')} - сервис в правиле NAT может быть только TCP или UDP ({found_service.get('proto')})")
                            error_counter['NatRules']['done'] -= 1
                            error_counter['NatRules']['warning'] += 1
                            break

                        rule['service'] = found_service
                        filled_nat_rules.append(rule)
        else:
            filled_nat_rules.append(rule)

    nat_rules = filled_nat_rules

    members_sections = ['members', 'value', 'port_value', 'src', 'dst', 'service', 'params']
    service_fields = [
        '__internal_type',
        'original_description'
    ]

    print_report(outpath, [*fw_rules, *nat_rules], [*section_dict], members_sections)
    description_check(fw_rules, members_sections)
    description_check(nat_rules, members_sections)

    # подсчёт элементов во всех секциях, содержащих объекты
    def obj_count(list_obj, members_sections, c):
        for obj in list_obj:
            if not type(obj) == dict:
                continue

            c += 1
            for section in members_sections:
                section_list = obj.get(section, [])
                if not type(section_list) == list:
                    continue

                c = obj_count(
                        section_list,
                        members_sections,
                        c
                    )

        return c

    # разбиение правил с отсечкой по 20к объектов и с ограничением по количеству правил
    def split_rules(rules):
        files_content = []
        object_count = 0
        rules_count = 0
        part_of_rules = []
        for rule in rules:
            object_count += 1
            if args.num_rule > 0:
                rules_count += 1

            objects_in_rule = 0
            for section in members_sections:
                section_list = rule.get(section, [])
                if not type(section_list) == list:
                    continue

                objects_in_rule = obj_count(
                        section_list,
                        members_sections,
                        objects_in_rule
                    )

            if object_count + objects_in_rule >= MAX_OBJECTS_BORDER or rules_count > args.num_rule:
                files_content.append(part_of_rules)
                part_of_rules = [rule]
                object_count = objects_in_rule
                rules_count -= args.num_rule
            else:
                object_count += objects_in_rule
                part_of_rules.append(rule)

        if len(part_of_rules) > 0:
            files_content.append(part_of_rules)

        return files_content

    nat_files = split_rules(nat_rules)
    del nat_rules

    fw_files = split_rules(fw_rules)
    del fw_rules

    def write_output_rules(files_content, file_prefix, file_postfix):
        def collect_stats(objs, stats):
            for obj in objs:
                if not type(obj) == dict:
                    continue

                obj_type = obj.get('__internal_type')
                if not obj_type is None:
                    stats[obj_type] += 1

                for members_section in members_sections:
                    if not members_section in obj.keys():
                        continue

                    if not type(obj[members_section]) == list:
                        continue

                    collect_stats(obj[members_section], stats)

        if len(files_content) > 0:
            i = 1
            for file_content in files_content:
                filename = outpath / OUTPUT_FILENAME.format(
                    file_prefix,
                    pathlib.Path(args.input).stem,
                    f"{file_postfix}{i if i > 1 else ''}")

                stats = {}
                for section in section_dict.keys():
                    stats[section] = 0

                collect_stats(file_content, stats)
                log.info(f"Файл: {filename}")
                log.info("\tВ промежуточном файле:")
                for section in section_dict.keys():
                    log.info(f"\t\t{section_dict[section]}: {stats[section]}")

                if not log.root.level == logging.DEBUG:
                    remove_fields(file_content, service_fields, members_sections)

                write_outfile(file_content, filename)
                i += 1

    def write_outfile(data, filename):
        if filename.exists():
            log.info("Выходной файл найден, перезапись")

        with open(filename, "w", encoding="utf8") as f:
            json.dump(data, f, indent=4, ensure_ascii=False)

        log.info(f"Записан файл: {filename}")

    prefix = args.name if args.name else 'import'
    write_output_rules(fw_files, prefix, 'fw')
    write_output_rules(nat_files, prefix, 'nat')
    print_stats()


if __name__ == '__main__':
    main()