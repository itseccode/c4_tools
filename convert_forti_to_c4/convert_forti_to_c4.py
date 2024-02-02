#!/usr/bin/env python3
import json
from os.path import basename
import sys
import argparse
import logging
import pathlib
import copy

OUTPUT_FILENAME = "{}-{}{}.json"
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
    'NatRules': 'Правила трансляции',
    'vip': 'vip объекты',
    'vipGroups': 'Группы vip объектов',
}
members_types = {
    'src': ['netobject'],
    'dst': ['netobject'],
    'service': ['service'],
    'value': ['netobject'],
    'port_value': ['service'],
    'params': ['timeinterval']
}
stats_header_dict = {
    'done': 'Извлечено успешно:',
    'warning': 'Извлечено с предупреждениями:',
    'error': 'Извлечено с ошибками:',
    'output': 'Записано всего:'
}
day_dict = {
    'sunday': 0,
    'monday': 1,
    'tuesday': 2,
    'wednesday': 3,
    'thursday': 4,
    'friday': 5,
    'saturday': 6
}
type_proto_dict = {
    'tcp': 6,
    'udp': 17,
    'icmp': 1,
    'icmpv6': 58,
    'tcp_citrix': 6,
    'sctp': 132,
    'gtp_v0': 17,
    'gtp_mm_v0': 17,
    'gtp_v1': 17,
    'gtp_mm_v1': 17,
    'gtp_v2': 17,
    'gtp_mm_v2': 17,
    'tcp_subservice': 6
}
section_type_dict = {
    'firewall vip': 'vip',
    'firewall vipgrp': 'vipGroups',
    'firewall address': 'NetObjects',
    'firewall multicast-address': 'NetObjects',
    'firewall addrgrp': 'NetObjectGroups',

    'firewall service custom': 'Services',
    'firewall service group': 'ServiceGroups',

    'firewall schedule recurring': 'TimeIntervals',
# 'firewall schedule group': ''
}
vip_postfixes = {
    'extip': '_vip_extip',
    'mappedip': '_vip_mapip',
    'extport': '_vip_extport',
    'mappedport': '_vip_mapport'
}

icmp_available = {
    3: [0, 1, 2, 3, 4, 5, 6,
        7, 8, 9, 10, 11, 12,
        13, 14, 15],
    5: [0, 1, 2, 3],
    6: [0],
    9: [0, 16],
    11: [0, 1],
    12: [0, 1, 2],
    40: [0, 1, 2, 3, 4, 5],
    42: [0],
    43: [0, 1, 2, 3, 4]
}


def icmp_validate(icmp_type, icmp_code):
    if icmp_type is None or icmp_code is None:
        return True

    if icmp_type in icmp_available.keys():
        if icmp_code in icmp_available[icmp_type]:
            return True

    return False


def get_netmask(netmask):
    return sum(bin(int(x)).count('1') for x in netmask.split('.'))


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


# Проверка описания на длину
def description_check(objs, members_sections):
    if not objs:
        return

    def check(object):
        if not type(object) == dict:
            return

        description = object.get('description')
        if description:
            if len(description) > MAX_DESCR_LEN:
                # log.warning('Слишком длинное описание!')
                section = object['__internal_type']
                error_counter[section]['warning'] += 1
                object['description'] = description[:MAX_DESCR_LEN]

        for members_section in members_sections:
            if members_section in object.keys():
                description_check(object[members_section], members_sections)

    if not type(objs) == list:
        check(objs)
    else:
        for object in objs:
            check(object)


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
                if members_section in object.keys():
                    index = walk(object[members_section], section, index, report_file)

        return index

    def write_object(obj, report_file, index):
        report_file.write(f"{index}. Имя: {obj['name']}\n")
        report_file.write(f"Оригинальное имя: {obj['original_name']}\n")
        report_file.write(f"Оригинальное описание: {obj['original_description']}\n")
        report_file.write("\n")

    with open(filename, "w", encoding="utf8") as report_file:
        report_file.write("Система-источник: FortiGate\n")
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
    else:
        out_list.append(added_object)
    return out_list


def get_minutes(time_str):
    colon_index = time_str.find(':')
    if colon_index >= 0:
        hours = time_str[:colon_index]
        mins = time_str[colon_index + 1:]
        return int(hours) * 60 + int(mins)
    else:
        return int(time_str)


def print_stats():
    for header in stats_header_dict.keys():
        log.info('')
        log.info(stats_header_dict[header])
        for section in error_counter.keys():
            log.info(f'\t{section_dict[section]}: {error_counter[section][header]}')


def read_forti(f):
    data = {}
    long_string = False
    long_key = None
    for line in f:
        clear_line = line.strip()
        if clear_line.startswith('#'):
            continue

        if line.count('"') % 2 > 0:
            long_string = not long_string
            if not long_string:
                data[long_key] = clear_line
                long_key = None
                continue

        if long_string and not long_key is None:
            data[long_key] = clear_line
            continue

        if clear_line.startswith('config') or clear_line.startswith('edit'):
            header = clear_line[clear_line.find(' ') + 1:]
            header = header.replace('"', '')
            data[header] = read_forti(f)
            continue

        if clear_line.startswith('next') or clear_line.startswith('end'):
            return data

        if clear_line.startswith('set'):
            command = clear_line[clear_line.find(' ') + 1:]
            cmd_space = command.find(' ')
            variable = command[:cmd_space]
            value = command[cmd_space + 1:]
            if long_string:
                long_key = variable

            if value[0] == '"':
                value = value[1:]
            if value[-1] == '"':
                value = value[:-1]

            if value.find('" "') > 0:
                value = value.split('" "')
                data[variable] = value
            else:
                data[variable] = value.replace(r'\"', '"').replace(r"\'", "'")
            continue

        if clear_line.startswith('unset'):
            data[clear_line] = ''
            continue

        log.debug(f"Не распознано! - {line}")

    return data


def parse_rules(data, vip_names, objects, ippools):
    rules = []
    for key in data.keys():
        rule_object = data[key]
        name = rule_object.get('name', '')
        description = rule_object['comment'] if 'comment' in rule_object.keys() else rule_object.get('comments', '')
        action = rule_object.get('action', '')
        fw_rule = {
            'name': name,
            'original_name': name,
            'description': description,
            'original_description': description,
            'is_enabled': False,
            '__internal_type': 'FilterRules',
            'rule_action': 'pass' if action == 'accept' else 'block',
            'src': [],
            'dst': [],
            'service': [],
            'params': [],
            'install_on': [],
            'passips': False,
            'rule_applications': [],
            'is_inverse_src': False,
            'is_inverse_dst': False,
            'logging': True
        }
        if rule_object.get('learning-mode', '') == 'enable':
            fw_rule['rule_action'] = 'pass'

        if rule_object.get('logtraffic', '') == 'disable':
            fw_rule['logging'] = False

        fields_dict = {
            'srcaddr': 'src',
            'dstaddr': 'dst',
            'schedule': 'params',
            'service': 'service'
        }

        for nested_key in fields_dict.keys():
            if nested_key in rule_object.keys():
                original_value = rule_object[nested_key]
                k4_field = fields_dict[nested_key]
                if type(original_value) == str and \
                    original_value.lower() in ['all', 'always']:
                    continue

                if type(original_value) == str:
                    original_value = [original_value]

                for obj_name in original_value:
                    for obj in objects:
                        if not obj['type'] in members_types[k4_field]:
                            continue

                        if k4_field == 'service' and obj['original_name'] == obj_name:
                            fw_rule[k4_field].append(obj)
                            continue

                        # netobjects
                        if not(obj['name'] in [obj_name, f"{obj_name}{vip_postfixes['extip']}"]):
                            continue

                        fw_rule[k4_field].append(obj)
        error_counter[fw_rule['__internal_type']]['done'] += 1
        rules.append(fw_rule)

        # NAT rules
        nat_enabled = rule_object.get('nat', '') == 'enable'
        ip_pool = rule_object.get('ippool', '') == 'enable'

        src_list = [None] if fw_rule['src'] == [] else fw_rule['src']
        dst_list = [None] if fw_rule['dst'] == [] else fw_rule['dst']
        for dst in dst_list:
            vip = not dst is None and dst['original_name'] in vip_names
            if not (nat_enabled or vip):
                continue

            for src in src_list:
                nat_rule = {
                    'name': name,
                    'original_name': name,
                    'description': description,
                    'original_description': description,
                    'is_enabled': False,
                    '__internal_type': 'NatRules',
                    'src': [],
                    'dst': [],
                    'service': fw_rule['service'],
                    'install_on': [],
                    'port_value': [],
                    'port_type': [],
                    'value': [],
                    'address_type': [],
                    'interface': None
                }

                if not src is None:
                    nat_rule['src'] = [src]

                if not dst is None:
                    nat_rule['dst'] = [dst]

                if vip:
                    nat_rule['nat_type'] = 'dnat'
                    vip_dict = {
                        'dst': f"{dst['original_name']}{vip_postfixes['extip']}",
                        'service': f"{dst['original_name']}{vip_postfixes['extport']}",
                        'value': f"{dst['original_name']}{vip_postfixes['mappedip']}",
                        'port_value': f"{dst['original_name']}{vip_postfixes['mappedport']}"
                    }

                    for field in vip_dict.keys():
                        for obj in objects:
                            if obj['name'] == vip_dict[field]:
                                nat_rule[field] = [obj]
                                break

                    if len(nat_rule['port_value']) > 0 and \
                        type(nat_rule['port_value'][0]) is dict and \
                        not nat_rule['port_value'][0].get('__port_forward'):
                            nat_rule['service'] = fw_rule['service']
                            nat_rule['port_value'] = []

                elif ip_pool:
                    nat_rule['nat_type'] = 'dynamic'
                    for obj in ippools:
                        if obj['original_name'] == rule_object['poolname']:
                            nat_rule['value'] = [obj]
                            nat_rule['address_type'] = 'netobject'
                            if obj.get('__one-to-one'):
                                nat_rule['nat_type'] = 'static'
                            break
                else:
                    nat_rule['nat_type'] = 'masquerade'

                if not nat_rule['port_value'] == []:
                    nat_rule['port_type'] = 'service'

                if not nat_rule['value'] == []:
                    nat_rule['address_type'] = 'netobject'

                # сервисы могут быть только TCP или UDP
                TCP_UDP_service = True
                for services in ['port_value', 'service']:
                    for service in nat_rule[services]:
                        if 'proto' in service.keys():
                            if not service['proto'] in [ type_proto_dict['tcp'],
                                                        type_proto_dict['udp'] ]:
                                error_counter[nat_rule['__internal_type']]['error'] += 1
                                TCP_UDP_service = False
                                break

                if not TCP_UDP_service:
                    continue

                error_counter[nat_rule['__internal_type']]['done'] += 1
                rules.append(nat_rule)
    return rules


def parse_objects(input_objects):
    vip_obj = []
    sections_dictionary = {
        'NetObjects': process_NetObjects,
        'NetObjectGroups': process_NetObjectGroups,
        'Services': process_Services,
        'ServiceGroups': process_ServiceGroups,
        'TimeIntervals': process_TimeIntervals,
        'vip': process_vip,
        'vipGroups': process_vipGroups
    }

    parsed_objects = []
    for section in section_type_dict.keys():
        input_section = input_objects.get(section, {})
        for original_name in input_section.keys():
            if original_name.lower() == 'all':
                continue

            original_dict = input_section[original_name]
            internal_type = section_type_dict[section]
            description = original_dict['comment'] if 'comment' in original_dict.keys() else original_dict.get('comments', '')

            obj = {
                'name': original_name,
                'original_name': original_name,
                'description': description,
                'original_description': description,
                '__internal_type': internal_type
            }

            parse_fun = sections_dictionary[internal_type]
            parsed_obj = parse_fun(original_dict, obj)
            if not parsed_obj is None:
                add_to_list(parsed_objects, parsed_obj)
                error_counter[internal_type]['done'] += 1
            else:
                error_counter[internal_type]['warning'] += 1
                log.warning(f"Объект некорректный: {original_dict}")

            if internal_type in ['vip', 'vipGroups']:
                vip_obj.append(original_name)

    # Добавление объектов в группы
    for group in parsed_objects:
        if group['type'] == 'group':
            if not 'members' in group.keys():
                continue

            filled_section = []
            for object_name in group['members']:
                for obj in parsed_objects:
                    if obj['original_name'] == object_name and obj['type'] == group['subtype']:
                        added_object = copy.deepcopy(obj)
                        filled_section.append(added_object)
            group['members'] = filled_section

    return parsed_objects, vip_obj


def process_NetObjects(original_dict, obj):
    obj['type'] = 'netobject'

    # subnet - network
    if 'subnet' in original_dict.keys():
        subnet = original_dict['subnet'].split()
        obj['ip'] = f"{subnet[0]}/{get_netmask(subnet[1])}"

    # range
    if 'start-ip' in original_dict.keys():
        start = original_dict.get('start-ip')
        end = original_dict.get('end-ip')
        if start == end:
            obj['ip'] = f"{start}"
        else:
            obj['ip'] = f"{start}-{end}"

    if not 'ip' in obj.keys():
        return None

    return obj


def process_NetObjectGroups(original_dict, obj):
    obj['type'] = 'group'
    obj['subtype'] = 'netobject'
    obj['members'] = original_dict.get('member', [])
    return obj


def process_Services(original_dict, obj):
    obj['type'] = 'service'
    obj['requires_keep_connections'] = False
    out_objects = []
    if 'tcp-portrange' in original_dict.keys():
        tcp_service = copy.deepcopy(obj)
        tcp_service['name'] = f"{tcp_service['name']}_tcp"
        tcp_service['proto'] = 6
        ports = original_dict['tcp-portrange'].replace(' ', ',')

        if ports.find(':') >= 0:
            tcp_service['dst'] = ports.split(':')[0]
            tcp_service['src'] = ports.split(':')[1]
        else:
            tcp_service['dst'] = ports
            tcp_service['src'] = ''

        if tcp_service['src'].startswith('0'):
            tcp_service['src'] = f"1{tcp_service['src'][1:]}"

        if tcp_service['dst'].startswith('0'):
            tcp_service['dst'] = f"1{tcp_service['dst'][1:]}"

        out_objects.append(tcp_service)

    if 'udp-portrange' in original_dict.keys():
        udp_service = copy.deepcopy(obj)
        udp_service['name'] = f"{udp_service['name']}_udp"
        udp_service['proto'] = 17
        ports = original_dict['udp-portrange'].replace(' ', ',')

        if ports.find(':') >= 0:
            udp_service['dst'] = ports.split(':')[0]
            udp_service['src'] = ports.split(':')[1]
        else:
            udp_service['dst'] = ports
            udp_service['src'] = ''

        if udp_service['src'].startswith('0'):
            udp_service['src'] = f"1{udp_service['src'][1:]}"

        if udp_service['dst'].startswith('0'):
            udp_service['dst'] = f"1{udp_service['dst'][1:]}"

        out_objects.append(udp_service)

    if original_dict.get('protocol') == 'IP':
        obj['proto'] = int(original_dict.get('protocol-number'))
        if obj['proto'] in [0, 41, 43, 44, 45, 46, 50, 51, 58, 59, 60]:
            log.warning('В параметрах сервиса используется неподдерживаемый протокол')
            return None

        return obj

    if original_dict.get('protocol') == 'ICMP':
        obj['proto'] = 1
        obj['icmp_type'] = original_dict.get('icmptype', '99')
        obj['icmp_code'] = original_dict.get('icmpcode', None)
        if not icmp_validate(obj['icmp_type'], obj['icmp_code']):
            return None

        return obj

    return out_objects


def process_ServiceGroups(original_dict, obj):
    obj['type'] = 'group'
    obj['subtype'] = 'service'
    obj['members'] = original_dict.get('member', [])
    return obj


def process_TimeIntervals(original_dict, obj):
    obj['type'] = 'timeinterval'
    obj['intervals'] = []
    for day in original_dict.get('day', '').split(' '):
        if day in day_dict.keys():
            start = get_minutes(original_dict.get('start', '00:00'))
            finish = get_minutes(original_dict.get('end', '23:59'))
            obj['intervals'].append({
                'day': day_dict[day],
                'start': start,
                'finish': finish
            })
    return obj


def process_vip(original_dict, obj):
    out_objs = []
    proto = original_dict.get('protocol', 'tcp').lower()

    if not original_dict.get('extip') is None:
        extip = copy.deepcopy(obj)
        extip['__internal_type'] = 'NetObjects'
        extip['name'] = f"{extip['name']}{vip_postfixes['extip']}"
        extip['type'] = 'netobject'
        extip['ip'] = original_dict['extip']
        out_objs.append(extip)

    if not original_dict.get('mappedip') is None:
        mappedip = copy.deepcopy(obj)
        mappedip['__internal_type'] = 'NetObjects'
        mappedip['name'] = f"{mappedip['name']}{vip_postfixes['mappedip']}"
        mappedip['type'] = 'netobject'
        mappedip['ip'] = original_dict['mappedip']
        out_objs.append(mappedip)

    if not original_dict.get('extport') is None:
        extport = copy.deepcopy(obj)
        extport['__internal_type'] = 'Services'
        extport['requires_keep_connections'] = False
        extport['name'] = f"{extport['name']}{vip_postfixes['extport']}"
        extport['type'] = 'service'
        extport['proto'] = type_proto_dict.get(proto)
        if proto in ['tcp', 'udp', 'sctp']:
            ports = original_dict['extport']
            if ports.find(':') >= 0:
                extport['dst'] = ports.split(':')[0]
                extport['src'] = ports.split(':')[1]
            else:
                extport['dst'] = ports
                extport['src'] = ''

            if extport['src'].startswith('0'):
                extport['src'] = f"1{extport['src'][1:]}"

            if extport['dst'].startswith('0'):
                extport['dst'] = f"1{extport['dst'][1:]}"

        if proto == 'icmp':
            obj['icmp_type'] = '99'
            obj['icmp_code'] = None

        out_objs.append(extport)

    if not original_dict.get('mappedport') is None:
        mappedport = copy.deepcopy(obj)
        mappedport['__internal_type'] = 'Services'
        mappedport['requires_keep_connections'] = False
        mappedport['name'] = f"{mappedport['name']}{vip_postfixes['mappedport']}"
        mappedport['type'] = 'service'
        mappedport['__port_forward'] = original_dict.get('portforward', '') == 'enable'
        mappedport['proto'] = type_proto_dict.get(proto)
        if proto in ['tcp', 'udp', 'sctp']:
            ports = original_dict['mappedport']
            if ports.find(':') >= 0:
                mappedport['dst'] = ports.split(':')[0]
                mappedport['src'] = ports.split(':')[1]
            else:
                mappedport['dst'] = ports
                mappedport['src'] = ''

            if mappedport['src'].startswith('0'):
                mappedport['src'] = f"1{mappedport['src'][1:]}"

            if mappedport['dst'].startswith('0'):
                mappedport['dst'] = f"1{mappedport['dst'][1:]}"

        if proto == 'icmp':
            obj['icmp_type'] = '99'
            obj['icmp_code'] = None

        out_objs.append(mappedport)

    return out_objs


def process_vipGroups(original_dict, obj):
    obj['type'] = 'group'
    netobject_grp = copy.deepcopy(obj)
    netobject_grp['subtype'] = 'netobject'
    netobject_grp['__internal_type'] = 'NetObjectGroups'
    service_grp = copy.deepcopy(obj)
    service_grp['subtype'] = 'service'
    service_grp['__internal_type'] = 'ServiceGroups'

    netobject_grp['members'] = []
    service_grp['members'] = []
    for member in original_dict.get('member', []):
        netobject_grp['members'].append(f"{member}{vip_postfixes['extip']}")
        netobject_grp['members'].append(f"{member}{vip_postfixes['mappedip']}")
        service_grp['members'].append(f"{member}{vip_postfixes['extport']}")
        service_grp['members'].append(f"{member}{vip_postfixes['mappedport']}")

    return [netobject_grp, service_grp]


def parse_ippool(input_objects):
    parsed_objects = []
    input_section = input_objects.get('firewall ippool', {})
    for original_name in input_section.keys():
        if original_name.lower() == 'all':
            continue

        original_dict = input_section[original_name]
        description = original_dict['comment'] if 'comment' in original_dict.keys() else original_dict.get('comments', '')

        obj = {
            'name': original_name,
            'original_name': original_name,
            'description': description,
            'original_description': description,
            'type': 'netobject',
            '__internal_type': 'NetObjects'
        }

        if 'startip' in original_dict.keys():
            obj['name'] = f"{obj['name']}_ippool"
            obj['__one-to-one'] = original_dict.get('type') == 'one-to-one'
            start = original_dict.get('startip')
            end = original_dict.get('endip')
            if start == end:
                obj['ip'] = f"{start}"
            else:
                obj['ip'] = f"{start}-{end}"

        if 'source-startip' in original_dict.keys():
            obj['name'] = f"{obj['name']}_ippool"
            obj['__one-to-one'] = original_dict.get('type', False)
            start = original_dict.get('source-startip')
            end = original_dict.get('source-endip')
            if start == end:
                obj['ip'] = f"{start}"
            else:
                obj['ip'] = f"{start}-{end}"

        parsed_objects.append(obj)
    return parsed_objects


def main():
    parser = argparse.ArgumentParser(
                formatter_class = argparse.RawTextHelpFormatter,
                prog = f"\n\npython {basename(sys.argv[0])}",
                description = 'Преобразование конфигурации FortiGate в Континент 4.',
                epilog = f'''example: python {basename(sys.argv[0])} -i fortigate.conf -o output_folder_path
                ''',
                add_help = False
            )
    parser.add_argument('-h', '--help', action='help', default=argparse.SUPPRESS, help='Показать текущее сообщение помощи и выйти.')
    parser.add_argument('-i', '--input', help='Пути до файла конфигурации для преобразования', type=str, required=True)
    parser.add_argument('-o', '--output_path', help='Путь до папки для выходного файла', type=pathlib.Path)
    parser.add_argument('--log_file', help='Имя файла логирования', type=str)
    parser.add_argument('--name', help='Префикс имени выходного файла', type=str)
    args = parser.parse_args(args=None if sys.argv[1:] else ['--help'])

    # Настройка вывода логов в файл
    if args.log_file:
        fh = logging.FileHandler(args.log_file)
        formatter = logging.Formatter('%(asctime)s %(levelname)-8s %(message)s')
        fh.setFormatter(formatter)
        log.addHandler(fh)

    # Инициализация структуры данных для отчёта
    for section in section_dict.keys():
        error_counter[section] = {}
        for severity in stats_header_dict.keys():
            error_counter[section][severity] = 0

    # Парсинг
    input_objects = {}
    log.info(f'Загрузка {args.input}')
    with open(args.input, 'r', encoding="utf8") as f:
        input_objects = read_forti(f)

    log.info(f'Загрузка завершена')

    if 'vdom' in input_objects.keys() and 'root' in input_objects.get('vdom', {}).keys():
        input_objects = input_objects['vdom']['root']

    firewall_policy = input_objects.get('firewall policy', {})
    objects, vip_names = parse_objects(input_objects)
    ippools = parse_ippool(input_objects)
    rules = parse_rules(firewall_policy, vip_names, objects, ippools)

    log.debug(f"VIP - {vip_names}")

    # Сохранение промежуточного представления для отладки
    if log.root.level <= logging.DEBUG:
        with open('debug.json', 'w') as f:
            json.dump(input_objects, f, indent=4, ensure_ascii=False)

        with open('objects.json', 'w') as f:
            json.dump(objects, f, indent=4, ensure_ascii=False)

    members_sections = [*members_types]
    members_sections.extend(['members', 'value', 'port_value'])
    path = make_outpath(args.output_path)

    print_report(path, rules, [*section_dict], members_sections)
    description_check(rules, members_sections)

    service_fields = [
        '__internal_type',
        'id',
        'original_name',
        'original_description',
        '__port_forward',
        '__one-to-one'
    ]

    def write_output_rules(files_content, file_prefix):
        def collect_stats(objs, stats):
            for obj in objs:
                if not type(obj) == dict:
                    continue

                obj_type = obj.get('__internal_type')
                if not obj_type is None:
                    stats[obj_type] += 1

                for members_section in members_sections:
                    if members_section in obj.keys():
                        collect_stats(obj[members_section], stats)

        if len(files_content) > 0:
            i = 1
            for file_content in files_content:
                filename = path / OUTPUT_FILENAME.format(
                    file_prefix,
                    pathlib.Path(args.input).stem,
                    f"{i if i > 1 else ''}")

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
    write_output_rules([rules], prefix)
    print_stats()

if __name__ == '__main__':
    main()