#!/usr/bin/env python3
import json
from os.path import basename, commonpath
import sys
import argparse
import logging
import pathlib
import copy
import re

OUTPUT_FILENAME = "{}-{}{}.json"
MAX_DESCR_LEN = 1024
MAX_OBJECTS_BORDER = 20000
IP_REGEX = r"^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}$"

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
members_types = {
    'src': ['netobject'],
    'dst': ['netobject'],
    'service': ['service'],
    'src_translated': ['netobject'],
    'dst_translated': ['netobject'],
    'port_value': ['service'],
    'params': ['timeinterval']
}
stats_header_dict = {
    'done': 'Успешно:',
    'warning': 'С предупреждениями:',
    'error': 'С ошибками:',
    'output': 'Итого:'
}
objects_type_dict = {
    'network': 'NetObjects',
    'service': 'Services',
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
transport_protocols = {
    'tcp': 6,
    'udp': 17,
    'sctp': 132
}

ports_names = {'ip': '0', 'icmp': '1', 'igmp': '2', 'ggp': '3', 'ipinip': '4', 'tcp': '6', 'echo': '7', 'egp': '8', 'igrp': '9', 'discard': '9', 'daytime': '13', 'udp': '17', 'chargen': '19', 'ftp-data': '20', 'ftp': '21', 'ssh': '22', 'telnet': '23', 'smtp': '25', 'time': '37', 'nameserver': '42', 'whois': '43', 'gre': '47', 'tacacs': '49', 'esp': '50', 'ah': '51', 'domain': '53', 'skip': '57', 'icmp6': '58', 'bootps': '67', 'bootpc': '68', 'tftp': '69', 'gopher': '70', 'finger': '79', 'http': '80', 'www': '80', 'eigrp': '88', 'ospf': '89', 'nos': '94', 'hostname': '101', 'pim': '103', 'pcp': '108', 'snp': '109', 'pop2': '109', 'pop3': '110', 'sunrpc': '111', 'vrrp': '112', 'ident': '113', 'nntp': '119', 'ntp': '123', 'netbios-ns': '137', 'netbios-dgm': '138', 'netbios-ssn': '139', 'imap4': '143', 'snmp': '161', 'snmptrap': '162', 'xdmcp': '177', 'bgp': '179', 'irc': '194', 'dnsix': '195', 'ldap': '389', 'mobile-ip': '434', 'https': '443', 'pim-auto-rp': '496', 'isakmp': '500', 'exec': '512', 'biff': '512', 'login': '513', 'who': '513', 'rsh': '514', 'syslog': '514', 'lpd': '515', 'talk': '517', 'rip': '520', 'uucp': '540', 'klogin': '543', 'kshell': '544', 'rtsp': '554', 'ldaps': '636', 'kerberos': '750', 'lotusnotes': '1352', 'citrix-ica': '1494', 'sqlnet': '1521', 'radius': '1645', 'radius-acct': '1646', 'h323': '1720', 'pptp': '1723', 'nfs': '2049', 'ctiqbe': '2748', 'cifs': '3020', 'sip': '5060', 'aol': '5190', 'secureid-udp': '5510', 'pcanywhere-data': '5631', 'pcanywhere-status': '5632'}
icmp_type_names = {
    'echo-reply': 0,
    'unreachable': 3,
    'source-quench': 4,
    'redirect': 5,
    'echo': 8,
    'time-exceeded': 11,
    'parameter-problem': 12,
    'timestamp-request': 13,
    'timestamp-reply': 14,
    'information-request': 15,
    'information-reply': 16,
    'mask-request': 17,
    'mask-reply': 18
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


def get_first(obj):
    if type(obj) is dict and not obj is {}:
        return next(iter(obj.values()))

    if type(obj) is list and len(obj) > 0:
        return obj[0]

    return None


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
        log.info(stats_header_dict[header])
        for section in error_counter.keys():
            log.info(f'\t{section_dict[section]}: {error_counter[section][header]}')


def read_cisco(f, i=0):
    def append_to_root(root, key, obj):
        if key in root.keys():
            # str to list
            if type(root[key]) is str:
                root[key] = [root[key]]

            if type(root[key]) is dict:
                root[key][obj] = {}
            else:
                root[key].append(obj)
        else:
            # str
            root[key] = obj

    data = {}
    line = f.readline()
    while line:
        clear_line = line.strip()
        if clear_line.startswith(':') or clear_line.startswith('!') or line == '\n':
            line = f.readline()
            continue

        words = clear_line.split()
        first_word = words[0]
        key = ' '.join(words[1:])

        position = f.tell()
        next_line = f.readline()
        f.seek(position)

        white_index = 0
        while next_line[white_index] == ' ': white_index += 1

        # Есть вложенные свойства
        if white_index > i:
            obj = read_cisco(f, white_index)
            if not first_word in data.keys():
                data[first_word] = {}

            # str to dict
            if type(data[first_word]) is str:
                data[first_word] = {data[first_word]: {}}

            # str list to dict
            if type(data[first_word]) is list:
                new_dict = {}
                for it in data[first_word]:
                    new_dict[it] = {}
                data[first_word] = new_dict

            if key == "" and data[first_word] == {}:
                data[first_word] = obj
            elif key in data[first_word].keys():
                data[first_word][key].update(obj)
            else:
                data[first_word][key] = obj

            line = f.readline()
            continue

        append_to_root(data, first_word, key)

        if white_index < i:
            return data

        line = f.readline()

    return data


def get_cisco_port(port_line):
    operator = port_line[0]
    port = port_line[1]

    if not port.isdigit():
        port = ports_names.get(port)

    if operator == 'gt':
        port = f"{port}-65535"
    elif operator == 'lt':
        port = f"1-{port}"
    elif operator == 'all':
        port = "1-65535"
    elif operator == 'range':
        finish_port = port_line[2]
        if not finish_port.isdigit():
            finish_port = ports_names.get(finish_port)

        port = f"{port}-{finish_port}"
    return port


def in_and_full(container, key):
    if container == None or container == [] or container == {}:
        return False

    if type(container) == dict:
        if key not in container.keys():
            return False

        obj = container[key]
        if obj == None or obj == [] or obj == {}:
            return False

    return True


def flat_ip(obj):
    ips = []
    if type(obj) == list:
        for member in obj:
            ips.extend(flat_ip(member))

    if type(obj) == dict:
        if 'ip' in obj.keys():
            ips.append(obj['ip'])

        if 'members' in obj.keys():
            for member in obj['members']:
                ips.extend(flat_ip(member))

    return ips


def parse_objects(input_objects):
    parsed_objects = []
    proto_group = {}
    objects_dictionary = {
        'NetObjects': process_NetObjects,
        'Services': process_Services
    }
    groups_dictionary = {
        'NetObjects': process_NetObjectGroups,
        'Services': process_ServiceGroups,
    }

    hostnames = []
    name_list = input_objects.get('name', {})
    for host_line in name_list:
        obj = {}
        host = host_line.split()
        obj['ip'] = host[0]
        obj['name'] = host[1]
        if len(host) > 2 and host[2] == 'description':
            obj['description'] = ' '.join(host[2:])
        hostnames.append(obj)

    def parse(objects, parsed_objects, funcs_dictionary, hostnames):
        for object_line in objects.keys():
            original_name = object_line[object_line.find(' ') + 1:]
            original_type = object_line[:object_line.find(' ')]

            k4_type = objects_type_dict.get(original_type)
            if k4_type is None:
                continue

            original_obj = objects[object_line]
            if original_obj == {}:
                continue

            description = original_obj.get('description', '')

            obj = {
                'name': original_name,
                'original_name': original_name,
                'description': description,
                'original_description': description,
                '__internal_type': k4_type
            }

            parse_fun = funcs_dictionary[k4_type]
            parsed_obj = parse_fun(original_obj, obj, hostnames)

            if parsed_obj is None:
                error_counter[k4_type]['warning'] += 1
                log.warning(f"Объект некорректный: {original_obj}")
                continue

            error_counter[k4_type]['done'] += 1
            add_to_list(parsed_objects, parsed_obj)

    objects = input_objects.get('object', {})
    parse(objects, parsed_objects, objects_dictionary, hostnames)

    objects = input_objects.get('object-group', {})
    parse(objects, parsed_objects, groups_dictionary, hostnames)

    # for proto_group
    objects = input_objects.get('object-group', {})
    for object_line in objects.keys():
        original_name = object_line[object_line.find(' ') + 1:]
        original_type = object_line[:object_line.find(' ')]
        if original_type == 'protocol':
            protocols = objects[object_line].get('protocol-object', [])
            if type(protocols) == str:
                protocols = [protocols]
            proto_group[original_name] = protocols

    # adding missing hostnames
    for hostname in hostnames:
        found = False
        for obj in parsed_objects:
            if not obj.get('type') == 'netobject':
                continue

            if obj['name'] == hostname['name']:
                found = True
                break

        if not found:
            parsed_objects.append(
                create_netobject(name = hostname['name'], ip = hostname['ip'])
            )

    return parsed_objects, proto_group


def process_NetObjects(original_obj, obj, hostnames):
    obj['type'] = 'netobject'

    if 'host' in original_obj.keys():
        obj['ip'] = original_obj['host']

    if 'range' in original_obj.keys():
        obj['ip'] = original_obj['range'].replace(' ', '-')

    if 'subnet' in original_obj.keys():
        subnet = original_obj['subnet'].split()
        obj['ip'] = f"{subnet[0]}/{get_netmask(subnet[1])}"

    if not 'ip' in obj.keys():
        return None

    if 'nat' in original_obj.keys():
        nat_line = original_obj['nat'].split()
        nat_type = 'dynamic'
        service = []
        port_value = []
        value = []

        if nat_line[2] == 'interface':
            nat_type = 'masquerade'
        elif re.match(IP_REGEX, nat_line[2]):
            value = [create_netobject(name=nat_line[2], ip=nat_line[2])]
        else:
            value = [nat_line[2]]

        # service
        if len(nat_line) > 3:
            proto = nat_line[4]

            real_port = nat_line[5]
            if not real_port.isdigit():
                real_port = ports_names.get(real_port)

            mapped_port = nat_line[6]
            if not mapped_port.isdigit():
                mapped_port = ports_names.get(mapped_port)

            if proto in ['tcp', 'udp']:
                service = [{
                    'name': f"{obj['name']}_{proto}_{real_port}",
                    'original_name': f"{obj['name']}_{proto}_{real_port}",
                    'description': '',
                    'original_description': '',
                    '__internal_type': 'Services',
                    'requires_keep_connections': False,
                    'type': 'service',
                    'proto': transport_protocols.get(proto),
                    'dst': real_port,
                    'src': ''
                }]
                port_value = [{
                    'name': f"{obj['name']}_{proto}_{mapped_port}",
                    'original_name': f"{obj['name']}_{proto}_{mapped_port}",
                    'description': '',
                    'original_description': '',
                    '__internal_type': 'Services',
                    'requires_keep_connections': False,
                    'type': 'service',
                    'proto': transport_protocols.get(proto),
                    'dst': mapped_port,
                    'src': ''
                }]

        rule = create_nat_rule(name=f"{obj['name']}_NAT", nat_type=nat_type, src=[obj], service=service, port_value=port_value, value=value)

        unidirectional = 'unidirectional' in nat_line
        static = nat_line[1] == 'static'
        if static and not unidirectional:
            mirror_rule = create_nat_rule(name = f"{obj['name']}_NAT_mirror",
                                        description = f"Зеркальное правило для {obj['name']}",
                                        nat_type = 'dnat',
                                        dst = value,
                                        service = service if port_value == [] else port_value,
                                        port_value = [] if port_value == [] else service,
                                        value = [obj])
            return [obj, rule, mirror_rule]

        return [obj, rule]

    return obj


def process_NetObjectGroups(original_obj, obj, hostnames):
    obj['type'] = 'group'
    obj['subtype'] = 'netobject'

    obj['members'] = []
    groups = original_obj.get('group-object')
    if not groups is None:
        if type(groups) is str:
            obj['members'].append(groups)
        if type(groups) is list:
            obj['members'].extend(groups)

    members = original_obj.get('network-object')
    if not members is None:
        if type(members) is str:
            members = [members]

        for m in members:
            netobj_list = m.split()
            if netobj_list[0] in ['host', 'object']:
                name = m[m.find(' ') + 1:]
                if re.match(IP_REGEX, name):
                    obj['members'].append(
                        create_netobject(name=name, ip=name)
                    )
                    continue
                obj['members'].append(name)
                continue

            netmask = get_netmask(netobj_list[1])
            description = ''
            ip = ''
            if re.match(IP_REGEX, netobj_list[0]):
                name = netobj_list[0]
                ip = netobj_list[0]
                description = ''
            else:
                name = netobj_list[0]
                for host in hostnames:
                    if host['name'] == name:
                        ip = host['ip']
                        description = host.get('description', '')
                        break

            obj['members'].append(
                create_netobject(name=name, description=description, ip=f"{ip}/{netmask}")
            )

    return obj


def process_Services(original_obj, obj, hostnames):
    obj['type'] = 'service'
    obj['requires_keep_connections'] = False

    service_line = original_obj.get('service')
    if service_line is None:
        return None

    service_line = service_line.split()
    proto = service_line[0]

    if proto in ['tcp', 'udp', 'tcp-udp']:
        obj['dst'] = ''
        obj['src'] = ''
        i = 1
        for word in service_line[1:]:
            # word is direction
            if word in ['source', 'destination']:
                port = get_cisco_port(service_line[i + 1:])

                if word == 'source':
                    obj['src'] = port
                else:
                    obj['dst'] = port
            i += 1

        if proto == 'tcp-udp':
            obj['proto'] = transport_protocols['tcp']
            second_service = copy.deepcopy(obj)
            second_service['proto'] = transport_protocols['udp']
            return [obj, second_service]

        else:
            obj['proto'] = transport_protocols[proto]

    if proto == 'icmp':
        obj['proto'] = 1
        obj['icmp_type'] = None
        obj['icmp_code'] = None
        if len(service_line) > 1:
            obj['icmp_type'] = service_line[1]

        if len(service_line) > 2:
            obj['icmp_code'] = service_line[2]

        obj['icmp_type'] = icmp_type_names.get(obj['icmp_type'])
        if not icmp_validate(obj['icmp_type'], obj['icmp_code']):
            return None

    if proto.isdigit():
        obj['proto'] = proto

    return obj


def process_ServiceGroups(original_obj, obj, hostnames):
    obj['type'] = 'group'
    obj['subtype'] = 'service'

    obj['members'] = []
    groups = original_obj.get('group-object')
    if not groups is None:
        if type(groups) is str:
            obj['members'].append(groups)
        if type(groups) is list:
            obj['members'].extend(groups)

    name = obj['name']
    proto = name[name.rfind(' ') + 1:]
    name = name[:name.rfind(' ')]
    obj['name'] = name
    obj['original_name'] = name

    if 'service-object' in original_obj.keys():
        services = original_obj['service-object']
        if not services is None:
            if type(services) is str:
                ports = [services]

            for m in services:
                service_line = m.split()

                # "icmp",
                if len(service_line) == 1:
                    service = {
                        'name': f"{name}_{service_line[0]}",
                        'original_name': name,
                        'description': '',
                        'original_description': '',
                        'requires_keep_connections': False,
                        '__internal_type': 'Services',
                        'type': 'service',
                        'proto': ports_names.get(service_line[0])
                    }
                    obj['members'].append(service)
                    continue

                # "object https-8443",
                if service_line[0] == 'object':
                    obj['members'].append(service_line[1])
                    continue

                # "tcp destination eq www",
                service = {
                    'name': name,
                    'original_name': name,
                    'description': '',
                    'original_description': '',
                    '__internal_type': 'Services'
                }
                process_Services({'service': m}, service, [])
                obj['members'].append(service)

    # ports group
    if 'port-object' in original_obj.keys():
        if not proto in ['tcp', 'udp', 'tcp-udp']:
            return None

        if proto == 'tcp-udp':
            proto = ['tcp', 'udp']
        else:
            proto = [proto]

        ports = original_obj['port-object']
        if not ports is None:
            if type(ports) is str:
                ports = [ports]

            for m in ports:
                port_line = m.split()
                port = get_cisco_port(port_line)

                for protocol in proto:
                    service = {
                        'name': f"{name}_{protocol}_{port}",
                        'original_name': name,
                        'description': '',
                        'original_description': '',
                        'requires_keep_connections': False,
                        '__internal_type': 'Services',
                        'type': 'service',
                        'proto': transport_protocols.get(protocol),
                        'dst': port,
                        'src': ''
                    }
                    obj['members'].append(service)

    return obj


def parse_rules(input_objects, proto_group):
    parsed_rules = []
    original_fw_rules = input_objects.get('access-list', {})
    for original_rule in original_fw_rules:
        parsed_rule = parse_fw_rule(original_rule, proto_group)
        if not parsed_rule is None:
            add_to_list(parsed_rules, parsed_rule)
            error_counter['FilterRules']['done'] += 1
        else:
            error_counter['FilterRules']['warning'] += 1
            log.warning(f"Правило некорректное: {original_rule}")

    del original_fw_rules

    original_nat_rules = input_objects.get('nat', {})
    for original_rule in original_nat_rules:
        parsed_rule = parse_nat_rule(original_rule)
        if not parsed_rule is None:
            add_to_list(parsed_rules, parsed_rule)
            error_counter['NatRules']['done'] += 1
        else:
            error_counter['NatRules']['warning'] += 1
            log.warning(f"Правило некорректное: {original_rule}")

    return parsed_rules


def parse_fw_rule(original_rule, proto_group):
    rule_list = original_rule.split()
    if rule_list[1] in ['remark', 'standard']:
        return []
    if not rule_list[1] == 'extended':
        return None

    name = rule_list[0]
    action = rule_list[2]
    proto = ''
    port = ''
    src = []
    dst = []
    service = []

    second_netw_obj = False
    i = 0
    while i < len(rule_list):
        word = rule_list[i]

        # service proto
        if i == 3:
            if word == 'object-group':
                proto = proto_group.get(rule_list[i + 1], [])
                i += 2
                continue
            proto = word

        if word in ['host', 'object', 'object-group'] or re.match(IP_REGEX, word):
            netobj = []

            if re.match(IP_REGEX, word):
                netmask = get_netmask(rule_list[i + 1])
                netobj = create_netobject(name=f"{word}_{netmask}", ip=f"{word}/{netmask}")

            if word in ['object', 'object-group']:
                netobj = rule_list[i + 1]

            if word == 'host':
                netobj = create_netobject(name=rule_list[i + 1], ip=rule_list[i + 1])

            if second_netw_obj:
                dst = [netobj]
            else:
                src = [netobj]
                second_netw_obj = True

            i += 1

        if word == 'any' and not second_netw_obj:
            second_netw_obj = True

        # service port
        if word in ['gt', 'lt', 'range', 'eq', 'all']:
            port = get_cisco_port(rule_list[i:])

        i += 1

    if type(proto) == str: proto = [proto]

    for protocol in proto:
        if protocol in transport_protocols.keys():
            service.append({
                'name': f"{name}_{protocol}_{port}" if not port == '' else f"{name}_{protocol}",
                'original_name': f"{name}_{protocol}_{port}" if not port == '' else f"{name}_{protocol}",
                'description': '',
                'original_description': '',
                'requires_keep_connections': False,
                '__internal_type': 'Services',
                'type': 'service',
                'proto': transport_protocols[protocol],
                'dst': port,
                'src': ''
            })
        elif protocol == 'icmp':
            service.append({
                'name': f"{name}_{protocol}",
                'original_name': f"{name}_{protocol}",
                'description': '',
                'original_description': '',
                'requires_keep_connections': False,
                '__internal_type': 'Services',
                'type': 'service',
                'proto': 1,
                'icmp_type': None,
                'icmp_code': None
            })

    rule = {
        'name': name,
        'original_name': name,
        'description': '',
        'original_description': '',
        'is_enabled': False,
        '__internal_type': 'FilterRules',
        'src': src,
        'dst': dst,
        'service': service,
        'params': [],
        'install_on': [],
        'is_inverse_src': False,
        'is_inverse_dst': False,
        'passips': False,
        'rule_applications': [],
        'rule_action': 'pass' if action == 'permit' else 'block',
        'logging': False
    }
    return rule


def parse_nat_rule(original_rule):
    def check_any(obj):
        if obj in ['any', 'interface']:
            return []
        return [obj]

    rule_list = original_rule.split()
    description = ''
    src = []
    dst = []
    service = []
    translated_src = []
    translated_dst = []
    translated_service = []

    srcStatic = True
    dstStatic = True
    unidirectional = 'unidirectional' in rule_list

    i = -1
    for word in rule_list:
        i += 1
        if word == 'source':
            if rule_list[i + 1] == 'dynamic':
                srcStatic = False
            src = check_any(rule_list[i + 2])
            translated_src = check_any(rule_list[i + 3])
            if src == translated_src:
                translated_src = []
            continue

        if word == 'destination':
            if rule_list[i + 1] == 'dynamic':
                dstStatic = False
            dst = check_any(rule_list[i + 2])
            translated_dst = check_any(rule_list[i + 3])
            if dst == translated_dst:
                translated_dst = []
            continue

        if word == 'service':
            service = check_any(rule_list[i + 1])
            translated_service = check_any(rule_list[i + 2])
            if service == translated_service:
                translated_service = []
            continue

        if word == 'description':
            description = ' '.join(rule_list[i + 1:])
            break

    if srcStatic and not dstStatic:
        log.warning("Правило имеет static src и dynamic dst")
        return None

    rules = []
    if translated_src == [] and translated_dst == []:
        rules.append(
            create_nat_rule(
                name='',
                description=description,
                src=src,
                dst=dst,
                service=service,
                nat_type='masquerade'
            )
        )

    if translated_dst != []:
        rules.append(
            create_nat_rule(
                name='',
                description=description,
                src=src,
                dst=dst,
                service=service,
                value=translated_dst,
                port_value=translated_service,
                nat_type='dnat'
            )
        )

    if translated_src != []:
        rules.append(
            create_nat_rule(
                name='',
                description=description,
                src=src,
                dst=dst,
                service=service,
                value=translated_src,
                port_value=translated_service,
                nat_type='dynamic'
            )
        )

    # mirror rule
    if srcStatic and not unidirectional:
        if translated_src != [] and src != []:
            rules.append(
                create_nat_rule(
                    name = "mirror",
                    description = description,
                    src = dst if translated_dst == [] else translated_dst,
                    dst = src if translated_src == [] else translated_src,
                    service = service if translated_service == [] else translated_service,
                    port_value = [] if translated_service == [] else service,
                    value = src,
                    nat_type = 'dnat'
                )
            )
        if translated_dst != [] and dst != []:
            rules.append(
                create_nat_rule(
                    name = "mirror",
                    description = description,
                    src = dst if translated_dst == [] else translated_dst,
                    dst = src if translated_src == [] else translated_src,
                    service = service if translated_service == [] else translated_service,
                    port_value = [] if translated_service == [] else service,
                    value = dst,
                    nat_type = 'dynamic'
                )
            )

    return rules


def create_netobject(name = '', description = '', ip = ''):
    return {
        'name': name,
        'original_name': name,
        'description': description,
        'original_description': description,
        '__internal_type': 'NetObjects',
        'type': 'netobject',
        'ip': ip
    }


def create_nat_rule(name, nat_type, src = [], dst = [], service = [], port_value = [], value = [], description = ''):
    port_type = [] if port_value == [] else 'service'
    address_type = [] if value == [] else 'netobject'

    names = [nat_type]
    for s_obj in src:
        if type(s_obj) == dict:
            names.append(s_obj['name'])
        else:
            names.append(s_obj)

    for s_obj in dst:
        if type(s_obj) == dict:
            names.append(s_obj['name'])
        else:
            names.append(s_obj)

    if not name == '':
        names.append(name)

    if nat_type == 'dynamic':
        for v in port_value:
            v['dst'] = ''
    elif nat_type == 'dnat':
        for v in port_value:
            v['src'] = ''

    return {
        'name': '_'.join(names),
        'original_name': name,
        'description': description,
        'original_description': description,
        'is_enabled': False,
        '__internal_type': 'NatRules',
        'src': src,
        'dst': dst,
        'service': service,
        'port_value': port_value,
        'port_type': port_type,
        'value': value,
        'address_type': address_type,
        'interface': None,
        'install_on': [],
        'nat_type': nat_type
    }


def main():
    parser = argparse.ArgumentParser(
                formatter_class = argparse.RawTextHelpFormatter,
                prog = f"\n\npython {basename(sys.argv[0])}",
                description = 'Преобразование конфигурации Cisco ASA в Континент 4.',
                epilog = f'''example: python {basename(sys.argv[0])} -i config.txt -o output_folder_path
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
        input_objects = read_cisco(f)

    log.info(f'Загрузка завершена')

    # Сохранение промежуточного представления при отладке
    if log.root.level <= logging.DEBUG:
        with open('debug.json', 'w') as f:
            json.dump(input_objects, f, indent=4, ensure_ascii=False)

    objects, proto_group = parse_objects(input_objects)
    rules = parse_rules(input_objects, proto_group)

    nat_obj_rules = []
    for obj in objects:
        if obj.get('__internal_type') == 'NatRules':
            nat_obj_rules.append(obj)

    rules.extend(nat_obj_rules)
    del nat_obj_rules

    # Заполнение объектов в группах
    for obj in objects:
        if not obj.get('type') == 'group':
            continue

        members = []
        for member_name in obj.get('members', []):
            if type(member_name) is dict:
                members.append(member_name)
                continue

            for embedded_obj in objects:
                if member_name == embedded_obj.get('name') and obj.get('subtype') == embedded_obj.get('type'):
                    members.append(embedded_obj)

        obj['members'] = members

    # Добавление объектов в правила
    members_types = {
        'src': ['netobject'],
        'dst': ['netobject'],
        'service': ['service'],
        'value': ['netobject'],
        'port_value': ['service']
    }
    for rule in rules:
        for section in members_types.keys():
            if section in rule.keys():
                filled_section = []
                for object_id in rule[section]:
                    if type(object_id) == dict:
                        filled_section.append(copy.deepcopy(object_id))
                        continue

                    # цикл по объектам
                    for obj in objects:
                        type_match = obj.get('type') in members_types[section] or \
                            obj.get('subtype') in members_types[section]
                        if obj['name'] == object_id and type_match:
                            filled_section.append(copy.deepcopy(obj))

                # поиск возможных пропущенных объектов при отладке
                if log.root.level <= logging.DEBUG and len(rule[section]) != len(filled_section):
                    log.debug(f"{rule['name']}: {section}")
                    log.debug(f"\t{rule[section]}")
                rule[section] = filled_section

    clean_rules = []
    for rule in rules:
        if not rule['__internal_type'] == 'NatRules':
            clean_rules.append(rule)
            continue

        # Замена группы с одним сервисом на этот сервис в правилах NAT и отсеивание правил с остальными группами
        if len(rule['value']) == 1 and rule['value'][0]['type'] == 'group':
            group = rule['value'][0]
            if len(group['members']) == 1:
                rule['value'] = copy.deepcopy(group['members'])
            else:
                continue

        # Отсеивание правил с типом dnat, у которых translated destination - сеть или диапазон
        value = rule.get('value', [])
        if rule['nat_type'] == 'dnat' and len(value) > 0:
            ip  = value[0].get('ip')
            if '/' in ip or '-' in ip:
                continue

        clean_rules.append(rule)

    rules = clean_rules
    del clean_rules

    # Сохранение промежуточного представления при отладке
    if log.root.level <= logging.DEBUG:
        with open('rules.json', 'w') as f:
            json.dump(rules, f, indent=4, ensure_ascii=False)

        with open('objects.json', 'w') as f:
            json.dump(objects, f, indent=4, ensure_ascii=False)

    members_sections = [*members_types]
    members_sections.extend(['members', 'value', 'port_value'])
    path = make_outpath(args.output_path)

    print_report(path, rules, [*section_dict], members_sections)
    description_check(rules, members_sections)

    service_fields = [
        '__internal_type',
        'original_name',
        'original_description'
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