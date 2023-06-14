#!/usr/bin/env python3
import json
from os.path import exists, basename
import sys
import argparse
import logging
import pathlib
import copy

OUTPUT_FILENAME = "import-{}-{}-ver01.json"
DEFAULT_MIN_PORT = 0
DEFAULT_MAX_PORT = 65535
MAX_DESCR_LEN = 1024

logging.basicConfig(encoding='utf-8', level=logging.INFO,
    format='%(asctime)s %(levelname)-8s %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
log = logging.getLogger(__name__)

rule_types_dict = {'rule': 'FilterRules', 'rule_adtr': 'NatRules'}
types_dict = {'services': 'Services', 'network_objects': 'NetObjects', 'times': 'TimeIntervals'}
groups_dict = {'services': 'ServiceGroups', 'network_objects': 'NetObjectGroups'}

error_counter = {}
section_dict = {
    'NetObjects': 'Сетевые объекты',
    'NetObjectGroups': 'Группы сетевых объектов',
    'Services': 'Сервисы',
    'ServiceGroups': 'Группы сервисов',
    'TimeIntervals': 'Временные интервалы',
    'FilterRules': 'Правила фильтрации',
    'NatRules': 'Правила трансляции',
}
stats_header_dict = {
    'done': 'Успешно:',
    'warning': 'С предупреждениями:',
    'error': 'С ошибками',
    'output': 'В итоговом файле:'
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
day_dict = {
    'Mon': 0,
    'Tue': 1,
    'Wed': 2,
    'Thu': 3,
    'Fri': 4,
    'Sat': 5,
    'Sun': 6
}
allowed_types = ['host', 'network', 'machines_range', 'group']


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


# Удаление служебных полей из итоговой структуры
def remove_fields(objs, fields, members_sections):
    if not objs:
        return

    def remove_fields_internal(object):
        if not type(object) == dict:
            return
        for field in fields:
            if field in object.keys(): del object[field]
        for members_section in members_sections:
            if members_section in object.keys():
                remove_fields(object[members_section], fields, members_sections)

    if not type(objs) == list:
        remove_fields_internal(objs)
    else:
        for object in objs:
            remove_fields_internal(object)


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


# Формирование поля conversion_err для отчёта из атрибутов, которые не переносятся
def collect_conversion_err(obj, interesting_attrs):
    conversion_err_parts = []
    for interesting_attr in interesting_attrs:
        if interesting_attr in obj.keys():
            conversion_err_parts.append(f'{interesting_attr}: {obj[interesting_attr]}')

    return '; '.join(conversion_err_parts)


# Формирование отчёта по непереносимой информации
def print_report(filepath, objects, sections, members_sections, chosen_rulebase):
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
        report_file.write(f"Информация об объекте системы, которая не переносится: {obj['conversion_err']}\n")
        if 'all_info_gates_use' in obj.keys():
            report_file.write(f"Связь с сетевыми устройствами: {', '.join(obj['all_info_gates_use'])}\n")
        report_file.write("\n")

    with open(filename, "w", encoding="utf8") as report_file:
        report_file.write("Система-источник: Check Point R77.30 / Check Point R80.20\n")
        report_file.write("Система-назначение: Континент 4\n")
        report_file.write(f"Политика: {chosen_rulebase['__internal_type_name']}\n")
        for section in sections:
            index = 1
            report_file.write(f"\n{section_dict[section]}:\n")
            walk(objects, section, index, report_file)

    log.info(f"Сформирован отчёт: {filename}")


def get_first(container, value):
    if type(container) == dict and value in container.keys():
        if len(container[value]) > 0:
            return container[value][0]
    return None


def add_to_list(list_object: list, added_object) -> list:
    out_list = list_object
    if type(added_object) == list:
        out_list.extend(added_object)
    else:
        out_list.append(added_object)
    return out_list


def get_netmask(netmask):
    return sum(bin(int(x)).count('1') for x in netmask.split('.'))


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


def get_nat_type(nat_dict):
    src_original = flat_ip(nat_dict['src']) if 'src' in nat_dict.keys() else None
    dst_original = flat_ip(nat_dict['dst']) if 'dst' in nat_dict.keys() else None
    service_original = flat_ip(nat_dict['service']) if 'service' in nat_dict.keys() else None
    src_translated = flat_ip(nat_dict['src_translated']) if in_and_full(nat_dict, 'src_translated') else src_original
    dst_translated = flat_ip(nat_dict['dst_translated']) if in_and_full(nat_dict, 'dst_translated') else dst_original
    service_translated = flat_ip(nat_dict['service_translated']) if in_and_full(nat_dict, 'service_translated') else service_original

    if service_original == None and service_translated:
        return None

    if src_original == src_translated and dst_original == dst_translated and service_original == service_translated:
        # "не транслировать"
        return "original"
    elif src_original != src_translated and dst_original == dst_translated:
        # "отправителя"
        return "dynamic"
    elif src_original == src_translated and dst_original != dst_translated:
        # "получателя"
        return "dnat"

    return None


# CheckPoint config to python dict
def parse_cp_config(cp_config):
    data = {}
    for line in cp_config:
        # :color (black)
        # : (POST)
        # )
        if line.strip().endswith(')'):
            if ':' in line and ' (' in line:
                clear_line = line.strip()[1:-1]
                param = clear_line[:clear_line.find(' (')]
                param = param.strip('"')
                value = clear_line[clear_line.find(' (') + 2:]
                value = value.strip('"')
                if param:
                    data[param] = value
                else:
                    if param not in data.keys():
                        data[param] = []
                    data[param].append(value)
                continue
            # )
            else:
                # for lists - : (POST)
                if list(data.keys()) == [""]:
                    return data[""]
                return data
        # : (
        # (
        if line.strip() == '(' or line.strip() == ': (':
            if not '__members' in data.keys():
                data['__members'] = []
            data['__members'].append(parse_cp_config(cp_config))
            continue
        # : ("All Users"
        # :AdminInfo (
        # :anyobj (Any
        if ':' in line and ' (' in line:
            clear_line = line.strip()[1:]
            param = clear_line[:clear_line.find(' (')]
            param = param.strip('"')

            internal_object = parse_cp_config(cp_config)

            internal_type_name = clear_line[clear_line.find(' (') + 2:]
            internal_type_name = internal_type_name.strip('"')
            if internal_type_name != '' and param != '':
                internal_object['__internal_type_name'] = internal_type_name

            if param == '':
                param = internal_type_name

            if not param in data.keys():
                data[param] = []
            if internal_object:
                add_to_list(data[param], internal_object)

    return data


def print_stats():
    for header in stats_header_dict.keys():
        log.info(stats_header_dict[header])
        for section in error_counter.keys():
            log.info(f'\t{section_dict[section]}: {error_counter[section][header]}')


def parse_rule(rule_dict, rule_type):
    if 'services' in rule_dict.keys() and len(rule_dict['services']) == 1:
        service = rule_dict['services'][0]
        # Правило вне политики
        if 'op' in service.keys() and service['op'] == 'not in':
            return None
    rule = {
        'name': rule_dict['name'],
        'original_name': rule_dict['name'],
        'description': '',
        'original_description': rule_dict.get('comments', ''),
        'is_enabled': False,
        '__internal_type': rule_type,
        'all_info_gates_use': [],
        'src': [],
        'dst': [],
        'service': [],
        'install_on': []
    }

    if 'disabled' in rule_dict.keys():
        rule['is_enabled'] = not rule_dict['disabled']

    ReferenceObjects = get_first(rule_dict, 'install')
    if ReferenceObjects:
        for install_on in ReferenceObjects['ReferenceObject']:
            if install_on:
                rule['all_info_gates_use'].append(install_on['Name'])

    sections_dictionary = {
        'FilterRules': process_FilterRules,
        'NatRules': process_NatRules
    }

    rule = sections_dictionary[rule_type](rule_dict, rule)

    if rule:
        desc_list = []
        if 'original_description' in rule.keys():
            desc_list.append(f"description ({rule['original_description']})")
        if 'conversion_err' in rule.keys():
            desc_list.append(f"non-transfer-info ({rule['conversion_err']})")
        if 'all_info_gates_use' in rule.keys():
            desc_list.append(f"gw-info ({', '.join(rule['all_info_gates_use'])})")
        rule['description'] = "; ".join(desc_list)

    return rule


def process_FilterRules(obj_dict, obj):
    obj['passips'] = False
    obj['rule_applications'] = []
    obj['is_inverse_src'] = False
    obj['is_inverse_dst'] = False

    if 'track' in obj_dict.keys():
        track_dict = get_first(obj_dict, 'track')
        track_obj = get_first(track_dict, 'ReferenceObject')
        if track_obj and 'Name' in track_obj.keys():
            obj['logging'] = {
                'Alert': True,
                'Log': True,
                'Account': False,
                'None': False,
            }.get(track_obj['Name'])

    if 'action' in obj_dict.keys():
        action_dict = get_first(obj_dict, 'action')
        if action_dict:
            action_obj = next(iter(action_dict.values()))[0]
            action = {
                'accept': 'pass',
                'drop': 'block',
                'reject': 'block',
            }.get(action_obj['type'], None)
            if not action:
                return None

            obj['rule_action'] = action

    objects_dict = {
        'src': 'src',
        'dst': 'dst',
        'services': 'service',
        'time': 'params'
    }

    for chapter in objects_dict.keys():
        r = get_first(obj_dict, chapter)
        if r and 'ReferenceObject' in r.keys():
            objects = r['ReferenceObject']
            obj[objects_dict[chapter]] = []
            for object in objects:
                if 'op' in object.keys() and object['op'] == 'not in':
                    continue
                obj[objects_dict[chapter]].append(object['Uid'])

    obj['conversion_err'] = collect_conversion_err(obj_dict,
        [
            'AdminInfo',
            'action',
            'disabled',
            'global_location',
            'install',
            'through'
        ])

    return obj


def process_NatRules(obj_dict, obj):
    obj['value'] = None
    obj['port_value'] = []
    obj['address_type'] = None
    obj['interface'] = None

    obj['conversion_err'] = collect_conversion_err(obj_dict,
        [
            'AdminInfo',
            'disabled',
            'global_location',
            'install',
            'rule_block_number'
        ])

    objects_dict = {
        'src_adtr': 'src',
        'dst_adtr': 'dst',
        'services_adtr': 'service',
        'src_adtr_translated': 'src_translated',
        'dst_adtr_translated': 'dst_translated',
        'services_adtr_translated': 'service_translated'
    }

    for chapter in objects_dict.keys():
        obj[objects_dict[chapter]] = []
        r = get_first(obj_dict, chapter)
        if r and 'ReferenceObject' in r.keys():
            objects = r['ReferenceObject']
            for object in objects:
                if 'op' in object.keys() and object['op'] == 'not in':
                    continue
                obj[objects_dict[chapter]].append(object['Uid'])
    return obj


def parse_rules(rulebase):
    rules = []
    for internal_rule_type in rule_types_dict.keys():
        for rule in rulebase.get(internal_rule_type, []):
            rule_type = rule_types_dict[internal_rule_type]
            parsed_rule = parse_rule(rule, rule_type)
            if parsed_rule:
                rules.append(parsed_rule)
                error_counter[rule_type]['done'] += 1
            else:
                error_counter[rule_type]['warning'] += 1
    return rules


def process_NetObjects(obj_dict, obj):
    obj['type'] = 'netobject'

    if 'ipaddr' in obj_dict.keys():
        if 'netmask' in obj_dict.keys() and obj_dict['netmask'] != '':
            obj['ip'] = f"{obj_dict['ipaddr']}/{get_netmask(obj_dict['netmask'])}"
        else:
            obj['ip'] = obj_dict['ipaddr']

    if 'ipaddr_first' in obj_dict.keys() and 'ipaddr_last' in obj_dict.keys():
        obj['ip'] = f"{obj_dict['ipaddr_first']}-{obj_dict['ipaddr_last']}"

    obj['conversion_err'] = collect_conversion_err(obj_dict,
        [
            'AdminInfo',
            'certificates',
            'edges',
            'interfaces',
            'DAG',
            'NAT',
            'read_community',
            'sysContact',
            'sysDescr',
            'sysLocation',
            'sysName',
            'write_community',
            'SNMP',
            'VPN',
            'add_adtr_rule',
            'additional_products',
            'addr_type_indication',
            'color',
            'connectra',
            'connectra_settings',
            'cp_products_installed',
            'data_source',
            'data_source_settings',
            'enforce_gtp_rate_limit',
            'firewall',
            'floodgate',
            'gtp_rate_limit',
            'ipaddr6',
            'macAddress',
            'os_info',
            'location_desc',
            'netmask6',
            'use_as_wildcard_netmask',
            'location',
            'broadcast',
            'ipaddr_first6',
            'ipaddr_last6'
        ])
    return obj


def process_NetObjectGroups(obj_dict, obj):
    obj['type'] = 'group'
    obj['subtype'] = 'netobject'

    if 'ReferenceObject' in obj_dict:
            obj['members'] = []
            for sub_object in obj_dict['ReferenceObject']:
                obj['members'].append(sub_object['Uid'])

    obj['conversion_err'] = collect_conversion_err(obj_dict,
        [
            'AdminInfo',
            'color',
            'group_convention_query',
            'group_sort_type',
            'ip_convention_object',
            'is_convention_on',
            'member_class',
            'members_query'
        ])
    return obj


def process_Services(obj_dict, obj):
    obj['type'] = 'service'
    obj['requires_keep_connections'] = False

    ports_dict = {
        'port': 'dst',
        'src_port': 'src',
    }
    for field_name in ports_dict:
        if field_name in obj_dict.keys():
            port = obj_dict[field_name]
            if port == '': continue
            if port.startswith('>'):
                min_port = int(port[1:]) + 1
                port = f'{min_port}-{DEFAULT_MAX_PORT}'
            elif port.startswith('<'):
                max_port = int(port[1:]) - 1
                port = f'{DEFAULT_MIN_PORT}-{max_port}'
            obj[ports_dict[field_name]] = port

    if not 'type' in obj_dict.keys(): return None
    protocol = obj_dict['type'].lower()

    if protocol in ['dcerpc', 'icmpv6']:
        return []

    if protocol in type_proto_dict.keys():
        obj['proto'] = type_proto_dict[protocol]

    if protocol == 'icmp':
        obj['icmp_type'] = obj_dict.get('icmp_type', None)
        obj['icmp_code'] = obj_dict.get('icmp_code', None)

    if protocol == 'other':
        if not 'protocol' in obj_dict.keys():
            return None

        protocol_number = int(obj_dict['protocol'])
        if protocol_number in [0, 41, 43, 44, 45, 46, 50, 51, 58, 59, 60]:
            return []

        obj['proto'] = protocol_number

    if protocol in ['tcp', 'udp', 'rpc']:
        for field in ['src', 'dst']:
            if obj.get(field, '0-65535') == '0-65535':
                obj[field] = ''

    obj['conversion_err'] = collect_conversion_err(obj_dict,
        [
            'AdminInfo',
            'aggressive_aging_timeout',
            'color',
            'default_aggressive_aging_timeout',
            'delete_on_reply',
            'enable_aggressive_aging',
            'etm_enabled',
            'include_in_any',
            'is_default_aggressive_timeout',
            'prohibit_aggressive_aging',
            'proto_type',
            'reload_proof',
            'replies',
            'replies_from_any_port',
            'sync_on_cluster',
            'timeout',
            'updated_by_sd',
            'delayed_sync_value',
            'enable_tcp_resource',
            'inspect_streaming',
            'spoofed_rst_detect',
            'unified_streaming',
            'use_delayed_sync',
            'unsupported_compatibility_packages',
            'exp',
            'needruleinfo',
            'weight'
        ])

    if protocol == 'rpc':
        obj['dst'] = '111'
        rpc_service1 = copy.deepcopy(obj)
        rpc_service1['proto'] = type_proto_dict['tcp']
        rpc_service2 = copy.deepcopy(obj)
        rpc_service2['proto'] = type_proto_dict['udp']
        obj = [rpc_service1, rpc_service2]

    return obj


def process_ServiceGroups(obj_dict, obj):
    obj['type'] = 'group'
    obj['subtype'] = 'service'

    if 'ReferenceObject' in obj_dict:
        obj['members'] = []
        for sub_object in obj_dict['ReferenceObject']:
            obj['members'].append(sub_object['Uid'])

    obj['conversion_err'] = collect_conversion_err(obj_dict,
        [
            'AdminInfo',
            'color',
            'group_convention_query',
            'group_sort_type',
            'ip_convention_object',
            'is_convention_on',
            'member_class',
            'members_query',
            'etm_enabled',
            'updated_by_sd'
        ])
    return obj


def process_TimeIntervals(obj_dict, obj):
    obj['type'] = 'timeinterval'

    def get_minutes(time_str):
        colon_index = time_str.find(':')
        if colon_index >= 0:
            hours = time_str[:colon_index]
            mins = time_str[colon_index + 1:]
            return int(hours) * 60 + int(mins)
        else:
            return int(time_str)

    obj['conversion_err'] = collect_conversion_err(obj_dict,
        [
            'AdminInfo',
            'color',
            'custom_fields',
            'day_of_month',
            'month',
            'time_period'
        ])

    days_specification = obj_dict.get('days_specification')
    # Дни
    days = []
    if days_specification == 'by day in week':
        days = obj_dict.get('day_of_week')
    elif days_specification in ['by day in month', 'seconds']:
        return None
    # none or daily
    else:
        days = [*day_dict]

    if len(days) > 0:
        obj['intervals'] = []

    if obj_dict.get('time1_active') or obj_dict.get('time2_active') or obj_dict.get('time3_active'):
        for i in range(1,3):
            if obj_dict.get(f'time{i}_active'):
                for day in days:
                    from_h = obj_dict.get(f'from_hour{i}')
                    from_m = obj_dict.get(f'from_minute{i}')
                    to_h = obj_dict.get(f'to_hour{i}')
                    to_m = obj_dict.get(f'to_minute{i}')
                    obj['intervals'].append({
                        'day': day_dict[day],
                        'start': get_minutes(f"{from_h}:{from_m}"),
                        'end': get_minutes(f"{to_h}:{to_m}")
                    })
    else:
        if obj_dict.get('is_owned') == False and \
            obj_dict.get('end_date_active') == False and \
            obj_dict.get('end_time') == 0 and \
            obj_dict.get('start_date_active') == False and \
            obj_dict.get('start_time') == 0:

            start = 0
            end = get_minutes("23:59")
            for day in days:
                obj['intervals'].append({'day': day_dict[day], 'start': start, 'end': end})

            return obj

    return obj


def parse_object(name, obj_dict, class_name):
    if name == 'Any':
        return None

    if class_name in ['NetObjects', 'NetObjectGroups'] and \
        obj_dict['type'] not in allowed_types:
        return None

    obj = {
        'name': name,
        'original_name': name,
        'description': '',
        'original_description': '',
        '__internal_type': class_name
    }
    adminInfo = get_first(obj_dict, 'AdminInfo')
    if adminInfo and 'chkpf_uid' in adminInfo.keys():
        obj['id'] = adminInfo['chkpf_uid']
    else:
        log.error("Объект без ID!")
        return None

    if 'comments' in obj_dict.keys():
        obj['original_description'] = obj_dict['comments']

    sections_dictionary = {
        'NetObjects': process_NetObjects,
        'NetObjectGroups': process_NetObjectGroups,
        'Services': process_Services,
        'ServiceGroups': process_ServiceGroups,
        'TimeIntervals': process_TimeIntervals,
    }

    obj = sections_dictionary[class_name](obj_dict, obj)

    def make_description(obj):
        desc_list = []
        if 'original_description' in obj.keys():
            desc_list.append(f"description ({obj['original_description']})")
        if 'conversion_err' in obj.keys():
            desc_list.append(f"non-transfer-info ({obj['conversion_err']})")
        obj['description'] = "; ".join(desc_list)
        return obj

    if type(obj) == list:
        for current_obj in obj:
            current_obj = make_description(current_obj)
    elif not obj is None:
        obj = make_description(obj)

    return obj


def parse_objects(objects_dict):
    objects = []
    for root_obj in objects_dict:
        for object_type in types_dict:
            object_dicts = get_first(root_obj, object_type)
            if not object_dicts:
                continue

            log.debug(f'process: {object_type}')
            for object_name in object_dicts:
                obj_dict = get_first(object_dicts, object_name)
                if not obj_dict:
                    continue

                if obj_dict['type'] == 'group':
                    k4_type = groups_dict[object_type]
                else:
                    k4_type = types_dict[object_type]

                obj = parse_object(
                        object_name,
                        obj_dict,
                        k4_type)

                if obj:
                    add_to_list(objects, obj)
                    error_counter[k4_type]['done'] += 1
                else:
                    error_counter[k4_type]['warning'] += 1
    return objects


def main():
    global node_id
    global node_name
    # Параметры
    parser = argparse.ArgumentParser(
                formatter_class = argparse.RawTextHelpFormatter,
                prog = f"\n\npython {basename(sys.argv[0])}",
                description = 'Преобразование правил Check Point R77.30 / Check Point R80.20 в Континент 4.',
                epilog = f'''example: python {basename(sys.argv[0])} -io input_objects_file_path.c -ir input_rules_file_path.fws -o output_folder_path --policy_name ##Policy
                ''',
                add_help = False
            )
    parser.add_argument('-h', '--help', action='help', default=argparse.SUPPRESS, help='Показать текущее сообщение помощи и выйти.')
    parser.add_argument('-io', '--input_objects', help='Путь до файла с объектами для преобразования', type=str)
    parser.add_argument('-ir', '--input_rules', help='Путь до файла с правилами для преобразования', type=str)
    parser.add_argument('-o', '--output_path', help='Путь до папки для выходного файла', type=pathlib.Path)
    parser.add_argument('--log', help='Имя файла отчёта', type=str)
    parser.add_argument('--policy_name', help='Имя политики для импорта', type=str)
    parser.add_argument('--name', help='Имя выходного файла', type=str)
    args = parser.parse_args()

    if not args.input_rules or not args.input_objects:
        parser.print_help()
        return

    # Настройка вывода логов в файл
    if args.log:
        fh = logging.FileHandler(args.log)
        formatter = logging.Formatter('%(asctime)s %(levelname)-8s %(message)s')
        fh.setFormatter(formatter)
        log.addHandler(fh)

    # Инициализация структуры данных для отчёта
    for section in section_dict.keys():
        error_counter[section] = {}
        for severity in stats_header_dict.keys():
            error_counter[section][severity] = 0

    # Парсинг
    input_objects_dict = []
    input_rules_dict = []
    log.info(f'Загрузка {args.input_objects}')

    with open(args.input_objects, 'r', errors='ignore') as f:
        while next(f, None):
            input_objects_dict.append(parse_cp_config(f))
    log.info(f'Загрузка завершена')

    log.info(f'Загрузка {args.input_rules}')
    with open(args.input_rules, 'r', errors='ignore') as f:
        while next(f, None):
            input_rules_dict.append(parse_cp_config(f))
    log.info(f'Загрузка завершена')

    if len(input_rules_dict) > 1:
        log.warning(f"Несколько корневых объектов в файле правил! {len(input_rules_dict)}")
    rules_root_obj = input_rules_dict[0]

    log.info(f"Количество политик: {len(rules_root_obj['rule-base'])}")

    # проверка политик
    if not args.policy_name:
        if len(rules_root_obj['rule-base']) > 1:
            for rulebase in rules_root_obj['rule-base']:
                if '__internal_type_name'  in rulebase.keys():
                    log.info(f'Политика \"{rulebase["__internal_type_name"]}\": ')
                    if 'rule' in rulebase.keys():
                        log.info(f"\tПравила фильтрации: {len(rulebase['rule'])}")
                    if 'rule_adtr' in rulebase.keys():
                        log.info(f"\tПравила трансляции: {len(rulebase['rule_adtr'])}")
            log.error("Не выбрана политика для импорта!")
            exit(0)
        elif len(rules_root_obj['rule-base']) == 1:
            policy = get_first(rules_root_obj, 'rule-base')
            if policy and "__internal_type_name" in policy.keys():
                args.policy_name = policy["__internal_type_name"]
        else:
            log.error("Нет политик!")
            exit(0)

    chosen_rulebase = None
    # info rules
    for rulebase in rules_root_obj['rule-base']:
        if '__internal_type_name'  in rulebase.keys():
            log.info(f'Политика \"{rulebase["__internal_type_name"]}\": ')
            if 'rule' in rulebase.keys():
                log.info(f"\tПравила фильтрации: {len(rulebase['rule'])}")
            if 'rule_adtr' in rulebase.keys():
                log.info(f"\tПравила трансляции: {len(rulebase['rule_adtr'])}")

            if rulebase['__internal_type_name'] == args.policy_name:
                chosen_rulebase = rulebase

    if not chosen_rulebase:
        log.error("Выбрана неверная политика!")
        exit(0)

    data = parse_rules(chosen_rulebase)
    objects = parse_objects(input_objects_dict)

    # Добавление объектов в группы
    for group in objects:
        if group['type'] == 'group':
            if not 'members' in group.keys():
                continue
            filled_section = []
            for object_id in group['members']:
                for obj in objects:
                    if obj['id'] == object_id and obj['type'] == group['subtype']:
                        added_object = copy.deepcopy(obj)
                        del added_object['id']
                        filled_section.append(added_object)
            group['members'] = filled_section

    # Добавление объектов в правила
    members_types = {
        'src': ['netobject'],
        'dst': ['netobject'],
        'service': ['service'],
        'src_translated': ['netobject'],
        'dst_translated': ['netobject'],
        'service_translated': ['service'],
        'params': ['timeinterval']
    }
    for rule in data:
        for section in members_types.keys():
            if section in rule.keys():
                filled_section = []
                for object_id in rule[section]:
                    # цикл по объектам
                    for obj in objects:
                        type_match = obj['type'] in members_types[section] or \
                            obj.get('subtype') in members_types[section]
                        if obj['id'] == object_id and type_match:
                            added_object = copy.deepcopy(obj)
                            del added_object['id']
                            filled_section.append(added_object)

                rule[section] = filled_section

    # В правиле может быть только один сервис, поэтому размножаем правила
    single_service_rules = []
    for rule in data:
        if 'service' in rule.keys() and len(rule['service']) > 1:
            for service in rule['service']:
                copied_rule = copy.deepcopy(rule)
                service_name = service['name'] if 'name' in service.keys() else ""
                copied_rule['name'] = f"{rule['name']}_{service_name}"
                copied_rule['service'] = [service]
                single_service_rules.append(copied_rule)
        else:
            single_service_rules.append(rule)
    data = single_service_rules

    # дозаполнение полей (nat_type, address_type, value) правил NAT
    full_rules = []
    for rule in data:
        if rule['__internal_type'] == 'NatRules':
            if 'service_translated' in rule.keys():
                rule['port_value'] = rule['service_translated']
                if rule['service_translated'] == []:
                    rule['port_type'] = []
                else:
                    rule['port_type'] = 'service'

            # nat type
            nat_type = get_nat_type(rule)
            if nat_type:
                rule['nat_type'] = nat_type
            else:
                error_counter['NatRules']['error'] += 1
                continue

            # сервисы могут быть только TCP или UDP
            for services in ['service_translated', 'service']:
                for service in rule[services]:
                    if 'proto' in service.keys():
                        if not service['proto'] in [ type_proto_dict['tcp'],
                                                     type_proto_dict['udp'] ]:
                            error_counter['NatRules']['error'] += 1
                            continue

            if rule['nat_type'] == 'dynamic':
                rule['address_type'] = 'netobject'
                rule['value'] = rule['src_translated']
            elif rule['nat_type'] == 'dnat':
                rule['address_type'] = 'netobject'
                rule['value'] = rule['dst_translated']
            else:
                rule['value'] = []
                rule['address_type'] = []
                rule['port_value'] = []
                rule['port_type'] = []

            for k in ['src_translated', 'dst_translated', 'service_translated']:
                if k in rule.keys():
                    del rule[k]

            error_counter['NatRules']['done'] += 1
        full_rules.append(rule)

    data = full_rules
    members_sections = [*members_types]
    members_sections.extend(['members', 'value', 'port_value'])
    path = make_outpath(args.output_path)
    print_report(path, data, [*section_dict], members_sections, chosen_rulebase)
    description_check(data, members_sections)
    remove_fields(data,
        [
            '__internal_type',
            'all_info_gates_use',
            'conversion_err',
            'id',
            'original_name',
            'original_description',
            '__translation_port'
        ], members_sections)

    if args.name:
        filename = path / args.name
    else:
        filename = path / OUTPUT_FILENAME.format(pathlib.Path(args.input_rules).stem,
                                                    chosen_rulebase['__internal_type_name'])
    if filename.exists():
        log.info("Выходной файл найден, перезапись")

    with open(filename, "w", encoding="utf8") as f:
        json.dump(data, f, indent=4, ensure_ascii=False)

    log.info(f"Записано: {filename}")

    print_stats()

if __name__ == '__main__':
    main()
