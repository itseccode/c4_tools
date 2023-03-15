#!/usr/bin/env python3
import json
from os.path import exists, basename
import sys
import xml.etree.ElementTree as ET
import argparse
import logging
import pathlib

OUTPUT_FILE_NAME_TEMPLATE = "import-gate{}{}-ver01.json"
MAX_DESCR_LEN = 1024

logging.basicConfig(encoding='utf-8', level=logging.INFO,
        format='%(asctime)s %(levelname)-8s %(message)s', datefmt='%Y-%m-%d %H:%M:%S'
)
log = logging.getLogger(__name__)
error_counter = {}
node_id = 0
node_name = ''
proto_map = {
    'icmp': 1,
    'tcp': 6,
    'udp': 17,
}
nat_type_map = {
    'Outbound': 'dynamic',
    'Inbound': 'dnat',
    'Both': 'static',
    'None': 'original',
}
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
icmp_type_dict = {
    'Любой': None,
    'Echo Reply': 0,
    'Destination Unreachable': 3,
    'Source Quench': 4,
    'Redirect': 5,
    'Alternate Host Address': 6,
    'Echo': 8,
    'Router Advertisement': 9,
    'Router Solicitation': 10,
    'Time Exceeded': 11,
    'Parameter Problem': 12,
    'Timestamp': 13,
    'Timestamp Reply': 14,
    'Information Request': 15,
    'Information Reply': 16,
    'Address Mask Request': 17,
    'Address Mask Reply': 18,
    'Traceroute': 30,
    'Datagram Conversion Error': 31,
    'Mobile Host Redirect': 32,
    'IPv6 Where-Are-You': 33,
    'IPv6 I-Am-Here': 34,
    'Mobile Registration Request': 35,
    'Mobile Registration Reply': 36
}
icmp_code_dict = {
    3: {
        'Net Unreachable': 0,
        'Host Unreachable': 1,
        'Protocol Unreachable': 2,
        'Port Unreachable': 3,
        'Fragmentation Needed and Don\'t Fragment was Set': 4,
        'Source Route Failed': 5,
        'Destination Network Unknown': 6,
        'Host Unreachable': 7,
        'Source Host Isolated': 8,
        'Communication with Destination Network is Administratively Prohibited': 9,
        'Communication with Destination Host is Administratively Prohibited': 10,
        'Destination Network Unreachable for Type of Service': 11,
        'Destination Host Unreachable for Type of Service': 12,
        'Communication Administratively Prohibited': 13,
        'Host Precedence Violation': 14,
        'Precedence Сutoff in Effect': 15
    },
    5: {
        'Redirect Network': 0,
        'Redirect Host': 1,
        'Redirect Network for TOS': 2,
        'Redirect Host for TOS': 3
    },
    11: {
        'TTL exceeded': 0,
        'Fragment Reassembly Time Exceeded': 1
    },
    12: {
        'Pointer indicates the error': 0,
        'Missing a Required Option': 1,
        'Bad Length ': 2
    },
}
day_dict = {
    'Monday': 0,
    'Tuesday': 1,
    'Wednesday': 2,
    'Thursday':3,
    'Friday': 4,
    'Saturday': 5,
    'Sunday': 6
}


# Одинаковое добавление к списку одного или множества объектов
def add_to_list(list_object: list, added_object) -> list:
    out_list = list_object
    if type(added_object) == list:
        out_list.extend(added_object)
    elif added_object:
        out_list.append(added_object)
    return out_list


def get_netmask(netmask):
    return sum(bin(int(x)).count('1') for x in netmask.split('.'))


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
                log.warning('Слишком длинное описание!')
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
    attrib_dicts = [obj.attrib]

    bindings = obj.find('Bindings')
    if bindings != None:
        for binding in bindings:
            attrib_dicts.append(binding.attrib)

    attributes = obj.find('Attributes')
    if attributes != None:
        attrib_dicts.append(attributes.attrib)

    for attrib_dict in attrib_dicts:
        for interesting_attr in interesting_attrs:
            if interesting_attr in attrib_dict.keys():
                conversion_err_parts.append(f'{interesting_attr}: {attrib_dict[interesting_attr]}')

    return '; '.join(conversion_err_parts)


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


def process_NetObjects(child, obj_attribs, obj):
    obj['type'] = 'netobject'

    if 'ip' in obj_attribs.keys():
        obj['ip'] = f"{obj_attribs['ip']}/{get_netmask(obj_attribs['mask'])}"

    if obj['name'] == 'Любой' and obj['ip'] == '0.0.0.0/0':
        return None

    obj['conversion_err'] = collect_conversion_err(child,
        ['id','multicast', 'link_type', 'registry', 'cgw_id', 'iface_id'])
    return obj


def process_NetObjectGroups(child, obj_attribs, obj):
    obj['type'] = 'group'
    obj['subtype'] = 'netobject'

    netobjects = child.findall('Netobject')
    if not netobjects == None:
        obj['members'] = []
        for netobject in netobjects:
            obj['members'].append(netobject.attrib['id'])

    obj['conversion_err'] = collect_conversion_err(child, ['id'])
    return obj


def process_Services(child, obj_attribs, obj):
    obj['type'] = 'service'
    obj['requires_keep_connections'] = False

    names_to_replace = {
        "Любой TCP": "TCP",
        "Любой UDP": "UDP",
        "Любой ICMP": "ICMP"
    }
    name = obj['name']
    if name in names_to_replace.keys():
        obj['name'] = names_to_replace[name]
        obj['description'] = ''

    if not 'proto' in obj_attribs.keys(): return None
    original_proto = obj_attribs['proto']

    if 'ip(' in original_proto:
        obj['proto'] = int(original_proto.replace('ip(', '').replace(')', ''))
    else:
        obj['proto'] = proto_map.get(original_proto, proto_map['icmp'])

    if 'src_port' in obj_attribs.keys():
        obj['src'] = obj_attribs['src_port']

    if 'dst_port' in obj_attribs.keys():
        obj['dst'] = obj_attribs['dst_port']

    if obj['proto'] in [ proto_map['tcp'], proto_map['udp'] ]:
        for field in ['src', 'dst']:
            if obj[field] == '0-65535':
                obj[field] = ''

    if obj['proto'] == proto_map['icmp']:
        original_type = obj_attribs.get('type', None)
        obj['icmp_type'] = icmp_type_dict.get(original_type, None)
        obj['icmp_code'] = None

        original_icmp_code = obj_attribs.get('code', None)
        icmp_code_chapter = icmp_code_dict.get(obj['icmp_type'], None)
        if original_icmp_code and icmp_code_chapter:
                obj['icmp_code'] = icmp_code_chapter.get(original_icmp_code, None)

    obj['conversion_err'] = collect_conversion_err(child,
        ['id', 'proto', 'type', 'code', 'src_port', 'dst_port'])
    return obj


def process_ServiceGroups(child, obj_attribs, obj):
    obj['type'] = 'group'
    obj['subtype'] = 'service'

    # members
    services = child.findall('Service')
    if not services == None:
        obj['members'] = []
        for service in services:
            obj['members'].append(service.attrib['id'])

    obj['conversion_err'] = collect_conversion_err(child, ['id'])
    return obj


def process_TimeIntervals(child, obj_attribs, obj):
    obj['type'] = 'timeinterval'
    obj['intervals'] = []

    def get_minutes(time_str):
        colon_index = time_str.find(':')
        if colon_index >= 0:
            hours = time_str[:colon_index]
            mins = time_str[colon_index + 1:]
            return int(hours) * 60 + int(mins)
        else:
            return int(time_str)

    intervals = child.find('Intervals')
    if intervals:
        for interval in intervals:
            interval_dict = {}

            day = interval.get('day')
            if day: interval_dict['day'] = day_dict.get(day, day_dict['Sunday'])
            start = interval.get('start')
            if start: interval_dict['start'] = get_minutes(start)
            end = interval.get('end')
            if end: interval_dict['finish'] = get_minutes(end)

            obj['intervals'].append(interval_dict)

    obj['conversion_err'] = collect_conversion_err(child, ['id', 'start', 'end'])
    if obj['name'] == 'Постоянно' and not intervals:
        return None

    return obj


def process_objects_section(section):
    log.debug(f'process: {section.tag}')
    objects = []
    for child in section:
        obj = {
            'description': '',
            'original_description': '',
            'name': '',
            'original_name': '',
            '__internal_type': section.tag
        }
        obj_attribs = {}
        if child.find('Attributes') == None:
            log.warning('У объекта нет атрибутов!')
            error_counter[section.tag]['warning'] += 1
            continue
        else:
            obj_attribs = child.find('Attributes').attrib

        if 'name' in child.attrib.keys():
            obj['name'] = child.attrib['name']
            obj['original_name'] = child.attrib['name']
        else:
            log.error('У объекта нет атрибута name!')
            error_counter[section.tag]['error'] += 1

        if 'description' in child.attrib.keys():
            obj['original_description'] = child.attrib['description']

        if 'id' in obj_attribs.keys():
            obj['id'] = obj_attribs['id']

        # all_info_gates_use
        bindings = child.find('Bindings')
        if bindings:
            id_list = []
            for binding in bindings:
                id_list.append(binding.attrib['cgw_id'])
            obj['all_info_gates_use'] = id_list

        sections_dictionary = {
            'NetObjects': process_NetObjects,
            'NetObjectGroups': process_NetObjectGroups,
            'Services': process_Services,
            'ServiceGroups': process_ServiceGroups,
            'TimeIntervals': process_TimeIntervals,
        }

        new_object = sections_dictionary[section.tag](child, obj_attribs, obj)

        if not new_object:
            continue

        desc_list = []
        if 'original_description' in obj.keys():
            desc_list.append(f"description ({obj['original_description']})")
        if 'conversion_err' in new_object.keys():
            desc_list.append(f"non-transfer-info ({new_object['conversion_err']})")
        if 'all_info_gates_use' in obj.keys():
            desc_list.append(f"gw-info ({', '.join(obj['all_info_gates_use'])})")
        obj['description'] = "; ".join(desc_list)

        objects.append(new_object)
        error_counter[section.tag]['done'] += 1
    return objects


def process_FilterRules(section):
    log.debug(f'process: {section.tag}')
    rules = []
    for child in section:
        rule = {
            'description': '',
            'original_description': '',
            'name': '',
            'original_name': '',
            'is_enabled': False,
            'passips': False,
            'service': [],
            'rule_applications': [],
            'install_on': [],
            '__internal_type': section.tag
        }
        rule_attribs = None
        if child.find('Attributes') == None:
            log.warning('У правила нет атрибутов!')
            error_counter[section.tag]['warning'] += 1
            continue
        else:
            rule_attribs = child.find('Attributes').attrib

        if 'name' in child.attrib.keys():
            rule['name'] = child.attrib['name']
            rule['original_name'] = child.attrib['name']
        else:
            log.error('У правила нет атрибута name!')
            error_counter[section.tag]['error'] += 1

        if 'src_inverse' in rule_attribs.keys():
            rule['is_inverse_src'] = bool(rule_attribs['src_inverse'])

        if 'dst_inverse' in rule_attribs.keys():
            rule['is_inverse_dst'] = bool(rule_attribs['dst_inverse'])

        if 'action' in rule_attribs.keys():
            if rule_attribs['action'] == 'Deny':
                rule['rule_action'] = 'block'
            else:
                rule['rule_action'] = 'pass'

        if 'registry' in rule_attribs.keys():
            rule['logging'] = bool(rule_attribs['registry'])

        if 'disabled' in rule_attribs.keys():
            rule['is_enabled'] = not rule_attribs['disabled']

        for field in ['src', 'dst']:
            netobjects = []
            add_to_list(netobjects, rule_attribs.get(f'{field}_no_id', None))
            add_to_list(netobjects, rule_attribs.get(f'{field}_ug_id', None))
            if len(netobjects) > 0:
                rule[field] = netobjects

        if 'dst_ug_id' in rule_attribs.keys() or 'src_ug_id' in rule_attribs.keys():
            rule['is_inverse_dst'] = False

        if 'ti_id' in rule_attribs.keys():
            rule['params'] = add_to_list([], rule_attribs['ti_id'])

        services = child.find('Services')
        if not services == None:
            rule['service'] = []
            for service in services:
                rule['service'].append(service.attrib['id'])

        rule['conversion_err'] = collect_conversion_err(child,
            ['id', 'action', 'tc_id', 'registry', 'keep_state', 'quick'])
        # all_info_gates_use
        bindings = child.find('Install_on')
        if bindings:
            id_list = []
            for binding in bindings:
                id_list.append(binding.attrib['id'])
            rule['all_info_gates_use'] = id_list

        if 'description' in child.attrib.keys():
            rule['original_description'] = child.attrib['description']

        desc_list = []
        if 'original_description' in rule.keys():
            desc_list.append(f"description ({rule['original_description']})")
        if 'conversion_err' in rule.keys():
            desc_list.append(f"non-transfer-info ({rule['conversion_err']})")
        if 'all_info_gates_use' in rule.keys():
            desc_list.append(f"gw-info ({', '.join(rule['all_info_gates_use'])})")
        rule['description'] = "; ".join(desc_list)

        rules.append(rule)
        error_counter[section.tag]['done'] += 1

    return rules


# port_type и port_value зависят от типа NAT
def convert_nat_rule(rule, service, name):
    rule['name'] = name
    rule['service'] = [service]
    if rule['nat_type'] == 'dnat' and not service['__translation_port'] == '0':
        rule['port_type'] = 'service'
        rule['port_value'] = service.copy()
        rule['port_value']['name'] += f"_{service['__translation_port']}"
        rule['port_value']['dst'] = service['__translation_port']
        rule['port_value']['src'] = []
    return rule


def process_NatRules(section):
    log.debug(f'process: {section.tag}')
    rules = []
    for child in section:
        rule = {
            'description': '',
            'original_description': '',
            'name': '',
            'original_name': '',
            'is_enabled': False,
            'interface': None,
            'service': [],
            'port_value': None,
            'port_type': None,
            'install_on': [],
            '__internal_type': section.tag
        }
        rule_attribs = None
        if child.find('Attributes') == None:
            log.warning('У правила нет атрибутов!')
            error_counter[section.tag]['warning'] += 1
            continue
        else:
            rule_attribs = child.find('Attributes').attrib

        if 'name' in child.attrib.keys():
            rule['name'] = child.attrib['name']
            rule['original_name'] = child.attrib['name']
        else:
            log.error('У правила нет атрибута name!')
            error_counter[section.tag]['error'] += 1

        if 'disabled' in rule_attribs.keys():
            rule['is_enabled'] = not rule_attribs['disabled']

        for field in ['src', 'dst']:
            netobjects = []
            add_to_list(netobjects, rule_attribs.get(f'{field}_no_id', None))
            add_to_list(netobjects, rule_attribs.get(f'{field}_ug_id', None))
            if len(netobjects) > 0:
                rule[field] = netobjects

        if 'ip_mask' in rule_attribs.keys():
            rule['value'] = add_to_list([], rule_attribs['ip_mask'])
            rule['address_type'] = 'netobject'

        if 'direction' in rule_attribs.keys():
            rule['nat_type'] = 'original'
            if 'direction' in rule_attribs.keys():
                rule['nat_type'] = nat_type_map.get(rule_attribs['direction'])

        rule['conversion_err'] = collect_conversion_err(child,
            ['id', 'eth_id', 'ti_id', 'tc_id', 'registry', 'ftp'])

        # all_info_gates_use
        bindings = child.find('Install_on')
        if bindings:
            id_list = []
            for binding in bindings:
                id_list.append(binding.attrib['id'])
            rule['all_info_gates_use'] = id_list

        if 'description' in child.attrib.keys():
            rule['original_description'] = child.attrib['description']

        desc_list = []
        if 'original_description' in rule.keys():
            desc_list.append(f"description ({rule['original_description']})")
        if 'conversion_err' in rule.keys():
            desc_list.append(f"non-transfer-info ({rule['conversion_err']})")
        if 'all_info_gates_use' in rule.keys():
            desc_list.append(f"gw-info ({', '.join(rule['all_info_gates_use'])})")
        rule['description'] = "; ".join(desc_list)

        services = child.find('Services')
        if not services == None:
            services_ids = []
            for service in services:
                new_service = {}
                if 'port' in service.attrib:
                    new_service['port'] = service.attrib['port']
                new_service['id'] = service.attrib['id']
                services_ids.append(new_service)
            rule['service'] = services_ids

        rules.append(rule)
        error_counter[section.tag]['done'] += 1

    return rules


def get_xml_object(xml_path):
    tree = None
    try:
        tree = ET.parse(xml_path)
    except:
        return None
    if tree:
        return tree.getroot()


# Вывод статистики по ошибкам и объектам на выходе
def print_stats():
    for header in stats_header_dict:
        log.info(stats_header_dict[header])
        for section in error_counter.keys():
            log.info(f'\t{section_dict[section]}: {error_counter[section][header]}')


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

    def write_object(object, report_file, index):
        report_file.write(f"{index}. Имя: {object['name']}\n")
        report_file.write(f"Оригинальное имя: {object['original_name']}\n")
        report_file.write(f"Оригинальное описание: {object['original_description']}\n")
        report_file.write(f"Информация об объекте системы, которая не переносится: {object['conversion_err']}\n")
        if 'all_info_gates_use' in object.keys():
            report_file.write(f"Связь с сетевыми устройствами (КШ): {', '.join(object['all_info_gates_use'])}\n")
        report_file.write("\n")

    with open(filename, "w", encoding="utf8") as report_file:
        report_file.write("Система-источник: Континент 3\n")
        report_file.write("Система-назначение: Континент 4\n")
        for section in sections:
            index = 1
            report_file.write(f"\n{section_dict[section]}:\n")
            walk(objects, section, index, report_file)

    log.info(f"Сформирован отчёт: {filename}")


def main():
    global node_id
    global node_name
    # Параметры
    parser = argparse.ArgumentParser(
                formatter_class=argparse.RawTextHelpFormatter,
                prog = f"\n\npython {basename(sys.argv[0])}",
                description = 'Преобразование правил Континент из XML в JSON.',
                epilog = f'''example: python {basename(sys.argv[0])} -i input_file_path.xml -o output_folder_path
                ''',
                add_help = False
            )
    parser.add_argument('-h', '--help', action='help', default=argparse.SUPPRESS, help='Показать текущее сообщение помощи и выйти.')
    parser.add_argument('-i', '--input', help='Путь до файла для преобразования.', type=str)
    parser.add_argument('-o', '--output_path', help='Путь до папки для выходного файла.', type=pathlib.Path)
    parser.add_argument('--log', help='Имя файла лога.', type=str)
    parser.add_argument('--name', help='Имя выходного файла.', type=str)
    args = parser.parse_args()

    if not args.input:
        parser.print_help()
        return

    # Настройка вывода логов в файл
    if args.log:
        file_handler = logging.FileHandler(args.log)
        formatter = logging.Formatter('%(asctime)s %(levelname)-8s %(message)s')
        file_handler.setFormatter(formatter)
        log.addHandler(file_handler)

    # Парсинг XML
    log.info(f'Загрузка {args.input}')
    xml_data = get_xml_object(args.input)
    if not xml_data:
        log.error(f'Невозможно открыть или распарсить {args.input}')
        return
    log.info(f'Загрузка завершена')

    # Проверка основного тэга
    log.debug(f'Основной тэг: {xml_data.tag}')
    if xml_data.tag != 'ObjBase':
        log.warning('Неправильный тэг основной секции. Возможно выбран неверный файл.')

    # Получение id gateway
    gateways = xml_data.find('Gateways')
    if gateways:
        node_name = gateways[0].attrib['name']
        gateway_attributes = gateways[0].find('Attributes')
        if not gateway_attributes == None:
            node_id = gateway_attributes.attrib['id']
        else:
            log.error("У узла нет атрибутов!")
        log.debug(f"ID узла: {node_id}")
        log.debug(f"Имя узла: {node_name}")

    # Словарь для сопоставления имени секции с функцией, обрабатывающей эту секцию
    sections_dictionary = {
        'NetObjects': process_objects_section,
        'NetObjectGroups': process_objects_section,
        'Services': process_objects_section,
        'ServiceGroups': process_objects_section,
        'TimeIntervals': process_objects_section,
        'FilterRules': process_FilterRules,
        'NatRules': process_NatRules,
    }

    # Инициализация структуры данных для отчёта
    for section in sections_dictionary.keys():
        error_counter[section] = {}
        for stats_header in stats_header_dict:
            error_counter[section][stats_header] = 0

    # Сбор объектов и правил
    json_data = []
    objects = []
    for section in xml_data:
        if not section.tag in sections_dictionary.keys():
            if not section.tag == 'Gateways':
                log.warning(f'Неподдерживаемая секция: {section.tag}')
        else:
            section_json_data = sections_dictionary[section.tag](section)
            if not section_json_data:
                continue
            if section.tag in ['FilterRules', 'NatRules']:
                json_data.extend(section_json_data)
            else:
                objects.extend(section_json_data)

    # Лог объектов и правил до объединения
    log.debug('#' * 90 + f' json_data: {len(json_data)}')
    log.debug(json.dumps(json_data, indent=4, ensure_ascii=False))
    log.debug('#' * 90 + f' objects: {len(objects)}')
    log.debug(json.dumps(objects, indent=4, ensure_ascii=False))
    log.debug('#' * 90)

    if len(json_data) == 0:
        log.error('Отсутствуют правила! Выбран неверный файл!')
        return

    if len(objects) == 0:
        log.error('Отсутствуют объекты! Выбран неверный файл!')
        return

    # Добавление объектов в группы
    groupable_object_types = {
        'NetObjectGroups': 'NetObjects',
        'ServiceGroups': 'Services'
    }
    for group in objects:
        group_type = group['__internal_type']
        if not group_type in groupable_object_types.keys():
            continue
        filled_section = []
        for object_id in group['members']:
            for obj in objects:
                if obj['id'] == object_id and obj['__internal_type'] == groupable_object_types[group_type]:
                    added_object = obj.copy()
                    filled_section.append(added_object)
        group['members'] = filled_section

    # Добавление объектов в правила
    members_types = {
        'params': ['TimeIntervals'],
        'src': ['NetObjects', 'NetObjectGroups'],
        'dst': ['NetObjects', 'NetObjectGroups'],
        'service': ['Services', 'ServiceGroups']
    }
    for rule in json_data:
        if not rule['__internal_type'] in ['NatRules', 'FilterRules']:
            continue
        for section in members_types.keys():
            # У nat поиск netobject по ip - блок ниже
            if (rule['__internal_type'] == 'NatRules' and section in ['service']):
                continue
            if not section in rule.keys():
                continue
            filled_section = []
            for object_id in rule[section]:
                for obj in objects:
                    if obj['id'] == object_id and obj['__internal_type'] in members_types[section]:
                        added_object = obj.copy()
                        filled_section.append(added_object)
            rule[section] = filled_section

    # Добавление объектов NAT
    for rule in json_data:
        if not rule['__internal_type'] == 'NatRules':
            continue
        filled_section = []
        for ip_and_mask in rule['value']:
            found = False
            for obj in objects:
                if obj.get('ip', None) == ip_and_mask:
                    added_object = obj.copy()
                    filled_section.append(added_object)
                    found = True
            if not found:
                filled_section.append({
                    'name': ip_and_mask,
                    'ip': ip_and_mask,
                    'type': 'netobject',
                    'description': '',
                    'original_description': '',
                    'original_name': '',
                    '__internal_type': 'NetObjects',
                    'conversion_err': ''
                })
        if len(filled_section) > 0:
            rule['value'] = filled_section
        else:
            del rule['value']

    # В правиле NAT может быть только один сервис
    # Окончательное заполнение port_type, port_value и service
    single_service_rules = []
    for rule in json_data:
        if 'NatRules' == rule['__internal_type'] and len(rule['service']) > 0:
            # Сбор объектов сервисов, формирование "плоского" списка с портами трансляции
            services = []
            for service in rule['service']:
                # Поиск сервиса в объектах по id
                raw_service = {}
                for obj in objects:
                    if obj['id'] == service['id'] and obj['__internal_type'] in ['Services', 'ServiceGroups']:
                        raw_service = obj
                        break

                # Сбор сервисов, если объект - группа и добавление порта трансляции
                port = service.get('port', None)
                if raw_service.get('type', None) == 'group':
                    for internal_service in raw_service['members']:
                        internal_service['__translation_port'] = port
                    services.extend(raw_service['members'])
                else:
                    raw_service['__translation_port'] = port
                    services.append(raw_service)

            # Первое правило без изменения имени
            single_service_rules.append(
                convert_nat_rule(rule, services[0], rule['name'])
            )

            # Если сервис не один, то остальные правила копируются с добавлением имени сервиса к имени правила
            for service in services[1:]:
                service_name = service['name'] if 'name' in service.keys() else ""
                name = f"{rule['name']}_{service_name}"
                copied_rule = rule.copy()
                single_service_rules.append(
                    convert_nat_rule(copied_rule, service, name)
                )
        else:
            # Сервисов вообще нет или это не NAT правило
            single_service_rules.append(rule)
    json_data = single_service_rules

    # Лог итоговой структуры с полным описанием и служебными полями
    log.debug(json.dumps(json_data, indent = 4, ensure_ascii=False))
    log.debug('#' * 90)

    members_sections = [*members_types]
    members_sections.extend(['members', 'port_value', 'value'])
    path = make_outpath(args.output_path)
    print_report(path, json_data, [*sections_dictionary], members_sections)
    description_check(json_data, members_sections)
    remove_fields(json_data,
        ['__internal_type', 'all_info_gates_use', 'conversion_err', 'id',
         'original_name', '__translation_port', 'original_description'], members_sections)

    if args.name:
        output_file_name = path / args.name
    else:
        output_file_name = path / OUTPUT_FILE_NAME_TEMPLATE.format(node_name, node_id)
    if output_file_name.exists():
        log.info("Выходной файл найден, перезапись")

    with open(output_file_name, "w", encoding="utf8") as f:
        json.dump(json_data, f, indent=4, ensure_ascii=False)
    log.info(f"Записано: {output_file_name}")

    print_stats()


if __name__ == '__main__':
    main()
