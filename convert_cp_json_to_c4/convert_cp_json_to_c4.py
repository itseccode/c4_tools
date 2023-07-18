#!/usr/bin/env python3
import json
from os.path import exists, basename
import sys
import argparse
import logging
import pathlib
import copy
import ipaddress
import os

# for progressbar in windows
os.system("")

OUTPUT_FILENAME = "{}-{}-{}.json"
MAX_DESCR_LEN = 1024

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
}
stats_header_dict = {
    'done': 'Успешно:',
    'warning': 'С предупреждениями:',
    'error': 'С ошибками',
    'output': 'В итоговом файле:'
}
rule_types_dict = {'access-rule': 'FilterRules', 'nat-rule': 'NatRules'}
types_dict = {
    'service-icmp': 'Services',
    'service-other': 'Services',
    'service-tcp': 'Services',
    'service-udp': 'Services',
    'address-range': 'NetObjects',
    'host': 'NetObjects',
    'network': 'NetObjects',
    'group': 'NetObjectGroups',
    'service-group': 'ServiceGroups',
    'time': 'TimeIntervals'
}
service_types = {
    'service-icmp': 1,
    'service-tcp': 6,
    'service-udp': 17
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


def draw_progress(i, min_i, max_i, size):
    sys.stdout.write("\033[G")
    i += 1
    progress_percent = (max_i - min_i) / size
    progress = round((i - min_i) / progress_percent)
    str_filler = "█" * progress
    str_emptiness = " " * (size - progress)
    percent = round((i - min_i) / ((max_i - min_i) / 100))
    sys.stdout.write(f"|\033[92m{str_filler}{str_emptiness}\033[0m| \033[1m{i - min_i} / {max_i - min_i} - {percent}%\033[0m")
    if i == max_i:
        sys.stdout.write("\n")
    sys.stdout.flush()


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


def add_to_list(list_object: list, added_object) -> list:
    out_list = list_object
    if type(added_object) == list:
        out_list.extend(added_object)
    else:
        out_list.append(added_object)
    return out_list


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
        for obj in objs:
            if not type(obj) == dict:
                continue
            if section == obj['__internal_type']:
                error_counter[section]['output'] += 1
                write_object(obj, report_file, index)
                index += 1
            for members_section in members_sections:
                if members_section in obj.keys():
                    index = walk(obj[members_section], section, index, report_file)
        return index

    def write_object(obj, report_file, index):
        report_file.write(f"{index}. Имя: {obj['name']}\n")
        report_file.write(f"Оригинальное имя: {obj['original_name']}\n")
        report_file.write(f"Оригинальное описание: {obj['original_description']}\n")
        report_file.write("\n")

    with open(filename, "w", encoding="utf8") as report_file:
        report_file.write("Система-источник: Check Point R81.10\n")
        report_file.write("Система-назначение: Континент 4\n")
        for section in sections:
            index = 1
            report_file.write(f"\n{section_dict[section]}:\n")
            walk(objects, section, index, report_file)

    log.info(f"Сформирован отчёт: {filename}")


def print_stats():
    for header in stats_header_dict.keys():
        log.info(stats_header_dict[header])
        for section in error_counter.keys():
            log.info(f'\t{section_dict[section]}: {error_counter[section][header]}')


def parse_rules(rules_input_list):
    rules = []
    for rule in rules_input_list:
        obj_type = rule.get('type')
        rule_type = rule_types_dict.get(obj_type)
        if rule_type is None:
            continue

        parsed_rule = parse_rule(rule, rule_type)
        if not parsed_rule is None:
            rules.append(parsed_rule)
            error_counter[rule_type]['done'] += 1
        else:
            error_counter[rule_type]['warning'] += 1
            log.warning(f"Правило некорректное: {rule}")
    return rules


def parse_rule(rule_dict, rule_type):
    rule = {
        'name': rule_dict.get('name', ''),
        'original_name': rule_dict.get('name', ''),
        'description': rule_dict.get('comments', ''),
        'original_description': rule_dict.get('comments', ''),
        'is_enabled': False,
        '__internal_type': rule_type,
        'src': [],
        'dst': [],
        'service': [],
        'install_on': [],
        'id': rule_dict.get('uid')
    }
    sections_dictionary = {
        'FilterRules': process_FilterRules,
        'NatRules': process_NatRules
    }
    return sections_dictionary[rule_type](rule_dict, rule)


def process_FilterRules(obj_dict, obj):
    obj['passips'] = False
    obj['rule_applications'] = []
    obj['is_inverse_src'] = obj_dict.get('source-negate', False)
    obj['is_inverse_dst'] = obj_dict.get('destination-negate', False)

    # uuid
    if 'track' in obj_dict.keys():
        if obj_dict['track'].get('accounting', False):
            log.warning('Правила с track = accounting не поддерживаются')
            return None
        obj['logging'] = obj_dict['track'].get('type')

    objects_dict = {
        'source': 'src',
        'destination': 'dst',
        'service': 'service',
        'time': 'params'
    }

    for chapter in objects_dict.keys():
        if chapter in obj_dict.keys():
            obj[objects_dict[chapter]] = obj_dict[chapter]

    # uuid
    obj['rule_action'] = obj_dict.get('action')
    return obj


def process_NatRules(obj_dict, obj):
    obj['value'] = None
    obj['port_value'] = []
    obj['address_type'] = None
    obj['interface'] = None

    objects_dict = {
        'original-source': 'src',
        'original-destination': 'dst',
        'original-service': 'service',
        'translated-source': 'src_translated',
        'translated-destination': 'dst_translated',
        'translated-service': 'service_translated'
    }

    for chapter in objects_dict.keys():
        obj[objects_dict[chapter]] = []
        member = obj_dict.get(chapter)
        if not member is None:
            obj[objects_dict[chapter]].append(member)

    return obj


def parse_objects(objects_dict):
    objects = []
    for obj_dict in objects_dict:
        obj_type = obj_dict.get('type')
        k4_type = types_dict.get(obj_type)
        if k4_type is None:
            continue

        obj = parse_object(obj_dict, k4_type)

        if not obj is None:
            add_to_list(objects, obj)
            error_counter[k4_type]['done'] += 1
        else:
            error_counter[k4_type]['warning'] += 1
            log.warning(f"Объект некорректный: {obj_dict}")
    return objects


def parse_object(obj_dict, class_name):
    obj = {
        'name': obj_dict.get('name', ''),
        'original_name': obj_dict.get('name', ''),
        'description': obj_dict.get('comments', ''),
        'original_description': obj_dict.get('comments', ''),
        '__internal_type': class_name,
        'id': obj_dict.get('uid')
    }

    sections_dictionary = {
        'NetObjects': process_NetObjects,
        'NetObjectGroups': process_NetObjectGroups,
        'Services': process_Services,
        'ServiceGroups': process_ServiceGroups,
        'TimeIntervals': process_TimeIntervals,
    }

    return sections_dictionary[class_name](obj_dict, obj)


def process_NetObjectGroups(obj_dict, obj):
    obj['type'] = 'group'
    obj['subtype'] = 'netobject'
    obj['members'] = obj_dict.get('members', [])
    return obj


def process_NetObjects(obj_dict, obj):
    obj['type'] = 'netobject'

    if obj_dict['type'] == 'host':
        if 'ipv6-address' in obj_dict.keys():
            log.warning('В параметрах объекта используется IPv6')
            return None
        obj['ip'] = obj_dict['ipv4-address']

    if obj_dict['type'] == 'network':
        if 'subnet6' in obj_dict.keys():
            log.warning('В параметрах объекта используется IPv6')
            return None
        obj['ip'] = f"{obj_dict['subnet4']}/{obj_dict['mask-length4']}"

    if obj_dict['type'] == 'address-range':
        if 'ipv6-address-first' in obj_dict.keys():
            log.warning('В параметрах объекта используется IPv6')
            return None
        obj['ip'] = f"{obj_dict['ipv4-address-first']}-{obj_dict['ipv4-address-last']}"

    if obj['name'] == '':
        obj['name'] = f"{obj['type']}_{obj['ip']}"

    return obj


def process_ServiceGroups(obj_dict, obj):
    obj['type'] = 'group'
    obj['subtype'] = 'service'
    obj['members'] = obj_dict.get('members', [])
    return obj


def process_Services(obj_dict, obj):
    obj['type'] = 'service'
    obj['requires_keep_connections'] = obj_dict.get('keep-connections-open-after-policy-installation', False)

    if obj_dict['type'] in service_types.keys():
        obj['proto'] = service_types.get(obj_dict['type'])
    else:
        obj['proto'] = obj_dict.get('ip-protocol')

    if obj['proto'] in [0, 41, 43, 44, 45, 46, 50, 51, 58, 59, 60]:
        log.warning('В параметрах сервиса используется неподдерживаемый протокол')
        return None

    if obj['proto'] == service_types['service-icmp']:
        obj['icmp_type'] = obj_dict.get('icmp-type', None)
        obj['icmp_code'] = obj_dict.get('icmp-code', None)

    if obj['proto'] in [ service_types['service-tcp'], service_types['service-udp'] ]:
        obj['src'] = obj_dict.get('port', '')
        obj['dst'] = obj_dict.get('port', '')

    if obj['name'] == '':
        obj['name'] = f"{obj['type']}_{obj['proto']}_{obj['src']}"

    return obj


def process_TimeIntervals(obj_dict, obj):
    obj['type'] = 'timeinterval'
    recurrence = obj_dict.get('recurrence', {})

    if not (recurrence.get('month') == 'Any' and \
        recurrence.get('days') == []):
        return None

    days = []
    if recurrence.get('pattern') == 'Daily':
        days = list(day_dict.values())

    if recurrence.get('pattern') == 'Weekly':
        for str_day in recurrence.get('weekdays', []):
            days.append(day_dict.get(str_day))

    if len(days) > 0:
        obj['intervals'] = []
    else:
        return None # pattern == Monthly

    if obj_dict.get('hours-ranges') is None:
        start = 0
        end = 23 * 60 + 59
        for day in days:
            obj['intervals'].append(
                {
                    'day': day,
                    'start': start,
                    'finish': end
                }
            )
    else:
        for day in days:
            for interval in obj_dict.get('hours-ranges'):
                obj['intervals'].append(
                    {
                        'day': day,
                        'start': get_minutes(interval['from']),
                        'finish': get_minutes(interval['to'])
                    }
                )

    if obj['name'] == '':
        first_day_string = ''
        if len(obj['intervals']) > 0:
            day = obj['intervals'][0]
            first_day_string = f"{day['day']}_{day['start']}_{day['finish']}"
        obj['name'] = f"{obj['type']}_{len(days)}_{first_day_string}"

    return obj


def get_minutes(time_str):
    colon_index = time_str.find(':')
    if colon_index >= 0:
        hours = time_str[:colon_index]
        mins = time_str[colon_index + 1:]
        return int(hours) * 60 + int(mins)
    else:
        return int(time_str)


# check key in dict is not None
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


# for members
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


# input - network, range, host ips
# output - list of ipaddress
def get_addresses_from_ip_objects(ips):
    out_list = []
    for addr in ips:

        ip_obj = None
        if '/' in addr:
            ip_obj = list(ipaddress.ip_network(addr, False))
        elif '-' in addr:
            first, last = addr.split('-')
            networks = ipaddress.summarize_address_range(first, last)
            ip_obj = []
            for obj in networks:
                add_to_list(ip_obj, list(obj))
        else:
            ip_obj = ipaddress.ip_address(addr)

        add_to_list(out_list, ip_obj)

    return out_list


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


def main():
    parser = argparse.ArgumentParser(
                formatter_class = argparse.RawTextHelpFormatter,
                prog = f"\n\npython {basename(sys.argv[0])}",
                description = 'Преобразование правил Check Point R80/ R80.X/ R81/ R81.X (Show Package Tool) в Континент 4.',
                epilog = f'''example: python {basename(sys.argv[0])} -i input_objects_file_path.json input_rules_file_path.json -o output_folder_path
                ''',
                add_help = False
            )
    parser.add_argument('-h', '--help', action='help', default=argparse.SUPPRESS, help='Показать текущее сообщение помощи и выйти.')
    parser.add_argument('-i', '--input', help='Пути до файлов с объектами и правилами для преобразования', type=str, nargs=2, required=True)
    parser.add_argument('-o', '--output_path', help='Путь до папки для выходного файла', type=pathlib.Path)
    parser.add_argument('--log', help='Имя файла логирования', type=str)
    parser.add_argument('--name', help='Имя выходного файла', type=str)
    parser.add_argument('--debug', default=False, action="store_true")
    args = parser.parse_args(args=None if sys.argv[1:] else ['--help'])

    if args.debug:
        log.setLevel(logging.DEBUG)

    if len(args.input) != 2:
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
    input_objects = {}
    input_objects2 = {}

    log.info(f'Загрузка {args.input[0]}')
    with open(args.input[0], 'r', encoding="utf8") as f:
        try:
            input_objects = json.load(f)
        except json.decoder.JSONDecodeError as e:
            log.error(e)
            log.error('')
            f.seek(0)
            for i in range(e.lineno + 5):
                if i > e.lineno - 5:
                    log.error(f"{i+1}: {f.readline().rstrip()}")
                else:
                    next(f)
            log.error('')
            return
    log.info(f'Загрузка завершена')

    log.info(f'Загрузка {args.input[1]}')
    with open(args.input[1], 'r', encoding="utf8") as f:
        try:
            input_objects2 = json.load(f)
        except json.decoder.JSONDecodeError as e:
            log.error(e)
            log.error('')
            f.seek(0)
            for i in range(e.lineno + 5):
                if i > e.lineno - 5:
                    log.error(f"{i+1}: {f.readline().rstrip()}")
                else:
                    next(f)
            log.error('')
            return

        add_to_list(input_objects, input_objects2)
        del input_objects2
    log.info(f'Загрузка завершена')

    data = parse_rules(input_objects)
    objects = parse_objects(input_objects)

    # Добавление объектов в группы
    def fill_group(objects, group, section_name):
        members = group.get(section_name, [])
        if len(members) == 0:
            return group
        # Уже заполнена
        if type(members[0]) is dict:
            return group

        filled_section = []
        for object_id in members:
            for obj in objects:
                if obj['id'] == object_id:
                    if obj['type'] == group['subtype']:
                        filled_section.append(obj)
                    elif obj['type'] == group['type'] and obj['subtype'] == group['subtype']:
                        filled_section.append(fill_group(objects, obj, section_name))

        if group['name'] == '':
            first_member_name = ''
            if len(filled_section) > 0:
                first_member_name = filled_section[0].get('name')
            group['name'] = f"{group['subtype']}-group_{len(group['members'])}{first_member_name}"

        group[section_name] = filled_section
        return group

    for group in objects:
        if group['type'] == 'group':
            fill_group(objects, group, 'members')


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
                            filled_section.append(obj)

                rule[section] = filled_section

    # В правиле может быть только один сервис, поэтому размножаем правила
    single_service_rules = []
    for rule in data:
        services = rule.get('service', [])
        if rule['__internal_type'] == 'NatRules' and len(services) > 1:
            for service in services:
                copied_rule = copy.deepcopy(rule)
                service_name = service['name'] if 'name' in service.keys() else ""
                copied_rule['name'] = f"{rule['name']}_{service_name}"
                copied_rule['service'] = [service]
                single_service_rules.append(copied_rule)
        else:
            single_service_rules.append(rule)
    data = single_service_rules

    # Дозаполнение action и logging в правилах fw
    k4_actions = {
        'accept': 'pass',
        'drop': 'block',
        'reject': 'block',
    }
    k4_logging = {
        'Alert': True,
        'Log': True,
        'Account': False,
        'None': False,
    }
    actions = {}
    for obj in input_objects:
        if obj.get('type') in ['RulebaseAction', 'Global']:
            actions[obj['uid']] = obj.get('name')

    track_types = {}
    for obj in input_objects:
        if obj.get('type') == 'Track':
            track_types[obj['uid']] = obj.get('name')

    log.debug("actions: ")
    log.debug(actions)
    log.debug("track_types: ")
    log.debug(track_types)

    out_rules = []
    for rule in data:
        if rule['__internal_type'] == 'FilterRules':
            action = actions.get(rule['rule_action'], 'Drop').lower()
            track = track_types.get(rule['logging'])

            if track == 'Account' or not action in k4_actions.keys():
                error_counter['FilterRules']['done'] -= 1
                error_counter['FilterRules']['warning'] += 1
                log.warning("Предупреждение track = Account или неподдерживаемое действие в правиле fw:")
                log.warning(rule)
                continue

            rule['rule_action'] = k4_actions.get(action, None)
            rule['logging'] = k4_logging.get(track, False)

        out_rules.append(rule)

    del data
    data = out_rules

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
                log.warning('Ошибка - не удалось определить тип в правиле NAT')
                error_counter['NatRules']['error'] += 1
                continue

            # сервисы могут быть только TCP или UDP
            for services in ['service_translated', 'service']:
                for service in rule[services]:
                    if 'proto' in service.keys():
                        if not service['proto'] in [ service_types['service-tcp'],
                                                     service_types['service-udp'] ]:
                            error_counter['NatRules']['error'] += 1
                            log.warning('Ошибка - сервис в правиле NAT может быть только TCP или UDP')
                            continue

            if rule['nat_type'] == 'dynamic':
                rule['address_type'] = 'netobject'
                rule['value'] = rule['src_translated']
                for port_value in rule['port_value']:
                    port_value['dst'] = ''
            elif rule['nat_type'] == 'dnat':
                rule['address_type'] = 'netobject'
                rule['value'] = rule['dst_translated']
                for port_value in rule['port_value']:
                    port_value['src'] = ''
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
    print_report(path, data, [*section_dict], members_sections)
    description_check(data, members_sections)

    # Разделение на правила FW и NAT
    fw_rules = []
    nat_rules = []
    for rule in data:
        if rule['__internal_type'] == 'FilterRules':
            fw_rules.append(rule)
        else:
            nat_rules.append(rule)

    del data

    # Удаление служебных полей
    if not args.debug:
        service_fields = [
            '__internal_type',
            'id',
            'original_name',
            'original_description',
            '__translation_port'
        ]
        remove_fields(fw_rules, service_fields, members_sections)
        remove_fields(nat_rules, service_fields, members_sections)

    def write_outdata(data, filename):
        if filename.exists():
            log.info("Выходной файл найден, перезапись")
        with open(filename, "w", encoding="utf8") as f:
            json.dump(data, f, indent=4, ensure_ascii=False)
        log.info(f"Записан файл: {filename}")

    prefix = args.name if args.name else 'import'
    if len(fw_rules) > 0:
        filename = path / OUTPUT_FILENAME.format(prefix, pathlib.Path(args.input[0]).stem, 'fw')
        write_outdata(fw_rules, filename)

    if len(nat_rules) > 0:
        filename = path / OUTPUT_FILENAME.format(prefix, pathlib.Path(args.input[0]).stem, 'nat')
        write_outdata(nat_rules, filename)

    print_stats()

if __name__ == '__main__':
    main()
