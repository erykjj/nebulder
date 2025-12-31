#!/usr/bin/env python3

"""
  File:           nebulder.py

  Description:    Generate Nebula configs based on a network outline

  MIT License:    Copyright (c) 2026 Eryk J.

  Permission is hereby granted, free of charge, to any person obtaining a copy
  of this software and associated documentation files (the "Software"), to deal
  in the Software without restriction, including without limitation the rights
  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  copies of the Software, and to permit persons to whom the Software is
  furnished to do so, subject to the following conditions:

  The above copyright notice and this permission notice shall be included in all
  copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
  SOFTWARE.
"""

APP = 'nebulder'
VERSION = 'v2.0.0'


import argparse, ipaddress, json, re, shutil, yaml
from copy import deepcopy
from pathlib import Path
from subprocess import run, PIPE
from zipfile import ZipFile, ZIP_DEFLATED


def get_version(path):
    version_file = path / 'version.txt'
    if not version_file.exists():
        return 'v1.0.0'
    current = version_file.read_text().strip()
    match = re.match(r'v?(\d+)\.(\d+)\.(\d+)', current)
    if not match:
        return 'v1.0.0'
    major, minor, patch = map(int, match.groups())
    patch += 1
    return f'v{major}.{minor}.{patch}'

def cert_date(cert_path):
    arguments = ['nebula-cert', 'print', '-path', str(cert_path)]
    cert = run(arguments, stdout=PIPE, check=True)
    cert_data = json.loads(cert.stdout)
    not_after = cert_data['details']['notAfter']
    return not_after

def generate_certificate_authority():
    ca_crt = conf_path / f"{mesh['tun_device']}_ca.crt"
    ca_key = conf_path / f"{mesh['tun_device']}_ca.private.key"
    print(f"Certificate authority for '{mesh['tun_device']}'")
    if ca_crt.exists() and ca_key.exists():
        print(f'   Key already exists - expires: {cert_date(ca_crt)}\n   Skipping key generation')
        return False
    else:
        run(['nebula-cert', 'ca', '-name', mesh['tun_device'], 
             '-out-crt', str(ca_crt), 
             '-out-key', str(ca_key)], check=True)
        ca_qr = conf_path / f"{mesh['tun_device']}_ca.qr"
        run(['nebula-cert', 'print', '-path', str(ca_crt),
             '-out-qr', str(ca_qr)], stdout=PIPE, check=True)
        print(f'   Certificate expires: {cert_date(ca_crt)}')
        return True

def copy_files(dest_path, device, op_sys, lighthouse=False):
    if lighthouse:
        d = 'lighthouse'
    else:
        d = 'node'
    print(f"\nProcessing {d} '{device['name']}' ({op_sys})")
    dest_path.mkdir(exist_ok=True)
    update_conf = conf_path / 'update.conf'
    if update_conf.exists():
        shutil.copy(str(update_conf), str(dest_path))
    if op_sys == 'linux':
        for script_name in ['deploy.sh', 'remove.sh', 'update.sh']:
            script_path = dest_path / script_name
            script_path.write_text(scripts[script_name])
        for service in ['nebula.service', 'nebula-update.service', 'nebula-update.timer']:
            renamed = re.sub('nebula', f"nebula_{mesh['tun_device']}", service)
            service_path = dest_path / renamed
            service_path.write_text(scripts[service])
    elif op_sys == 'android' or op_sys == 'ios':
        ca_qr_src = conf_path / f"{mesh['tun_device']}_ca.qr"
        ca_qr_dest = dest_path / 'ca.qr'
        shutil.copy(str(ca_qr_src), str(ca_qr_dest))
    elif op_sys == 'macos':
        for script_name in ['deploy-mac.sh', 'remove-mac.sh', 'update-mac.sh']:
            renamed = re.sub('-mac', '', script_name)
            script_path = dest_path / renamed
            script_path.write_text(scripts[script_name])
        for service in ['nebula.plist', 'nebula-update.plist']:
            renamed = re.sub('nebula', f"nebula_{mesh['tun_device']}", service)
            service_path = dest_path / renamed
            service_path.write_text(scripts[service])
    else:
        for script_name in ['update.bat', 'deploy.ps1', 'update.ps1', 'remove.ps1']:
            script_path = dest_path / script_name
            script_path.write_text(scripts[script_name])
    ca_crt_src = conf_path / f"{mesh['tun_device']}_ca.crt"
    ca_crt_dest = dest_path / 'ca.crt'
    shutil.copy(str(ca_crt_src), str(ca_crt_dest))
    host_crt = dest_path / 'host.crt'
    host_key = dest_path / 'host.key'
    if host_crt.exists() or host_key.exists():
        if is_new:
            host_crt.unlink(missing_ok=True)
            host_key.unlink(missing_ok=True)
        else:
            print(f'   Certificate already exists - expires: {cert_date(host_crt)}\n   Skipping key generation\n   Added config.yaml')
            return
    ca_crt_path = conf_path / f"{mesh['tun_device']}_ca.crt"
    ca_key_path = conf_path / f"{mesh['tun_device']}_ca.private.key"
    arguments = ['nebula-cert', 'sign', '-name', device['name'],
                 '-out-crt', str(host_crt), '-out-key', str(host_key),
                 '-ca-crt', str(ca_crt_path), '-ca-key', str(ca_key_path),
                 '-ip', f"{device['nebula_ip']}/24"]
    if 'groups' in device:
        arguments.extend(['-groups', ','.join(device['groups'])])
    run(arguments, check=True)
    if op_sys in ['linux', 'windows', 'macos']:
        run(['nebula-cert', 'print', '-path', str(host_crt)], stdout=PIPE, check=True)
    else:
        host_qr = dest_path / 'host.qr'
        run(['nebula-cert', 'print', '-path', str(host_crt), '-out-qr', str(host_qr)], 
            stdout=PIPE, check=True)
    print(f'   Added config.yaml and key files\n   Certificate expires: {cert_date(host_crt)}')

def zip_package(archive_name):
    package_path = root_path / archive_name
    version_file = package_path / 'version'
    version_file.write_text(args['V'] + '\n')
    if not args['z']:
        return
    zip_path = root_path / f"{archive_name}_{args['V']}.zip"
    with ZipFile(zip_path, 'w', compression=ZIP_DEFLATED) as zip_file:
        for file_path in package_path.rglob('*'):
            if file_path.is_file():
                arcname = file_path.relative_to(package_path)
                zip_file.write(str(file_path), str(arcname))

def process_firewall(firewall_rules):
    processed = []
    for rules in firewall_rules:
        for rule, hosts in rules.items():
            res = re.search(r'(\d+)(?:/([a-zA-Z]+))?', rule)
            if not res:
                continue
            inbound = {'port': int(res.group(1))}
            inbound['proto'] = res.group(2) if res.group(2) else 'any'
            if hosts == 'any':
                inbound['host'] = 'any'
            elif len(hosts) == 1:
                inbound['group'] = hosts[0]
            else:
                inbound['groups'] = hosts
            processed.append(inbound)
    return processed

def add_common_config(node, base_config):
    if node.get('os') == 'windows':
        p = r'C:\\nebula\\' + mesh['tun_device'] + r'\\'
    elif node.get('os') == 'macos':
        p = f"/usr/local/etc/nebula/{mesh['tun_device']}/"
    else:
        p = f"/etc/nebula/{mesh['tun_device']}/"
    base_config['pki'] = {
        'ca': p + 'ca.crt',
        'cert': p + 'host.crt',
        'key': p + 'host.key'
    }
    base_config['tun'] = {'dev': mesh['tun_device']}
    if 'preferred_ranges' in node:
        base_config['preferred_ranges'] = node['preferred_ranges']
    if 'inbound_firewall' in node:
        inbound_rules = process_firewall(node['inbound_firewall'])
        base_config['firewall']['inbound'] += inbound_rules
    return base_config

def create_device_config(dest_path, device_type, device_name, op_sys, device_ip, config_data):
    config_file = dest_path / 'config.yaml'
    if device_type == 'lighthouse':
        description = f"lighthouse '{device_name}'"
    else:
        description = f"node '{device_name}'"
    header = f"# Nebula config for {op_sys} {description} on '{mesh['tun_device']}' mesh network device with IP {device_ip}\n\n"
    config_file.write_text(header)
    with config_file.open('a') as f:
        yaml.dump(config_data, f, Dumper=yaml.dumper.SafeDumper, indent=2, sort_keys=False)

def process_lighthouses():
    if 'lighthouses' not in mesh:
        print('*** ERROR: No lighthouse defined!\n')
        exit()
    for i, lighthouse in enumerate(mesh['lighthouses']):
        if 'name' not in lighthouse:
            print(f"*** ERROR: Lighthouse {i+1} missing 'name' field!\n")
            exit()
        if 'nebula_ip' not in lighthouse:
            print(f"*** ERROR: Lighthouse '{lighthouse['name']}' missing 'nebula_ip' field!\n")
            exit()
        if 'public_ip' not in lighthouse:
            print(f"*** ERROR: Lighthouse '{lighthouse['name']}' missing 'public_ip' field!\n")
            exit()
        if 'listen_port' not in lighthouse:
            print(f"*** ERROR: Lighthouse '{lighthouse['name']}' missing 'listen_port' field!\n")
            exit()
    for lighthouse in mesh['lighthouses']:
        host_map = []
        for ip in lighthouse['public_ip']:
            if ':' not in ip:
                ip += f":{lighthouse['listen_port']}"
            host_map.append(ip)
        relays[lighthouse['nebula_ip']] = host_map
    for lighthouse in mesh['lighthouses']:
        path = root_path / f"lighthouse_{lighthouse['name']}"
        op_sys = lighthouse.get('os', 'linux')
        copy_files(path, lighthouse, op_sys, True)
        lighthouse_ips.append(lighthouse['nebula_ip'])
        conf = deepcopy(base_config)
        conf = add_common_config(lighthouse, conf)
        conf['listen'] = {'port': lighthouse['listen_port']}
        conf['lighthouse'] = {'am_lighthouse': True}
        conf['relay'] = {'am_relay': True, 'use_relays': False}
        conf['static_host_map'] = {}
        for host in relays:
            if host == lighthouse['nebula_ip']:
                continue
            conf['static_host_map'][host] = list(relays[host])
        node_file = path / 'node'
        node_file.write_text(f"lighthouse_{lighthouse['name']}")
        create_device_config(
            path, 'lighthouse', lighthouse['name'], op_sys, lighthouse['nebula_ip'], conf
        )
        zip_package(f"lighthouse_{lighthouse['name']}")

def process_nodes():
    if 'nodes' not in mesh:
        print('*** No standard nodes defined! ***')
        return
    for i, node in enumerate(mesh['nodes']):
        if 'name' not in node:
            print(f"*** ERROR: Node {i+1} missing 'name' field!\n")
            exit()
        if 'nebula_ip' not in node:
            print(f"*** ERROR: Node '{node['name']}' missing 'nebula_ip' field!\n")
            exit()
    for node in mesh['nodes']:
        path = root_path / f"node_{node['name']}"
        op_sys = node.get('os', 'linux')
        copy_files(path, node, op_sys)
        conf = deepcopy(base_config)
        conf = add_common_config(node, conf)
        conf['static_host_map'] = {}
        for host in relays:
            conf['static_host_map'][host] = list(relays[host])
        conf['lighthouse'] = {'hosts': list(lighthouse_ips)}
        if 'advertise_addrs' in node:
            conf['lighthouse']['advertise_addrs'] = f"{node['advertise_addrs']}:0"
        conf['relay'] = {'relays': lighthouse_ips}
        node_file = path / 'node'
        node_file.write_text(f"node_{node['name']}")
        create_device_config(
            path, 'node', node['name'], op_sys, node['nebula_ip'], conf
        )
        zip_package(f"node_{node['name']}")

def load_resources():
    res_path = Path(__file__).resolve().parent / 'res'
    base_config_path = res_path / 'config.yaml'
    with base_config_path.open() as f:
        base_config = yaml.load(f, Loader=yaml.loader.SafeLoader)
    scripts_dict = {}
    scripts_dir = res_path / 'scripts'
    for script_file in scripts_dir.iterdir():
        with script_file.open() as f:
            scripts_dict[script_file.name] = f.read()
    return base_config, scripts_dict

def validate_names_and_ips(mesh):

    def validate_device_name(name, device_type):
        if not name:
            print(f"*** ERROR: {device_type} missing 'name' field!")
            exit(1)
        if not re.match(r'^[a-zA-Z0-9_\-]+$', name):
            print(f"*** ERROR: Invalid {device_type} name '{name}'!")
            print('   Must contain only letters, numbers, hyphens, and underscores')
            exit(1)
        if name in used_names:
            print(f"*** ERROR: Duplicate name '{name}'!")
            print('   All device names must be unique')
            exit(1)
        used_names.add(name)
        return name
    
    def process_device(device, device_type, index):
        device_name = validate_device_name(device.get('name'), f'{device_type} {index}')
        nebula_ip = device.get('nebula_ip')
        if not nebula_ip:
            print(f"*** ERROR: {device_type} '{device_name}' missing 'nebula_ip'!")
            exit(1)
        try:
            ip_obj = ipaddress.IPv4Address(nebula_ip)
            if not ip_obj.is_private:
                print(f"*** ERROR: {device_type} '{device_name}' IP '{nebula_ip}' is not a private IP!")
                print('   Must be in ranges: 10.0.0.0/8, 172.16.0.0/12, or 192.168.0.0/16')
                exit(1)
            last_octet = int(nebula_ip.split('.')[-1])
            if last_octet == 0 or last_octet == 255:
                print(f"*** ERROR: {device_type} '{device_name}' IP '{nebula_ip}' may be network or broadcast address!")
                print('   Avoid .0 or .255 as last octet for /24 networks')
                exit(1)
            return device_name, nebula_ip, ipaddress.IPv4Network(f'{nebula_ip}/24', strict=False)
        except (ipaddress.AddressValueError, ValueError) as e:
            print(f"*** ERROR: {device_type} '{device_name}' has invalid IP '{nebula_ip}': {e}")
            exit(1)

    tun_device = mesh.get('tun_device')
    if not tun_device:
        print("*** ERROR: Missing 'tun_device' in mesh configuration!")
        exit(1)
    if not re.match(r'^[a-zA-Z0-9_\-]+$', tun_device):
        print(f"*** ERROR: Invalid tun_device name '{tun_device}'!")
        print('   Must contain only letters, numbers, hyphens, and underscores')
        exit(1)
    if tun_device.startswith('-') or tun_device.endswith('-'):
        print(f"*** ERROR: Invalid tun_device name '{tun_device}'!")
        print('   Cannot start or end with hyphen')
        exit(1)
    used_names = set()
    all_ips = []
    networks = []
    if 'lighthouses' not in mesh or not mesh['lighthouses']:
        print('*** ERROR: At least one lighthouse is required!')
        exit(1)
    for i, lighthouse in enumerate(mesh['lighthouses']):
        _, ip, network = process_device(lighthouse, 'Lighthouse', i+1)
        all_ips.append(ip)
        networks.append(network)
    if 'nodes' in mesh:
        for i, node in enumerate(mesh['nodes']):
            _, ip, network = process_device(node, 'Node', i+1)
            all_ips.append(ip)
            networks.append(network)
    if len(set(all_ips)) != len(all_ips):
        print('*** ERROR: Duplicate IP addresses found!')
        print('   All devices must have unique IP addresses')
        exit(1)
    network_base = networks[0] if networks else None
    for i, network in enumerate(networks):
        if network != network_base:
            device_type = 'Lighthouse' if i < len(mesh['lighthouses']) else 'Node'
            index = i+1 if i < len(mesh['lighthouses']) else i - len(mesh['lighthouses']) + 1
            print(f"*** ERROR: {device_type} {index} IP is not in the same /24 network!")
            print(f'   All devices must be in {network_base} network')
            exit(1)
    return tun_device, network_base, all_ips

def process_config(config_path, output_dir):
    global mesh, root_path, conf_path, base_config, scripts, is_new, relays, lighthouse_ips
    with open(config_path) as f:
        mesh = yaml.load(f, Loader=yaml.loader.SafeLoader)
    tun_device, network_base, all_ips = validate_names_and_ips(mesh)
    root_path = Path(output_dir) / mesh['tun_device']
    conf_path = Path(output_dir)
    root_path.mkdir(exist_ok=True)
    print()
    print('='*75)
    print('nebulder - a builder script for Nebula mesh networks')
    print('='*75)
    print(f'\nMesh network: {tun_device}')
    print(f'IP network: {network_base}')
    print(f'Total devices: {len(all_ips)}\n')
    if not args['V']:
        args['V'] = get_version(root_path)
    version_file = root_path / 'version.txt'
    version_file.write_text(args['V'] + '\n')
    base_config, scripts_dict = load_resources()
    for script_name in scripts_dict:
        scripts_dict[script_name] = scripts_dict[script_name].replace('@@tun_device@@', mesh['tun_device'])
    scripts = scripts_dict
    is_new = generate_certificate_authority()
    relays = {}
    lighthouse_ips = []
    process_lighthouses()
    process_nodes()
    print(f'\nCompleted successfully\n   See output in {root_path}')
    print('='*75)
    print()


parser = argparse.ArgumentParser(description='Generate Nebula configs based on a network outline')
parser.add_argument('-v', '--version', action='version', version=f'{APP} {VERSION}')
parser.add_argument('Outline', help='Network outline (YAML format)')
parser.add_argument('-o', metavar='directory', help='Output directory (defaults to dir where Outline is located)')
parser.add_argument('-z', action='store_true', help='Zip packages')
parser.add_argument('-V', metavar='id', help='Config version number or id (optional)')
args = vars(parser.parse_args())
if args['o']:
    output_path = Path(args['o'].rstrip('/'))
else:
    output_path = Path(args['Outline']).resolve().parent
process_config(args['Outline'], output_path)
