#!/usr/bin/env python3

"""
  File:           nebulder.py

  Description:    Generate Nebula configs based on a network outline

  MIT License:    Copyright (c) 2023 Eryk J.

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
VERSION = 'v0.1.0'


import argparse, os, re, yaml
from copy import deepcopy
from pathlib import Path
from subprocess import run, PIPE


def process_config(config, dir):

    def cert_date(path):
        arguments = ['nebula-cert', 'print', '-path', path]
        cert = run(arguments, stdout=PIPE)
        return re.search(r'Not After: (.*)', cert.stdout.decode(), re.MULTILINE).group(1) or 'ERROR in reading CERT file'

    def generate_certs(path, device):
        print(f"\nProcessing device '{device['name']}'")
        if os.path.isfile(path + '/host.crt') or os.path.isfile(path + '/host.key'):
            if new_cert:
                os.remove(path + '/host.crt')
                os.remove(path + '/host.key')
            else:
                print(f"   Certificate already exists - expires: {cert_date( path + '/host.crt')}\n   Skipping key generation\n   Added config.yaml")
                return
        os.makedirs(path, exist_ok=True)
        arguments = ['nebula-cert', 'sign', '-name', device['name'], '-out-crt', path + '/host.crt', '-out-key', path + '/host.key', '-ca-crt', f'{dir}/ca.crt', '-ca-key', f'{dir}/ca.key', '-ip', f"{device['nebula_ip']}/32"]
        if 'groups' in device.keys():
            arguments.append('-groups')
            arguments.append(','.join(device['groups']))
        run(arguments)
        run(['cp', f'{dir}/ca.crt', path])
        print(f"   Added config.yaml and key files\n   Certificate expires: {cert_date( path + '/host.crt')}")

    def add_common(node, conf):

        def process_firewall(firewall):
            processed = []
            inbound = {}
            for rules in firewall:
                for rule, hosts in rules.items():
                    res = re.search(r'(\d+)(?:/([a-zA-Z]+))?', rule)
                    if res:
                        inbound = { 'port': int(res.group(1)) }
                        if res.group(2):
                            proto = res.group(2)
                        else:
                            proto = 'any'
                        inbound['proto'] = proto
                        if hosts == 'any':
                            inbound['host'] = 'any'
                        elif len(hosts) == 1:
                            inbound['group'] = hosts[0]
                        else:
                            inbound['groups'] = hosts
                        processed.append(inbound)
            return processed

        conf['pki'] = { 'ca': f"/etc/nebula/{mesh['tun_device']}/ca.crt",
                        'cert': f"/etc/nebula/{mesh['tun_device']}/host.crt'",
                        'key': f"/etc/nebula/{mesh['tun_device']}/host.key'" }
        conf['tun'] = { 'dev': mesh['tun_device'] }
        if 'preferred_ranges' in node.keys():
            conf['preferred_ranges'] = node['preferred_ranges']
        if 'inbound_firewall' in node.keys():
            conf['firewall']['inbound'] += process_firewall(node['inbound_firewall'])

    def process_lighthouses():
        if 'lighthouses' not in mesh.keys():
            print('*** No lighthouse defined!! ***')
            exit()
        for lighthouse in mesh['lighthouses']:
            generate_certs(dir + f"/lighthouse_{lighthouse['name']}", lighthouse)
            ips.append(lighthouse['nebula_ip'])
            conf = deepcopy(base)
            add_common(lighthouse, conf)
            conf['listen'] = { 'port': lighthouse['listen_port'] }
            conf['lighthouse'] = { 'am_lighthouse': True }
            conf['relay'] = { 'am_relay': True, 'use_relays': False }
            host_map = []
            for ip in lighthouse['public_ip']:
                host_map.append(ip)
            relays[lighthouse['nebula_ip']] = host_map
            with open(f"{dir}/lighthouse_{lighthouse['name']}/config.yaml", 'w', encoding='UTF-8') as f:
                f.write(f"# Nebula config for lighthouse '{lighthouse['name']}' on '{mesh['tun_device']}' network: {lighthouse['nebula_ip']}\n\n")
                yaml.dump(conf, f, Dumper=yaml.dumper.SafeDumper, indent=2, sort_keys=False)

    def process_nodes():
        if 'nodes' not in mesh.keys():
            print('*** No standard nodes defined! ***')
            return
        for node in mesh['nodes']:
            generate_certs(dir + f"/node_{node['name']}", node)
            conf = deepcopy(base)
            add_common(node, conf)
            conf['static_host_map'] = {}
            for host in relays.keys():
                conf['static_host_map'][host] = list(relays[host])
            conf['lighthouse'] = { 'hosts': list(ips) }
            if 'advertise_addrs' in node.keys():
                conf['lighthouse']['advertise_addrs'] = f"{node['advertise_addrs']}:0"
            conf['relay'] = { 'relays': ips }
            with open(f"{dir}/node_{node['name']}/config.yaml", 'w', encoding='UTF-8') as f:
                f.write(f"# Nebula config for node '{node['name']}' on '{mesh['tun_device']}' network: {node['nebula_ip']}\n\n")
                yaml.dump(conf, f, Dumper=yaml.dumper.SafeDumper, indent=2, sort_keys=False)

    with open(Path(__file__).resolve().parent / 'res/config.yaml') as f:
        base = yaml.load(f, Loader=yaml.loader.SafeLoader)
    with open(config) as f:
        mesh = yaml.load(f, Loader=yaml.loader.SafeLoader)

    dir += '/' + mesh['tun_device']
    os.makedirs(dir, exist_ok=True)

    print(f"Generating certificate authority for '{mesh['tun_device']}'")
    if os.path.isfile(f'{dir}/ca.crt') or os.path.isfile(f'{dir}/ca.key'):
        print(f"   Key already exists - expires: {cert_date(dir + '/ca.crt')}\n   Skipping key generation")
        new_cert = False
    else:
        run(['nebula-cert', 'ca', '-name', mesh['tun_device'], '-out-crt', f'{dir}/ca.crt', '-out-key', f'{dir}/ca.key'])
        new_cert = True

    relays = {}
    ips = []
    process_lighthouses()
    process_nodes()
    print(f'\nCompleted successfully. See output in {dir}\n')


parser = argparse.ArgumentParser(description="Generate Nebula configs based on a network outline")
parser.add_argument('-v', '--version', action='version', version=f"{APP} {VERSION}")
parser.add_argument("Outline", help='Network outline (YAML format)')
parser.add_argument('-o', metavar='directory', help='Output directory (defaults to dir where Outline is located)')
args = vars(parser.parse_args())
if args['o']:
    dir = args['o'].rstrip('/')
else:
    dir = str(Path(args['Outline']).resolve().parent)
process_config(args['Outline'], dir)
