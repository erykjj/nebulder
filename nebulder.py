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
VERSION = 'v0.1.1'


import argparse, os, re, yaml
from copy import deepcopy
from pathlib import Path
from subprocess import run, PIPE


def process_config(config, path):

    def cert_date(path):
        arguments = ['nebula-cert', 'print', '-path', path]
        cert = run(arguments, stdout=PIPE)
        return re.search(r'Not After: (.*)', cert.stdout.decode(), re.MULTILINE).group(1) or 'ERROR in reading CERT file'

    def certificate_authority():
        print(f"Generating certificate authority for '{mesh['tun_device']}'")
        if os.path.isfile(root_path + 'ca.crt') or os.path.isfile(root_path + 'ca.key'):
            print(f"   Key already exists - expires: {cert_date(root_path + 'ca.crt')}\n   Skipping key generation")
            return False
        else:
            run(['nebula-cert', 'ca', '-name', mesh['tun_device'], '-out-crt', root_path + 'ca.crt', '-out-key', root_path + 'ca.key'])
            run(['nebula-cert', 'print', '-path', root_path + 'ca.crt', '-out-qr', root_path + 'ca.qr'], stdout=PIPE)
            print(f"   Certificate expires: {cert_date( root_path + 'ca.crt')}")
            return True

    def generate_certs(path, device):
        print(f"\nProcessing device '{device['name']}'")
        os.makedirs(path, exist_ok=True)
        with open(path + f"deploy_{device['name']}.sh", 'w', encoding='UTF-8') as f:
            f.write(deploy)
        with open(path + f"remove_{device['name']}.sh", 'w', encoding='UTF-8') as f:
            f.write(remove)
        run(['cp', root_path + f"nebula_{mesh['tun_device']}.service", path])
        run(['cp', root_path + 'ca.crt', path])
        run(['cp', root_path + 'ca.qr', path])
        if os.path.isfile(path + 'host.crt') or os.path.isfile(path + 'host.key'):
            if is_new:
                os.remove(path + 'host.crt')
                os.remove(path + 'host.key')
            else:
                print(f"   Certificate already exists - expires: {cert_date( path + 'host.crt')}\n   Skipping key generation\n   Added config.yaml")
                return
        arguments = ['nebula-cert', 'sign', '-name', device['name'], '-out-crt', path + 'host.crt', '-out-key', path + 'host.key', '-ca-crt', root_path + 'ca.crt', '-ca-key', root_path + 'ca.key', '-ip', f"{device['nebula_ip']}/24"]
        if 'groups' in device.keys():
            arguments.append('-groups')
            arguments.append(','.join(device['groups']))
        run(arguments)
        run(['nebula-cert', 'print', '-path', path + 'host.crt', '-out-qr', path + 'host.qr'], stdout=PIPE)
        print(f"   Added config.yaml and key files\n   Certificate expires: {cert_date( path + 'host.crt')}")


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
                        'cert': f"/etc/nebula/{mesh['tun_device']}/host.crt",
                        'key': f"/etc/nebula/{mesh['tun_device']}/host.key" }
        conf['tun'] = { 'dev': mesh['tun_device'] }
        if 'preferred_ranges' in node.keys():
            conf['preferred_ranges'] = node['preferred_ranges']
        if 'inbound_firewall' in node.keys():
            conf['firewall']['inbound'] += process_firewall(node['inbound_firewall'])

    def process_lighthouses():
        if 'lighthouses' not in mesh.keys():
            print('*** ERROR: No lighthouse defined!!\n')
            exit()
        for lighthouse in mesh['lighthouses']:
            path = root_path + 'lighthouse_' + lighthouse['name'] + '/'
            generate_certs(path, lighthouse)
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
            with open(path + 'config.yaml', 'w', encoding='UTF-8') as f:
                f.write(f"# Nebula config for lighthouse '{lighthouse['name']}' on '{mesh['tun_device']}' network device: {lighthouse['nebula_ip']}\n\n")
                yaml.dump(conf, f, Dumper=yaml.dumper.SafeDumper, indent=2, sort_keys=False)

    def process_nodes():
        if 'nodes' not in mesh.keys():
            print('*** No standard nodes defined! ***')
            return
        for node in mesh['nodes']:
            path = root_path  + 'node_' + node['name'] + '/'
            generate_certs(path, node)
            conf = deepcopy(base)
            add_common(node, conf)
            conf['static_host_map'] = {}
            for host in relays.keys():
                conf['static_host_map'][host] = list(relays[host])
            conf['lighthouse'] = { 'hosts': list(ips) }
            if 'advertise_addrs' in node.keys():
                conf['lighthouse']['advertise_addrs'] = f"{node['advertise_addrs']}:0"
            conf['relay'] = { 'relays': ips }
            with open(path + 'config.yaml', 'w', encoding='UTF-8') as f:
                f.write(f"# Nebula config for node '{node['name']}' on '{mesh['tun_device']}' network device: {node['nebula_ip']}\n\n")
                yaml.dump(conf, f, Dumper=yaml.dumper.SafeDumper, indent=2, sort_keys=False)


    res_path = str(Path(__file__).resolve().parent) + '/res/'
    with open(res_path + 'config.yaml') as f:
        base = yaml.load(f, Loader=yaml.loader.SafeLoader)
    with open(config) as f:
        mesh = yaml.load(f, Loader=yaml.loader.SafeLoader)

    root_path = path + '/' + mesh['tun_device'] + '/'
    os.makedirs(root_path, exist_ok=True)
    with open(res_path + 'nebula.service') as f:
        txt = f.read()
    with open(root_path + f"nebula_{mesh['tun_device']}.service", 'w', encoding='UTF-8') as f:
        f.write(re.sub('@@tun_device@@', mesh['tun_device'], txt, re.MULTILINE))

    with open(res_path + 'deploy.sh') as f:
        txt = re.sub('@@tun_device@@', mesh['tun_device'], f.read(), re.MULTILINE)
    deploy = re.sub(r'@@tun_device@@', mesh['tun_device'], txt, re.MULTILINE)
    with open(res_path + 'remove.sh') as f:
        txt = re.sub('@@tun_device@@', mesh['tun_device'], f.read(), re.MULTILINE)
    remove = re.sub(r'@@tun_device@@', mesh['tun_device'], txt, re.MULTILINE)

    is_new = certificate_authority()
    relays = {}
    ips = []
    process_lighthouses()
    process_nodes()
    run(['rm', root_path + f"nebula_{mesh['tun_device']}.service"])
    print(f'\nCompleted successfully\n   See output in {root_path}\n')


parser = argparse.ArgumentParser(description="Generate Nebula configs based on a network outline")
parser.add_argument('-v', '--version', action='version', version=f"{APP} {VERSION}")
parser.add_argument("Outline", help='Network outline (YAML format)')
parser.add_argument('-o', metavar='directory', help='Output directory (defaults to dir where Outline is located)')
args = vars(parser.parse_args())
if args['o']:
    path = args['o'].rstrip('/')
else:
    path = str(Path(args['Outline']).resolve().parent)
process_config(args['Outline'], path)
