#!/usr/bin/env python3

"""
  File:           nebulder

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
VERSION = 'v0.0.2'


import argparse, os, subprocess, yaml
from pathlib import Path


def sh(command, arguments='', inp=''):
    res = subprocess.run([command, arguments], stdout=subprocess.PIPE, stderr=subprocess.PIPE, input=inp.encode('utf-8'))
    if res.stderr.decode('utf-8'):
        print(res.stderr.decode('utf-8'))
        exit()
    return res.stdout.decode('utf-8')


def create_deploy_script(name, port):
    if port:
        note = f'echo "You may need to add a rule to your firewall to allow traffic to the WireGuard interface\'s port:"\necho "sudo ufw allow {port}/udp"\necho "sudo ufw reload"\n\n'
    else:
        note = ''
    return f'#!/bin/bash\n\nsystemctl stop wg-quick@{name}\nsystemctl disable wg-quick@{name}\n\ncp --remove-destination {name}.conf /etc/wireguard/\nchown root:root /etc/wireguard/{name}.conf\nchmod 600 /etc/wireguard/{name}.conf\n\nsystemctl enable wg-quick@{name}\nsystemctl start wg-quick@{name}\n\nwg show {name}\n\n{note}exit 0'

def create_remove_script(name):
    return f'#!/bin/bash\n\nsystemctl stop wg-quick@{name}\nsystemctl disable wg-quick@{name}\n\nrm /etc/wireguard/{name}.conf\n\nwg show\n\necho "You may also need to check your firewall rules"\n\nexit 0'


def process_config(config, dir):

    def generate_certs(path, device):
        print(device['name'])
        os.makedirs(path + device['name'], exist_ok=True)
        arguments = ['nebula-cert', 'sign', '-name', device['name'], '-out-crt', f"{path + device['name']}/host.crt", '-out-key', f"{path + device['name']}/host.key", '-ca-crt', f'{dir}/ca.crt', '-ca-key', f'{dir}/ca.key', '-ip', f"{device['nebula_ip']}/32"]
        if 'groups' in device.keys():
            arguments.append('-groups')
            arguments.append(','.join(device['groups']))
        subprocess.run(arguments)
        subprocess.run(['cp', f'{dir}/ca.crt', f"{path + device['name']}/"])


    with open(Path(__file__).resolve().parent / 'res/config.yaml') as f:
        base = yaml.load(f, Loader=yaml.loader.SafeLoader)
    with open(config) as f:
        mesh = yaml.load(f, Loader=yaml.loader.SafeLoader)

    dir += '/' + mesh['organization']
    os.makedirs(dir, exist_ok=True)

    # generate certificate authority
    subprocess.run(['nebula-cert', 'ca', '-name', mesh['organization'], '-out-crt', f'{dir}/ca.crt', '-out-key', f'{dir}/ca.key'])

    os.makedirs(dir + '/lighthouses', exist_ok=True)
    relays = {}
    ips = []
    for lighthouse in mesh['lighthouses']:
        generate_certs(dir + '/lighthouses/', lighthouse)
        conf = base.copy()
        ips.append(lighthouse['nebula_ip'])
        conf['tun'] = { 'dev': mesh['tun_device'] }
        conf['listen'] = { 'port': lighthouse['listen_port'] }
        conf['lighthouse'] = { 'am_lighthouse': True }
        conf['relay'] = { 'am_relay': True, 'use_relays': False }
        if 'preferred_ranges' in lighthouse.keys():
            conf['preferred_ranges'] = lighthouse['preferred_ranges']
        host_map = []
        for ip in lighthouse['public_ip']:
            host_map.append(ip)
        relays[lighthouse['nebula_ip']] = host_map
        with open(f"{dir}/lighthouses/{lighthouse['name']}/config.yaml", 'w', encoding='UTF-8') as f:
            yaml.dump(conf, f, Dumper=yaml.dumper.SafeDumper, indent=2, sort_keys=False)
        conf.clear()

    os.makedirs(dir + '/nodes', exist_ok=True)
    for node in mesh['nodes']:
        generate_certs(dir + '/nodes/', node)
        conf = base.copy()
        conf['tun'] = { 'dev': mesh['tun_device'] }
        conf['static_host_map'] = {}
        for host in relays.keys():
            conf['static_host_map'][host] = list(relays[host])
        conf['lighthouse'] = { 'am_lighthouse': False, 'hosts': list(ips) }
        if 'advertise_addrs' in node.keys():
            conf['lighthouse']['advertise_addrs'] = f"{node['advertise_addrs']}:0"
        conf['relay'] = { 'relays': ips }
        if 'preferred_ranges' in node.keys():
            conf['preferred_ranges'] = node['preferred_ranges']
        # print(conf)
        with open(f"{dir}/nodes/{node['name']}/config.yaml", 'w', encoding='UTF-8') as f:
            yaml.dump(conf, f, Dumper=yaml.dumper.SafeDumper, indent=2, sort_keys=False)
        conf.clear()
    return

    file_dir = f"{dir}/{device}/"
    with open(f"{file_dir}{mesh['NetworkName']}.conf", 'w', encoding='UTF-8') as f:
        f.write(conf)
        os.chmod(f"{file_dir}{mesh['NetworkName']}.conf", mode=0o600)
    with open(file_dir + f"deploy_{device}.sh", 'w', encoding='UTF-8') as f:
        f.write(create_deploy_script(mesh['NetworkName'], mesh[device]['ListenPort']))
        os.chmod(f'{file_dir}deploy_{device}.sh', mode=0o740)
    with open(file_dir + f"remove_{device}.sh", 'w', encoding='UTF-8') as f:
        f.write(create_remove_script(mesh['NetworkName']))
        os.chmod(f'{file_dir}remove_{device}.sh', mode=0o740)
    print(f'Generated config and scripts for {device}')


parser = argparse.ArgumentParser(description="Generate Nebula configs based on a network outline")
parser.add_argument('-v', '--version', action='version', version=f"{APP} {VERSION}")
parser.add_argument("Outline", help='Network outline (YAML format)')
parser.add_argument('-o', metavar='directory', help='Output directory (working dir if not provided)')
args = vars(parser.parse_args())
if args['o']:
    dir = args['o'].rstrip('/')
else:
    dir = '.'
process_config(args['Outline'], dir)
