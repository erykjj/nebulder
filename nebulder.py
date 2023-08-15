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
    for lighthouse in mesh['lighthouses']:
        generate_certs(dir + '/lighthouses/', lighthouse)

    os.makedirs(dir + '/nodes', exist_ok=True)
    for node in mesh['nodes']:
        generate_certs(dir + '/nodes/', node)


    return

    for device in mesh.keys():
        if device == 'NetworkName':
            continue
        os.makedirs(dir + '/' + device, exist_ok=True)
        if 'PrivateKey' not in mesh[device].keys():
            mesh[device]['PrivateKey'] = sh('wg', 'genkey').rstrip('\n')
            mesh[device]['PublicKey'] = sh('wg', 'pubkey', mesh[device]['PrivateKey']).rstrip('\n')

    for device in mesh.keys():
        if device == 'NetworkName':
            continue
        if 'AllowedIPs' in mesh[device].keys():
            subnet = '/24'
            routing = f"\n\n# IP forwarding\nPreUp = sysctl -w net.ipv4.ip_forward=1\n\n# IP masquerading\nPreUp = iptables -t mangle -A PREROUTING -i {mesh['NetworkName']} -j MARK --set-mark 0x30\nPreUp = iptables -t nat -A POSTROUTING ! -o {mesh['NetworkName']} -m mark --mark 0x30 -j MASQUERADE\nPostDown = iptables -t mangle -D PREROUTING -i {mesh['NetworkName']} -j MARK --set-mark 0x30\nPostDown = iptables -t nat -D POSTROUTING ! -o {mesh['NetworkName']} -m mark --mark 0x30 -j MASQUERADE"
        else:
            subnet = '/32'
            routing = ''
        conf = f"[Interface]\n# Name: {device}\nAddress = {mesh[device]['Address']}{subnet}\nPrivateKey = {mesh[device]['PrivateKey']}"
        if 'ListenPort' in mesh[device].keys():
            conf += f"\nListenPort = {mesh[device]['ListenPort']}{routing}"
        else:
            mesh[device]['ListenPort'] = False
        if 'DNS' in mesh[device].keys():
            conf += f"\nDNS = {mesh[device]['DNS']}"
        for peer in mesh.keys():
            if peer == 'NetworkName' or peer == device:
                continue
            if 'Endpoint' not in mesh[peer].keys() and 'AllowedIPs' not in mesh[device].keys():
                continue
            conf += f"\n\n[Peer]\n# Name: {peer}\nPublicKey = {mesh[peer]['PublicKey']}"
            if 'Endpoint' in mesh[peer].keys():
                conf += f"\nEndpoint = {mesh[peer]['Endpoint']}:{mesh[peer]['ListenPort']}"

            if 'AllowedIPs' in mesh[peer].keys():
                conf += f"\nAllowedIPs = {mesh[peer]['AllowedIPs']}"
            else:
                conf += f"\nAllowedIPs = {mesh[peer]['Address']}/32"
            if 'PersistentKeepalive' in mesh[device].keys():
                conf += f"\nPersistentKeepalive = {mesh[device]['PersistentKeepalive']}"

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
