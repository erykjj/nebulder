# nebulder

## Purpose

This is a Python script to automate the generation of interface configs for [Nebula](https://nebula.defined.net/docs) mesh/overlay networks. The nodes are all listed in a simple 'outline' (config file in YAML format) passed to the script. See the [*sample_outline.yaml*](https://github.com/erykjj/nebulder/blob/main/res/sample_outline.yaml) for format layout.

The script uses the `nebula-cert` binary to generate the keys/certs for each node. The script has only been tested under Linux. It will output the `config.yaml` file for each device/node, as well as a couple of bash scripts: one for automating the install/deploy of the device (along with a systemd unit file); the other for removing it/cleaning up. All that needs to be done is to copy the files to the corresponding node/device and to execute (**as root**) the `deploy.sh` script - again, only under Linux, and requires `systemd`. If your device is running a different OS, follow the [Nebula documentation](https://nebula.defined.net/docs/guides/quick-start/) for instructions on installation. In all cases, you will need to first download the corresponding Nebula binaries (on Linux, these go into `/usr/bin`). The QR PNG files are for scanning in the certificates on mobile devices.

As the deploy script indicates, you may also have to tweak your system firewall to allow the UDP connections to get through to your network interface if it will be used as a lighthouse. Of course, NAT port-forwarding on your router may also be required to let UDP through to the port your lighthouse is listening on.

Keep in mind that (by design and by default) Nebula certificate authority keys expire in 1 year, and so do all the certificates signed with it. Within that period, you can re-use the `ca.key` to generate more devices/nodes. So, keep `ca.key` safe. To renew, remove the `ca.key` and `ca.crt` files from the destination directory, re-run the `nebulder.py` script, and deploy again on each device. The `deploy.sh` script will first remove any previous keys/settings, and then install the new ones.

____
## Command-line usage
```
python3 nebulder.py [-h] [-v] [-o directory] Outline

positional arguments:
  Outline        Network outline (YAML format)

options:
  -h, --help     show this help message and exit
  -v, --version  show program's version number and exit
  -o directory   Output directory (defaults to dir where Outline is located)
```
.
____
## Feedback

Feel free to [get in touch and post any issues and suggestions](https://github.com/erykjj/nebulder/issues).

[![RSS of releases](res/rss-36.png)](https://github.com/erykjj/nebulder/releases.atom)
