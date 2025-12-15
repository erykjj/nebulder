# nebulder

## Python script to "build" deployment packages for [Nebula](https://nebula.defined.net/docs) mesh/overlay networks

The script has only been tested under Linux and the lates `nebula-cert` binary has to be in your path.

1. Define your mesh network by creating an 'outline' (config file in YAML format) listing all the nodes. See the [*sample_outline.yaml*](https://github.com/erykjj/nebulder/blob/main/res/sample_outline.yaml) for format layout and available attributes
2. Execute the script. It will generation the `config.yaml` interface configuration file and other necessary key files for each device/node in its own deployment package/folder
3. If installing for the first time (or updating), place the latest binaries from https://github.com/slackhq/nebula/releases/latest into each folder - make sure they are for the correct platform (amd64, arm64, etc.)
    - Linux will need the `nebula` binary (if not already on the target system)
    - Windows will need `nebula.exe` as well as the `dist` folder and all its contents (`wintun.dll` driver)
4. Copy each deployment package to the corresponding device
5. Execute the deployment script on each device (from within package folder copied onto each device):
    - On **Linux** (requires `systemd`) execute (**as root**) the `deploy.sh` script to install or update. The script will (re)place the binary in /usr/bin and the config and keys in /etc/nebula, and will create and (re)start a `systemd` service
      - A `remove.sh` script is also included for removing/cleaning up
    - On **Windows**, execute (**as Administrator**) the `deploy.bat` batch file which will ask for a target directory where all the required files will be placed, and will install and start a Windows service
    - For installation on mobile devices (**Android and iOS**), follow the [Nebula documentation](https://nebula.defined.net/docs/guides/quick-start/). QR codes are included in the package to make the process simpler, but there is no script included
    - For **MacOS**, only the configuration and key-files are provided. You are on your own to configure a service on target device
6. If a device is to be used as a **lighthouse**, you may also have to tweak your system firewall to allow the UDP connections to get through to your network interface, and NAT port-forwarding on your router may also be required to let UDP through to the port your lighthouse is listening on

Keep in mind that (by design and by default) Nebula certificate authority keys expire in 1 year, and so do all the certificates signed with it. Within that period, you can re-use the `ca.key` to generate more devices/nodes, or update existing ones with new binaries. So, keep `ca.key` safe. To renew (i.e., generate new certificate authority keys), remove the `ca.key` and `ca.crt` files from the destination directory, re-run the `nebulder.py` script, and deploy again on every device. 

____
## Command-line usage

Requires PyYAML: `pip install pyyaml`

```
usage: python3 nebulder.py [-h] [-v] [-o directory] [-z] [-V id] Outline

Generate Nebula configs based on a network outline

positional arguments:
  Outline        Network outline (YAML format)

options:
  -h, --help     show this help message and exit
  -v, --version  show program's version number and exit
  -o directory   Output directory (defaults to dir where Outline is located)
  -z             Zip packages
  -V id          Config version number or id (optional)
```

NOTE: `-V id` is optional; versioning is via an auto-incrementing *version.txt* file (starting at "v1.0.0" by default), or one can specify the version number/id
____
## Feedback

Feel free to [get in touch and post any issues and suggestions](https://github.com/erykjj/nebulder/issues).

[![RSS of releases](res/rss-36.png)](https://github.com/erykjj/nebulder/releases.atom)
