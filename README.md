# nebulder v2[^*]

Pronounced "NEH-byool-der" (/ˈnɛb.jʊl.dɚ/) - a composite of *Nebula* + *builder*

## Python 3 script to "build" deployment packages for [Nebula](https://nebula.defined.net/docs) mesh/overlay networks

The script has only been tested under Linux and the latest *nebula-cert* binary has to be in your path. It requires PyYAML: `pip install pyyaml`

<details>
<summary>[EXPAND] HOWTO</summary><br/>

1. Define your mesh network by creating an 'outline' (config file in YAML format) listing all the nodes (including at least one lighthouse)
   - See the [*sample_outline.yaml*](https://github.com/erykjj/nebulder/blob/main/res/sample_outline.yaml) for format layout and available attributes
2. If you want to set up auto-updating (Linux, macOS, Windows), you will need to include a *update.conf* file ([*sample_update.conf*](https://github.com/erykjj/nebulder/blob/main/res/sample_update.conf))
    - Indicate a web file server with basic auth where update each node will check for updates
    - If you want to receive notifications via *ntfy.sh*, provide the channel these notifications will be sent to
3. Execute this *nebulder.py* script. It will generate the *config.yaml* interface configuration file and other necessary files for each device/node in its own deployment package/folder
4. If installing *for the first time* (or updating the binaries), place the latest **binaries** from the [Nebula repo](https://github.com/slackhq/nebula/releases/latest) into each node's deployment folder - make sure they are for the correct OS/architecture:
    - Linux and macOS will need the *nebula* binary
    - Windows will need *nebula.exe* as well as the *dist* folder and its contents (*wintun.dll* driver)
5. Copy each deployment package to the corresponding device
6. Execute the deployment script on each device (from within package folder copied to the device):
    - On **Linux** (requires *systemd*) execute `sudo bash deploy.sh` to install or update. The script will (re)place the binary in `/usr/lib/nebula/[tun_device]/` and the config and keys in `/etc/nebula/[tun_device]/`, and will create and (re)start a *systemd* service. The *tun_device* (mesh network name from the outline YAML) is used as a subdirectory to support multiple independent Nebula networks on the same machine
      - A *remove.sh* script is also included for removing/cleaning up
    - On **Windows**, execute (as Administrator in *PowerShell*) the *deploy.ps1* script; the install directory on Windows (for *all* files) is `C:\nebula\[tun_device]\`; the script will also install and start a Windows service
    - For installation on mobile devices (**Android and iOS**), follow the [Nebula documentation](https://nebula.defined.net/docs/guides/quick-start/). QR codes are included in the package to make the process simpler, but there is no script included and you'll need the official apps
    - On **MacOS** we follow a similar approach to Linux, except for using `/usr/local/lib` and `/usr/local/etc/`, and *launchd* for background services
7. **Lighthouses** need to be reachable from other nodes, so they typically require a public IP address. You may need to set up NAT/port forwarding, dynamic DNS, or use a cloud VPS for this purpose; you may also have to tweak your system firewall to allow UDP connections through to your network interface
8. If you set up **auto-update**, when you execute *nebulder.py* with `-z`, it will generate zipped deployment/update packages; copy these (along with the *version.txt* file) to your web server's update directory
    - The update service on each node that has been configured checks for updates every 15 min
    - It will check if the contents of *version.txt* are different from the local version, which would indicate that an update package for the node is available
    - It will then download and deploy it automatically
    - If you configured *ntfy.sh* notifications, you'll receive confirmation messages for successful updates or error alerts
</details><br/>

Keep in mind that (by design and by default) Nebula certificate authority keys expire in 1 year, and so do all the certificates signed with these keys. Within that period, you can re-use the *ca.key* to generate more devices/nodes, or update existing ones with new binaries. So, keep *ca.key* safe. To renew (i.e., generate new certificate authority keys), remove the *ca.key* and *ca.crt* files from the destination directory, re-run the `nebulder.py` script, and deploy again on every device; or, upload the update packages to your server for nodes with auto-update enabled to deploy themselves. Keep in mind that while deploying; the nebula service on the node goes down; also, if changing the certificate authority, there may be a lost connection until the node and lighthouse(s) are using the same updated certificate.

<details>
<summary>[EXPAND] Command-line usage</summary><br/>

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
</details><br/>

____
## Feedback

Feel free to [get in touch and post any issues and suggestions](https://github.com/erykjj/nebulder/issues).

[![RSS of releases](res/rss-36.png)](https://github.com/erykjj/nebulder/releases.atom)

____
[^*]: Due to changed paths, etc., if you are upgrading the nodes from v1, ensure you clean up their current installs first; otherwise, you may have conflicting services