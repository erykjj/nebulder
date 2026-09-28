# nebulder

Pronounced "NEH-byool-der" (/ˈnɛb.jʊl.dɚ/) - a composite of *Nebula* + *builder*

## Python script to "build" deployment packages for [Nebula](https://nebula.defined.net/docs) mesh/overlay networks

The script has only been tested under Linux and the latest *nebula-cert* binary has to be in your path. It requires Python3 and PyYAML: `pip install pyyaml`

<details><summary>[EXPAND] HOWTO</summary><br/>

1. Define your mesh network by creating an 'outline' (config file in YAML format) listing all the nodes (including at least one lighthouse)
   - See the [*sample_outline.yaml*](https://github.com/erykjj/nebulder/blob/main/res/sample_outline.yaml) for format layout and available attributes
2. If you want to set up auto-updating (Linux, macOS, Windows), you will need to include an *update.conf* file next to your outline (see [*sample_update.conf*](https://github.com/erykjj/nebulder/blob/main/res/sample_update.conf) for the full set of configuration keys, including GitHub-based updates)
    - Indicate a web server with basic auth where each node will check for updates, **and/or** a private GitHub repository
    - If you want to receive notifications via *ntfy.sh*, provide the channel these notifications will be sent to
    - If configuring both a web server and GitHub, `UPDATE_PRIMARY` **must** be set to indicate which is tried first; the other becomes the fallback
3. Execute this *nebulder.py* script. It will generate the *config.yaml* interface configuration file and other necessary files for each device/node in its own deployment package/folder
    - An update password will be automatically generated (if it doesn't already exist) for each Linux, macOS and Windows node/lighthouse; this will be used to encrypt the zipped update packages. These passwords will be stored in *passwords.conf* (in the same directory as the outline) - don't lose/modify these (unless you know what you are doing) since these are the passwords the nodes expect to decrypt their update packages
    - If `GITHUB_REPO` is configured and you run with the `-Z` flag, packages are also uploaded to the GitHub release for that version (created automatically if it does not exist)
4. If installing *for the first time* (or updating the binaries), place the latest **binaries** from the [Nebula repo](https://github.com/slackhq/nebula/releases/latest) into each node's deployment folder[^1] - make sure they are for the correct OS/architecture:
    - Linux and macOS will need the *nebula* binary
    - Windows will need *nebula.exe* as well as the *dist* directory tree (*wintun.dll* driver)
5. Copy each deployment package to the corresponding device
6. Execute the deployment script on each device (from within package folder copied to the device):
    - On **Linux** (requires *systemd*) execute `sudo bash deploy.sh` to install or update. The script will (re)place the binary in `/usr/lib/nebula/[tun_device]/` and the config and keys in `/etc/nebula/[tun_device]/`, and will create and (re)start a *systemd* service. The *tun_device* (mesh network name from the outline YAML) is used as a subdirectory to support multiple independent Nebula networks on the same machine
      - A *remove.sh* script is also included for removing/cleaning up
    - On **Windows**, execute (as Administrator in *PowerShell*) the *deploy.ps1* script; the install directory on Windows (for *all* files) is `C:\nebula\[tun_device]\`; the script will also install and start a Windows service
    - For installation on mobile devices (**Android and iOS**), follow the [Nebula documentation](https://nebula.defined.net/docs/guides/quick-start/). QR codes are included in the package to make the process simpler, but there is no script included and you'll need the official apps
    - On **macOS** we follow a similar approach to Linux, except for using `/usr/local/lib` and `/usr/local/etc/`, and *launchd* for background services
7. **Lighthouses** need to be reachable from other nodes, so they typically require a public IP address. You may need to set up NAT/port forwarding, dynamic DNS, or use a cloud VPS for this purpose; you may also have to tweak your system firewall to allow UDP connections through to your network interface
8. If you set up **auto-update**, when you execute *nebulder.py* with `-Z`, it will generate zipped and encrypted deployment/update packages (which only the designated node will be able to open). Then:
    - **Web server**: copy the packages (along with the *version.txt* file) to your server's update directory
    - **GitHub**: the packages are uploaded to the release automatically (no manual step)
    - The update service on each node checks for updates every 15 min
    - It compares the remote version to its local version; if different, it downloads, decrypts, unzips, and deploys the package automatically
    - If you configured *ntfy.sh* notifications, you'll receive messages for successful updates, fallbacks, or errors

NOTE: Keep in mind that (by design and by default) Nebula certificate authority keys expire in 1 year, and so do all the certificates signed with these keys. Within that period, you can re-use the *ca.key* to generate more devices/nodes, or update existing ones with new binaries. So, **keep *ca.key* (and your outline) safe**. To renew (i.e., generate new certificate authority keys), remove the *ca.key* and *ca.crt* files from the destination directory, re-run the `nebulder.py` script, and deploy again on every device; or, publish the update packages (to your server, or to the GitHub release) for nodes with auto-update enabled to deploy themselves. Keep in mind that while deploying; the nebula service on the node goes down; also, if changing the certificate authority, there may be a lost connection until the node and lighthouse(s) are using the same updated certificate.

NOTE: If you are using GitHub-based updates, the read-write `GITHUB_TOKEN` is required to publish releases, while the read-only `UPDATE_TOKEN` is what ships to nodes. Keep `GITHUB_TOKEN` on your build machine only. Rotating it later only requires updating *update.conf* on the build side; the nodes are unaffected since they only carry `UPDATE_TOKEN`.
</details><br/>

<details><summary>[EXPAND] GitHub-based updates</summary><br/>

Instead of (or in addition to) a web server, updates can be distributed via a **private GitHub repository**. `nebulder.py` builds the release and uploads the packages, and the nodes fetch them using a read-only token.

### Two tokens, two purposes

GitHub updates require **two separate personal access tokens (PATs)** with different scopes:

| Token | Scope | Where it lives | Purpose |
|---|---|---|---|
| `GITHUB_TOKEN` | **Contents: Read and write** | Your build machine, in *update.conf* | `nebulder.py` uses it to create the release and upload packages |
| `UPDATE_TOKEN` | **Contents: Read-only** | Every node, in *update.conf* | Nodes use it to check for updates and download packages |

**`GITHUB_TOKEN` is stripped from the per-device *update.conf* during the build** — only the read-only `UPDATE_TOKEN` reaches the nodes. Never the read-write one.

### Creating the tokens

Both are **fine-grained personal access tokens** (Settings → Developer settings → Personal access tokens → Fine-grained tokens):

1. **Read-write token** (build machine):
   - Name: e.g. `nebulder-publish`
   - Repository access: *Only select repositories* → your update repo
   - Permissions: **Contents → Read and write**
   - The **Metadata: Read-only** permission is added automatically
   - Copy the token value into `GITHUB_TOKEN` in *update.conf*

2. **Read-only token** (nodes):
   - Name: e.g. `nebulder-update`
   - Repository access: *Only select repositories* → the same repo
   - Permissions: **Contents → Read-only**
   - Copy the token value into `UPDATE_TOKEN` in *update.conf*

### Releasing

1. Set up *update.conf* with `GITHUB_REPO`, `GITHUB_TOKEN`, `UPDATE_TOKEN`, and optionally `UPDATE_PRIMARY` and `NTFY_CHANNEL`
2. Run `nebulder.py` with the `-Z` flag: `python3 nebulder.py my_outline.yaml -Z`
3. The script creates the GitHub release (tagged with the current version) and uploads all `*_<version>.zip.enc` files. If the release already exists, existing assets with the same names are replaced; other assets are left untouched.

### Fallback behavior

When both `UPDATE_SERVER` and `GITHUB_REPO` are configured:

- `UPDATE_PRIMARY` determines which source is tried first
- If the primary source fails (network unreachable, auth failure), a low-priority *ntfy.sh* warning is sent and the secondary source is tried
- If the secondary also fails, a high-priority alert is sent
- **Exception:** if a release exists but the specific package for the node is missing (`ASSET_NOT_FOUND`), **no fallback is attempted** — this indicates a build problem worth investigating, not a transient network issue
- If only one source is configured, that source is used and no fallback occurs
</details><br/>

<details><summary>[EXPAND] Command-line usage</summary><br/>

```
usage: python3 nebulder.py [-h] [-v] [-o directory] [-Z] [-V id] outline

Generate Nebula configs based on a network outline

positional arguments:
  outline        Network outline (YAML format)

options:
  -h, --help     show this help message and exit
  -v, --version  show program's version number and exit
  -o directory   Output directory (defaults to dir where outline is located)
  -Z             Zip and encrypt packages, and upload to GitHub if configured (for auto-update)
  -V id          Config version number or id (optional)
```

NOTE: `-V id` is optional; versioning is via an auto-incrementing *version.txt* file (starting at "v1.0.0" by default), or one can specify the version number/id
</details><br/>

____
## Feedback

Feel free to [get in touch and post any issues and suggestions](https://github.com/erykjj/nebulder/issues).

[![RSS of releases](res/rss-36.png)](https://github.com/erykjj/nebulder/releases.atom)

____
[^1]: The binaries (and the Windows *wintun* driver) only need to be in the package folder for initial deployment or if updating these binaries on the node(s)