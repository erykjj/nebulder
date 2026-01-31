# nebulder 

## [Unreleased]

### Added

### Changed

- **BREAKING CHANGES**
  - Update passwords are no longer added to the original outline, since updating it (without additional dependencies) removes comments, etc.
  - Instead, a `{mesh_name}_passwords.conf` file is created/updated in the same directory as the outline - containing *device name* and *password* key-value pairs
  - **IMPORTANT** - to transition properly in an already-deployed mesh, generate this new file by running nebulder once, then **copy the existing password for each device from your outline into this `passwords.conf` file** - otherwise your update packages will be encrypted with new passwords that the device doesn't know
    - Then you can remove the `update_password` values from the outline (and regenerate update packages)
- Allows CGNAT IP range

### Fixed

### Removed

____
## [2.1.1] - 2026-01-16
### Changed

- Adjustment for nebula-cert 1.10.1

## [2.1.0] - 2026-01-13
### Fixed

- Fixed ntfy messages when network not yet up
  - Added network connectivity checks and a slight delay

## [2.0.0] - 2026-01-02
### Added

- **Auto-update functionality** with own server
  - works on Linux, macOS and Windows

### Changed

- **Major rewrite** of node scripts
- Better macOS support

## [1.1.2] - 2025-07-12

### Fixed
- Fixed regex flag passed as count parameter

## [1.1.1] - 2024-05-21

### Added

- Added -z option to ZIP generated package directories

### Changed

- Use shutil and os functions to cp, mv and rm

## [1.0.2] - 2023-12-18
### Added

- Added 'macos' support - limited: only config and key-files; no scripts

## [1.0.1] - 2023-12-14
### Added

- Script to stop/uninstall nebula service on Windows

## [1.0.0] - 2023-12-13
### Added

- Windows batch file for automatic deployment (must be executed as Administrator)
  - `nebula.exe` (for the appropriate Windows platform: amd64, arm64, etc.) and the `dist` folder (containing the required `wintun.dll` driver) can be placed inside the deployment package for installation/update

## [0.1.4] - 2023-12-12
### Added

- `os` attribute for each node - 'windows', 'android', 'ios', or 'linux' (default)
  - determines which files are included in the generated node folder
- `nebula` binary (ensure platform is correct: amd64, arm64, etc.) can be placed in the node folder and will be placed in /usr/bin/ on the target device (Linux only)

## [0.1.3] - 2023-10-24
### Changed

- port in public_ip is optional - added in from listen_port if not provided

## [0.1.2] - 2023-08-31
### Added

- *deploy.sh* script
  - added check for binary
  - added check for root privileges
  - added commands to remore previous keys/config - for easy re-deployment/renewal

### Changed

- Small fixes/improvements

## [0.1.1] - 2023-08-22
### Fixed

- Included ignored scripts in repo

## [0.1.0] - 2023-08-21

Initial release

____
[Unreleased]: https://github.com/erykjj/nebulder
[2.1.1]: https://github.com/erykjj/nebulder/releases/tag/v2.1.1
[2.1.0]: https://github.com/erykjj/nebulder/releases/tag/v2.1.0
[2.0.0]: https://github.com/erykjj/nebulder/releases/tag/v2.0.0
[1.1.2]: https://github.com/erykjj/nebulder/releases/tag/v1.1.2
[1.1.1]: https://github.com/erykjj/nebulder/releases/tag/v1.1.1
[1.0.2]: https://github.com/erykjj/nebulder/releases/tag/v1.0.2
[1.0.1]: https://github.com/erykjj/nebulder/releases/tag/v1.0.1
[1.0.0]: https://github.com/erykjj/nebulder/releases/tag/v1.0.0
[0.1.4]: https://github.com/erykjj/nebulder/releases/tag/v0.1.4
[0.1.3]: https://github.com/erykjj/nebulder/releases/tag/v0.1.3
[0.1.2]: https://github.com/erykjj/nebulder/releases/tag/v0.1.2
[0.1.1]: https://github.com/erykjj/nebulder/releases/tag/v0.1.1
[0.1.0]: https://github.com/erykjj/nebulder/releases/tag/v0.1.0
