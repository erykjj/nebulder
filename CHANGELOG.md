# nebulder 

## [Unreleased]

### Added

### Changed

### Fixed

### Removed

____
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
[1.0.1]: https://github.com/erykjj/nebulder/releases/tag/v1.0.1
[1.0.0]: https://github.com/erykjj/nebulder/releases/tag/v1.0.0
[0.1.4]: https://github.com/erykjj/nebulder/releases/tag/v0.1.4
[0.1.3]: https://github.com/erykjj/nebulder/releases/tag/v0.1.3
[0.1.2]: https://github.com/erykjj/nebulder/releases/tag/v0.1.2
[0.1.1]: https://github.com/erykjj/nebulder/releases/tag/v0.1.1
[0.1.0]: https://github.com/erykjj/nebulder/releases/tag/v0.1.0
