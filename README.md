# MeshGuard — WireGuard Mesh Configurator

MeshGuard is a Python project for preparing and reviewing WireGuard mesh configuration files. Its CLI includes blueprint creation, configuration generation, topology display, key generation, and checks for issues such as overlapping addresses.

**Status:** Experimental configuration tooling. Its output and cryptographic implementation have not been independently security audited in this review. A passing audit is not proof that a network is secure or reachable; review generated settings and validate them in a disposable environment before deployment.

## Getting started

The project declares Python 3.8 or newer in [pyproject.toml](pyproject.toml). From the repository root, inspect the CLI and run the included unit tests:

```sh
python3 -m meshguard --help
python3 -m unittest discover -s tests -v
```

The existing CLI documents the following example workflow:

```sh
python3 -m meshguard init --topology full_mesh --nodes 3 --output mesh.json
python3 -m meshguard visualize --config mesh.json
python3 -m meshguard generate --config mesh.json --output-dir ./output --interface wg0
python3 -m meshguard audit --dir ./output
```

Initialization generates keys and writes a blueprint; generated configuration may also contain private keys. Use disposable values while experimenting, restrict access to those files, and avoid committing or sharing them. Endpoint addresses in a starter blueprint must be reviewed and replaced for the intended network. `keygen`, `export-systemd`, and other options are described by `python3 -m meshguard --help` and the subcommand help.

These commands are based on the source and previous documentation; they were not run as part of this review. The configuration generator does not replace WireGuard installation, firewall setup, routing review, or real connectivity testing.

## Project layout

[CLI source](meshguard/cli.py) · [Package metadata](pyproject.toml) · [Tests](tests/) · [Issues](https://github.com/Ethan-da-Tech-Wizard/wireguard-mesh-configurator/issues)

## License

Project code is distributed under the [MIT License](LICENSE). WireGuard and any other external tools retain their own licenses.
