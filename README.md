# VZ-Tool Devil

A Python command-line helper for inspecting GitHub project layouts and checking common platform compatibility assumptions before installation. The repository also includes an offline defensive URL/header triage guide.

## Kali Linux setup

```bash
sudo apt update
sudo apt install -y git python3 python3-venv
git clone https://github.com/nagatoara4/VZ-Tool-devil.git
cd VZ-Tool-devil
python3 -m venv .venv
source .venv/bin/activate
python3 vztool.py --help
```

The tool uses Python's standard library. It does not execute project code while cloning or analyzing a directory. Setup commands are suggestions to review, not commands to run blindly.

## Commands

```bash
python3 vztool.py clone https://github.com/OWNER/PROJECT.git
python3 vztool.py analyze .
python3 vztool.py analyze . --json
python3 vztool.py prepare .
python3 -m unittest -v
```

The repository's defensive analysis guide is in [SHADOWPHISH.md](SHADOWPHISH.md). URL and email-header triage should be treated as heuristic only, not a verdict. Never use tools against systems or data without authorization.

## Platform notes

Kali Linux provides a conventional Linux userland. iSH on iPhone is a constrained Alpine userland, not an unrestricted Linux kernel; containers, systemd, kernel modules, privileged networking, and some native dependencies may not work.

## Security

Cloning and analysis do not run upstream code. Inspect dependencies and scripts before installing them. See [SECURITY.md](SECURITY.md).
