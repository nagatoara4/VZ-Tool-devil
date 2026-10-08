# VZ-Tool Devil

A lightweight, offline defensive triage CLI for Kali Linux and other Python 3 environments. It analyzes URL strings and saved email headers, explains the indicators it finds, and exports JSON or CSV reports. It does not contact target URLs or perform reputation lookups.

## Kali Linux setup

```bash
sudo apt update
sudo apt install -y git python3 python3-venv
git clone https://github.com/nagatoara4/VZ-Tool-devil.git
cd VZ-Tool-devil
python3 -m venv .venv
source .venv/bin/activate
python3 devil_lab.py --help
```

No third-party Python packages are required.

## Usage

Analyze one URL string:

```bash
python3 devil_lab.py url 'https://example.org/account/verify'
python3 devil_lab.py url 'http://192.0.2.10/login' --json report.json
```

Analyze a file with one URL per line:

```bash
python3 devil_lab.py file examples/urls.txt --csv urls.csv
python3 devil_lab.py file examples/urls.txt --json urls.json
```

Analyze saved email headers:

```bash
python3 devil_lab.py headers examples/sample-headers.txt --json headers.json
```

## Tests

```bash
python3 -m unittest -v
```

## Important limitations

- The score is a transparent heuristic, not a probability or a verdict; false positives and false negatives are expected.
- URL analysis is local parsing only: no DNS resolution, HTTP requests, redirect following, or reputation checks.
- Email-header analysis relies on the supplied text. Trust authentication results only when added by trusted mail infrastructure.
- Use only on data you are authorized to assess. This is not a substitute for professional incident response.

See [SECURITY.md](SECURITY.md) for responsible-use guidance. The repository is currently private; change its visibility in GitHub repository settings if you want the public to clone it.
