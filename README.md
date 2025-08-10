<p align="center">
  <img width="300" height="300" src="/icons/syshell.svg">
</p>

# syshell - Web Shell Framework for Penetration Testing

## Overview

syshell is a web shell framework for authorized penetration testing and security assessments. It consists of a PHP web shell with modern interface and encrypted function obfuscation, and a Python generator tool that creates customized shells with unique credentials.

## Components

### Web Shell (`diagnose.php`)

- Secure authentication with SHA-256 hashed credentials
- Command execution with output capture
- File management and built-in text editor
- System information display
- Responsive web interface
- AES-256-CBC encrypted function names

### Generator (`shell_generator.py`)

- Generate shells with custom credentials
- Batch processing from credential files
- Interactive and command-line modes
- Template-based shell generation
- Encryption compatibility testing

## Showcase

<p align="center">
  <img width="600" height="300" src="/images/syshell_login.png">
</p>

<p align="center">
  <img width="600" height="300" src="/images/syshell_dashboard.png">
</p>

<p align="center">
  <img width="600" height="300" src="/images/syshell_file_viewer.png">
</p>


## Installation

```console
# Install Python dependencies
pip install cryptography

# Generate single shell
python3 shell_generator.py -u admin -p SuperSecret123 -o custom_shell.php

# Interactive mode
python3 shell_generator.py -i

# Use custom template
python3 shell_generator.py -u testuser -p mypass123 -t /path/to/template.php

# Batch generation
python3 shell_generator.py -b credentials.txt

# Test Encryption Compatibility
python3 shell_generator.py --test-encryption
```

## Usage

```console
$ python3 shell_generator.py 
[!] Username required. Use -u or --interactive mode.
[!] Password required. Use -p or --interactive mode.

Use --help for usage information or -i for interactive mode.
```

```console
$ python3 shell_generator.py --help
usage: shell_generator.py [-h] [-u USERNAME] [-p PASSWORD] [-o OUTPUT] [-t TEMPLATE] [-i] [-b BATCH] [--test-encryption]

syshell Generator - Customizable Web Shell Builder

options:
  -h, --help            show this help message and exit
  -u, --username USERNAME
                        Username for web shell authentication
  -p, --password PASSWORD
                        Password for web shell authentication
  -o, --output OUTPUT   Output filename for generated web shell
  -t, --template TEMPLATE
                        Path to web shell template file
  -i, --interactive     Run in interactive mode
  -b, --batch BATCH     Batch generate from file (format: username:password per line)
  --test-encryption     Test encryption compatibility with PHP

For authorized penetration testing and offensive security operations only!
```

## Examples

```console
$ python3 shell_generator.py -u admin -p SuperSecret123 -o custom_shell.php
[+] Generating web shell with credentials:
    Username: admin
    Password: **************
[+] Generated hashes:
    User hash: 8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918
    Pass hash: 343fcb40497549085c98ae137c137116a5c2442eb8dc0bf0cac3a3419ce05b9f
[+] Generated encrypted values:
    diagLogParser: /Zt5QH2C9Rao8UYQlRy9/w==
    dataStreamFilter: u1Awy/VCOf940h0mhny+sA==
[+] Web shell generated successfully: custom_shell.php
```

```console
$ python3 shell_generator.py -i
============================================================
syshell Generator - Interactive Mode
For authorized penetration testing operations only!
============================================================
Enter username: admin
Enter password: SuperSecret123
Output filename (press Enter for auto-generated): myshell.php
Template path (press Enter for 'diagnose.php'): 

============================================================
[+] Generating web shell with credentials:
    Username: admin
    Password: **************
[+] Generated hashes:
    User hash: 8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918
    Pass hash: 343fcb40497549085c98ae137c137116a5c2442eb8dc0bf0cac3a3419ce05b9f
[+] Generated encrypted values:
    diagLogParser: /Zt5QH2C9Rao8UYQlRy9/w==
    dataStreamFilter: u1Awy/VCOf940h0mhny+sA==
[+] Web shell generated successfully: myshell.php
```

```console
$ python3 shell_generator.py -u testuser -p mypass123 -t diagnose.php         
[+] Generating web shell with credentials:
    Username: testuser
    Password: *********
[+] Generated hashes:
    User hash: ae5deb822e0d71992900471a7199d0d95b8e7c9d05c40a8245a281fd2c1d6684
    Pass hash: e6e07510d6531af5f403d1e6d0eb997855b6453488aaee6a9dd10ad5133f936a
[+] Generated encrypted values:
    diagLogParser: ywDGkJs5+Hq7s0TM93PjhA==
    dataStreamFilter: 7Mbf/20diZzsHtsq9eQ25A==
[+] Web shell generated successfully: syshell_testuser_bad65492.php
```

```console
$ python3 shell_generator.py -b credentials.txt
[+] Batch generating 3 web shells...

[+] Processing 1/3: admin
[+] Generating web shell with credentials:
    Username: admin
    Password: **************
[+] Generated hashes:
    User hash: 8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918
    Pass hash: 343fcb40497549085c98ae137c137116a5c2442eb8dc0bf0cac3a3419ce05b9f
[+] Generated encrypted values:
    diagLogParser: /Zt5QH2C9Rao8UYQlRy9/w==
    dataStreamFilter: u1Awy/VCOf940h0mhny+sA==
[+] Web shell generated successfully: output/syshell_admin_28db9e12.php

[+] Processing 2/3: test
[+] Generating web shell with credentials:
    Username: test
    Password: ***********
[+] Generated hashes:
    User hash: 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
    Pass hash: ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f
[+] Generated encrypted values:
    diagLogParser: 1C9Ak1Sm5642pHNSAp+NmQ==
    dataStreamFilter: 9pD/zfxqswDtAhFODo1Nog==
[+] Web shell generated successfully: output/syshell_test_482c811d.php

[+] Processing 3/3: client1
[+] Generating web shell with credentials:
    Username: client1
    Password: *********
[+] Generated hashes:
    User hash: 1917e33407c28366c8e3b975b17e7374589312676b90229adb4ce6e58552e223
    Pass hash: 0e44ce7308af2b3de5232e4616403ce7d49ba2aec83f79c196409556422a4927
[+] Generated encrypted values:
    diagLogParser: Sw0ywdk/c5YD0qUe2BUJAQ==
    dataStreamFilter: zpzI71o2Gxk2y64viw1dug==
[+] Web shell generated successfully: output/syshell_client1_8a24367a.php

[+] Batch generation complete: 3/3 successful
```

## Requirements

- Python 3.6+ with cryptography library
- PHP 7.0+ with OpenSSL extension
- Written authorization for all testing activities

## Legal Disclaimer

FOR AUTHORIZED SECURITY TESTING ONLY - This software is intended exclusively for authorized penetration testing, security assessments, and educational purposes by qualified professionals. Users must obtain explicit written permission before deployment on any systems. Unauthorized access to computer systems is illegal and may result in criminal prosecution. The software is provided "AS IS" without warranty, and users assume full responsibility for compliance with all applicable laws and regulations. By using this software, you agree to indemnify and hold harmless the developers from any claims or damages arising from its use or misuse.