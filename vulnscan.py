#!/usr/bin/env python3
"""
Security Code Scanner for Penetration Testing
Scans files for potential security vulnerabilities and interesting information
"""

import os
import re
import argparse
import sys
from collections import defaultdict

try:
    from colorama import Fore, Style, init
    # Initialize colorama for cross-platform colored output
    init(autoreset=True)
except ImportError:
    print("Warning: colorama not installed. Install with: pip install colorama")
    print("Continuing without colored output...\n")
    # Create dummy color constants
    class Fore:
        RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = WHITE = ''
    class Style:
        BRIGHT = ''

class SecurityScanner:
    def __init__(self):
        # Define patterns for different vulnerability types
        self.patterns = {
            'credentials': {
                'patterns': [
                    # Passwords - various formats
                    (r'password\s*[=:]\s*["\']([^"\']+)["\']', 'Hardcoded password'),
                    (r'passwd\s*[=:]\s*["\']([^"\']+)["\']', 'Hardcoded password'),
                    (r'pwd\s*[=:]\s*["\']([^"\']+)["\']', 'Hardcoded password'),
                    (r'pass\s*[=:]\s*["\']([^"\']+)["\']', 'Hardcoded password'),
                    
                    # Method calls with password parameters
                    (r'\.put\s*\(\s*["\']password["\']\s*,\s*["\']([^"\']+)["\']', 'Hardcoded password in method call'),
                    (r'\.put\s*\(\s*["\']pass["\']\s*,\s*["\']([^"\']+)["\']', 'Hardcoded password in method call'),
                    (r'\.put\s*\(\s*["\']pwd["\']\s*,\s*["\']([^"\']+)["\']', 'Hardcoded password in method call'),
                    (r'setPassword\s*\(\s*["\']([^"\']+)["\']', 'Hardcoded password in setter'),
                    
                    # API Keys and Tokens
                    (r'api[_-]?key\s*[=:]\s*["\']([^"\']+)["\']', 'API Key'),
                    (r'apikey\s*[=:]\s*["\']([^"\']+)["\']', 'API Key'),
                    (r'access[_-]?token\s*[=:]\s*["\']([^"\']+)["\']', 'Access Token'),
                    (r'auth[_-]?token\s*[=:]\s*["\']([^"\']+)["\']', 'Auth Token'),
                    (r'secret[_-]?key\s*[=:]\s*["\']([^"\']+)["\']', 'Secret Key'),
                    
                    # Database credentials
                    (r'db[_-]?pass\s*[=:]\s*["\']([^"\']+)["\']', 'Database password'),
                    (r'database[_-]?password\s*[=:]\s*["\']([^"\']+)["\']', 'Database password'),
                    
                    # AWS Keys
                    (r'aws[_-]?access[_-]?key[_-]?id\s*[=:]\s*["\']([^"\']+)["\']', 'AWS Access Key'),
                    (r'aws[_-]?secret[_-]?access[_-]?key\s*[=:]\s*["\']([^"\']+)["\']', 'AWS Secret Key'),
                    
                    # Private Keys
                    (r'-----BEGIN (RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----', 'Private Key'),
                    
                    # Connection strings
                    (r'connectionstring\s*[=:]\s*["\']([^"\']+)["\']', 'Connection String'),
                    (r'jdbc:[a-zA-Z0-9]+://[^"\'\s]+', 'JDBC Connection String'),
                    
                    # Username credentials
                    (r'\.put\s*\(\s*["\']user["\']\s*,\s*["\']([^"\']+)["\']', 'Hardcoded username'),
                    (r'username\s*[=:]\s*["\']([^"\']+)["\']', 'Hardcoded username'),
                    (r'user\s*[=:]\s*["\']([^"\']+)["\']', 'Hardcoded username'),
                ],
                'color': Fore.RED
            },
            
            'sql_injection': {
                'patterns': [
                    # String concatenation in SQL - ordered from most specific to least specific
                    (r'(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)[^"\']*[\'"]\s*\+\s*\w+', 'SQL concatenation with variable'),
                    (r'query\s*[=:]\s*["\'][^"\']*[\'"]\s*\+', 'Query string concatenation'),
                    (r'sql\s*[=:]\s*["\'][^"\']*[\'"]\s*\+', 'SQL string concatenation'),
                    
                    # WHERE clause specific patterns
                    (r'WHERE\s+\w+\s*=\s*[\'"][\'"]?\s*\+', 'WHERE clause with concatenation'),
                    
                    # Generic string concatenation that could be SQL injection
                    (r'[\'"]\s*\+\s*\w+\s*\+\s*[\'"]', 'Variable injection between quotes'),
                    
                    # Statement usage (not PreparedStatement)
                    (r'Statement\s+\w+\s*=', 'Using Statement instead of PreparedStatement'),
                    (r'createStatement\(\)', 'Creating Statement object'),
                    (r'executeQuery\([^?]+\)', 'ExecuteQuery without parameters'),
                    (r'executeUpdate\([^?]+\)', 'ExecuteUpdate without parameters'),
                    
                    # Dynamic SQL
                    (r'exec\s*\(\s*["\'].*\+', 'Dynamic SQL execution'),
                    (r'execute\s*\(\s*["\'].*\+', 'Dynamic SQL execution'),
                    
                    # Format string SQL
                    (r'\.format\(.*\).*(?:SELECT|INSERT|UPDATE|DELETE)', 'SQL with format string'),
                    (r'%[sd].*(?:SELECT|INSERT|UPDATE|DELETE)', 'SQL with string formatting'),
                ],
                'color': Fore.YELLOW
            },
            
            'command_injection': {
                'patterns': [
                    # OS command execution
                    (r'exec\s*\([^)]*\$', 'Command execution with variable'),
                    (r'system\s*\([^)]*\$', 'System call with variable'),
                    (r'shell_exec\s*\([^)]*\$', 'Shell execution with variable'),
                    (r'eval\s*\([^)]*\$', 'Eval with variable'),
                    (r'Runtime\.getRuntime\(\)\.exec', 'Java Runtime exec'),
                    (r'subprocess\.(call|run|Popen)\s*\([^)]*,\s*shell\s*=\s*True', 'Python subprocess with shell=True'),
                    (r'os\.system\s*\([^)]*\%', 'OS system with formatting'),
                ],
                'color': Fore.MAGENTA
            },
            
            'path_traversal': {
                'patterns': [
                    (r'\.\./', 'Path traversal pattern'),
                    (r'\.\.\\\\', 'Windows path traversal'),
                    (r'new\s+File\s*\([^)]*\+', 'File path concatenation'),
                    (r'open\s*\([^)]*\+', 'File open with concatenation'),
                    (r'include\s*\([^)]*\$', 'Dynamic file inclusion'),
                    (r'require\s*\([^)]*\$', 'Dynamic file requirement'),
                    (r'file_get_contents\s*\([^)]*\$', 'Dynamic file reading'),
                ],
                'color': Fore.CYAN
            },
            
            'interesting_files': {
                'patterns': [
                    # Configuration files
                    (r'config\.php|config\.py|config\.js|config\.properties', 'Configuration file reference'),
                    (r'\.env', 'Environment file reference'),
                    (r'web\.config|app\.config', '.NET configuration'),
                    
                    # Backup files
                    (r'\.bak|\.backup|\.old|\.orig', 'Backup file reference'),
                    
                    # Debug/Test
                    (r'debug\s*=\s*[Tt]rue', 'Debug mode enabled'),
                    (r'DEBUG\s*=\s*[Tt]rue', 'Debug mode enabled'),
                    (r'test|TODO|FIXME|HACK|XXX', 'Development comment'),
                    
                    # Admin/Management
                    (r'/admin|/management|/manager', 'Admin path reference'),
                    (r'phpinfo\(\)', 'PHPInfo() call'),
                    
                    # Interesting functions
                    (r'base64_decode|base64_encode', 'Base64 operations'),
                    (r'serialize|unserialize', 'Serialization operations'),
                ],
                'color': Fore.GREEN
            },
            
            'database_operations': {
                'patterns': [
                    # Database connections
                    (r'mysqli?_connect|mysql_connect', 'MySQL connection'),
                    (r'pg_connect|psql', 'PostgreSQL connection'),
                    (r'DriverManager\.getConnection', 'JDBC connection'),
                    (r'new\s+PDO\s*\(', 'PDO connection'),
                    
                    # Database credentials in connection strings
                    (r'jdbc:mysql://[^"\']+:([^@]+)@', 'Database credentials in URL'),
                    (r'connectionProps\.put', 'Connection properties configuration'),
                    
                    # INTO OUTFILE (MySQL file write)
                    (r'INTO\s+OUTFILE', 'MySQL INTO OUTFILE capability'),
                    (r'LOAD_FILE\s*\(', 'MySQL LOAD_FILE capability'),
                    
                    # NoSQL injection patterns
                    (r'\$where|\$ne|\$gt|\$lt|\$regex', 'MongoDB operators'),
                ],
                'color': Fore.BLUE
            }
        }
        
        # File extensions to scan
        self.scan_extensions = [
            '.java', '.php', '.py', '.js', '.jsp', '.asp', '.aspx',
            '.c', '.cpp', '.cs', '.rb', '.pl', '.sh', '.bat', '.ps1',
            '.xml', '.conf', '.config', '.properties', '.ini', '.env',
            '.yml', '.yaml', '.json', '.sql'
        ]
        
        # Files to always scan regardless of extension
        self.always_scan = [
            'Dockerfile', 'docker-compose', 'Makefile', '.htaccess',
            '.htpasswd', 'web.config', 'build.gradle', 'pom.xml'
        ]

    def should_scan_file(self, filepath):
        """Determine if a file should be scanned"""
        filename = os.path.basename(filepath)
        
        # Always scan certain files
        if filename in self.always_scan:
            return True
            
        # Check extensions
        return any(filepath.endswith(ext) for ext in self.scan_extensions)

    def scan_file(self, filepath, categories=None):
        """Scan a single file for vulnerabilities"""
        if not self.should_scan_file(filepath):
            return {}
            
        findings = defaultdict(list)
        # Track unique findings per line to avoid duplicates
        seen_findings = defaultdict(set)
        
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                
            # Check each pattern category
            for category, config in self.patterns.items():
                # Skip if category filtering is enabled and this category isn't selected
                if categories is not None and category not in categories:
                    continue
                    
                for pattern, description in config['patterns']:
                    # Use re.IGNORECASE and re.MULTILINE for better matching
                    matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
                    
                    for match in matches:
                        # Get line number
                        line_num = content[:match.start()].count('\n') + 1
                        
                        # Create a unique key for this finding
                        finding_key = f"{line_num}:{category}"
                        
                        # Skip if we already found a vulnerability in this category on this line
                        if finding_key in seen_findings[category]:
                            continue
                            
                        seen_findings[category].add(finding_key)
                        
                        # Get the line content
                        lines = content.splitlines()
                        if line_num <= len(lines):
                            line_content = lines[line_num - 1].strip()
                            
                            finding = {
                                'description': description,
                                'line': line_num,
                                'content': line_content[:100] + '...' if len(line_content) > 100 else line_content,
                                'match': match.group(0)
                            }
                            
                            findings[category].append(finding)
                            
        except Exception as e:
            # Silently skip files that can't be read
            pass
            
        return findings

    def print_findings(self, filepath, findings):
        """Print findings for a file"""
        if not findings:
            return
            
        print(f"\n{Fore.WHITE}{Style.BRIGHT}{'='*80}")
        print(f"{Fore.WHITE}{Style.BRIGHT}File: {filepath}")
        print(f"{Fore.WHITE}{Style.BRIGHT}{'='*80}")
        
        for category, items in findings.items():
            if items:
                color = self.patterns[category]['color']
                print(f"\n{color}{Style.BRIGHT}[{category.upper().replace('_', ' ')}]")
                
                for item in items:
                    print(f"{color}  Line {item['line']}: {item['description']}")
                    print(f"{color}  Found: {item['match']}")
                    print(f"{color}  Context: {item['content']}")
                    print()

    def scan_directory(self, directory, recursive=False, verbose=False, categories=None):
        """Scan a directory for vulnerabilities"""
        total_files = 0
        total_findings = 0
        files_with_findings = 0
        
        if recursive:
            # Walk through all subdirectories
            for root, dirs, files in os.walk(directory):
                # Skip hidden directories and common non-source directories
                dirs[:] = [d for d in dirs if not d.startswith('.') and d not in ['node_modules', 'vendor', '__pycache__']]
                
                for file in files:
                    filepath = os.path.join(root, file)
                    
                    if self.should_scan_file(filepath):
                        total_files += 1
                        if verbose:
                            print(f"{Fore.BLUE}Scanning: {filepath}")
                            
                        findings = self.scan_file(filepath, categories)
                        
                        if any(findings.values()):
                            files_with_findings += 1
                            total_findings += sum(len(items) for items in findings.values())
                            self.print_findings(filepath, findings)
        else:
            # Only scan files in the specified directory
            for file in os.listdir(directory):
                filepath = os.path.join(directory, file)
                
                if os.path.isfile(filepath) and self.should_scan_file(filepath):
                    total_files += 1
                    if verbose:
                        print(f"{Fore.BLUE}Scanning: {filepath}")
                        
                    findings = self.scan_file(filepath, categories)
                    
                    if any(findings.values()):
                        files_with_findings += 1
                        total_findings += sum(len(items) for items in findings.values())
                        self.print_findings(filepath, findings)
        
        # Print summary
        print(f"\n{Fore.WHITE}{Style.BRIGHT}{'='*80}")
        print(f"{Fore.WHITE}{Style.BRIGHT}SCAN SUMMARY")
        print(f"{Fore.WHITE}{Style.BRIGHT}{'='*80}")
        print(f"Total files scanned: {total_files}")
        print(f"Files with findings: {files_with_findings}")
        print(f"Total findings: {total_findings}")
        if categories:
            print(f"Categories scanned: {', '.join(categories)}")
        else:
            print(f"Categories scanned: All")

def show_categories():
    """Display available vulnerability categories"""
    scanner = SecurityScanner()
    
    print(f"{Fore.CYAN}{Style.BRIGHT}Available vulnerability categories:")
    print(f"{Fore.CYAN}{Style.BRIGHT}{'='*80}")
    
    category_map = {
        'credentials': '-c, --credentials',
        'sql_injection': '--sqli',
        'command_injection': '--cmd',
        'path_traversal': '--path',
        'interesting_files': '--interesting',
        'database_operations': '--db'
    }
    
    for category, config in scanner.patterns.items():
        flag = category_map.get(category, '')
        color = config['color']
        print(f"\n{color}{Style.BRIGHT}[{category.upper().replace('_', ' ')}] {flag}")
        print(f"{color}Examples of what this category detects:")
        # Show first 3 patterns as examples
        for i, (pattern, description) in enumerate(config['patterns'][:3]):
            print(f"{color}  • {description}")
        if len(config['patterns']) > 3:
            print(f"{color}  • ... and {len(config['patterns']) - 3} more patterns")

def test_patterns():
    """Test patterns against sample vulnerable code"""
    scanner = SecurityScanner()
    
    test_cases = [
        # Java: SQL injection via string concatenation + hardcoded DB credentials
        'String query = "SELECT message FROM item WHERE priority=\'"+priority+"\'";',
        'connectionProps.put("password", "SAMPLE_PASSWORD");',
        'connectionProps.put("user", "app_user");',
        'Statement stmt = conn.createStatement();',
        'conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/app_db",connectionProps);',

        # Other common patterns
        'sql = "SELECT * FROM users WHERE id=" + userId;',
        'password = "admin123"',
        'api_key = "sk-1234567890abcdef"',
    ]
    
    print(f"{Fore.CYAN}{Style.BRIGHT}Testing patterns against sample code...")
    print(f"{Fore.CYAN}{Style.BRIGHT}{'='*80}")
    
    for test in test_cases:
        print(f"\n{Fore.WHITE}Testing: {test}")
        found = False
        
        for category, config in scanner.patterns.items():
            for pattern, description in config['patterns']:
                match = re.search(pattern, test, re.IGNORECASE)
                if match:
                    print(f"{config['color']}  ✓ Matched [{category}]: {description}")
                    print(f"{config['color']}    Pattern: {pattern}")
                    print(f"{config['color']}    Matched text: '{match.group(0)}'")
                    found = True
        
        if not found:
            print(f"{Fore.RED}  ✗ No patterns matched!")
    
    print(f"\n{Fore.CYAN}{Style.BRIGHT}{'='*80}")
    print(f"{Fore.CYAN}Pattern test complete.")


def main():
    parser = argparse.ArgumentParser(
        description='Security Code Scanner - Scan source code for vulnerabilities and interesting information',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s /path/to/project          # Scan only files in the directory
  %(prog)s -r /path/to/project       # Recursively scan all subdirectories
  %(prog)s -r .                      # Recursively scan current directory
  %(prog)s -r -v /path/to/project    # Recursive scan with verbose output
  %(prog)s -f /path/to/file.java     # Scan a single file
  %(prog)s --test-patterns           # Test pattern matching (for debugging)
  %(prog)s --show-categories         # Show available vulnerability categories
  
Category filtering:
  %(prog)s -r -c /path/to/project    # Scan only for hardcoded credentials
  %(prog)s -r --sqli /path/to/project # Scan only for SQL injection
  %(prog)s -r --sqli --cmd /path       # Scan for SQLi and command injection
  %(prog)s -r -A /path/to/project    # Scan all categories (default)

Typical workflow (reviewing source pulled from a target):
  %(prog)s -r ./target-source/                 # sweep the whole codebase
  %(prog)s -r --sqli --cmd ./target-source/    # focus on injection sinks
  %(prog)s -r -c ./target-source/              # hunt hardcoded credentials
        """
    )
    
    parser.add_argument('directory', nargs='?', help='Directory to scan (or file with -f)')
    parser.add_argument('-r', '--recursive', action='store_true', 
                       help='Recursively scan subdirectories')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Show all files being scanned')
    parser.add_argument('-f', '--file', action='store_true',
                       help='Scan a single file instead of directory')
    parser.add_argument('--test-patterns', action='store_true',
                       help='Test patterns against a specific string (for debugging)')
    parser.add_argument('--show-categories', action='store_true',
                       help='Show available vulnerability categories and exit')
    
    # Category filtering arguments
    category_group = parser.add_argument_group('category filters', 
                                             'Scan for specific vulnerability types (default: all)')
    category_group.add_argument('-A', '--all', action='store_true', 
                              help='Scan all categories (default)')
    category_group.add_argument('-c', '--credentials', action='store_true',
                              help='Scan for hardcoded credentials only')
    category_group.add_argument('--sqli', action='store_true',
                              help='Scan for SQL injection vulnerabilities only')
    category_group.add_argument('--cmd', action='store_true',
                              help='Scan for command injection vulnerabilities only')
    category_group.add_argument('--path', action='store_true',
                              help='Scan for path traversal vulnerabilities only')
    category_group.add_argument('--interesting', action='store_true',
                              help='Scan for interesting files and functions only')
    category_group.add_argument('--db', action='store_true',
                              help='Scan for database operations only')
    
    args = parser.parse_args()
    
    # If show categories mode, display and exit
    if args.show_categories:
        show_categories()
        sys.exit(0)
    
    # If test patterns mode, run tests and exit
    if args.test_patterns:
        test_patterns()
        sys.exit(0)
    
    # Check if directory is provided for normal mode
    if not args.directory:
        parser.error("Directory/file argument is required when not using --test-patterns or --show-categories")
    
    # Determine which categories to scan
    categories = None
    if not args.all:  # If -A/--all is not specified, check for specific categories
        selected_categories = []
        if args.credentials:
            selected_categories.append('credentials')
        if args.sqli:
            selected_categories.append('sql_injection')
        if args.cmd:
            selected_categories.append('command_injection')
        if args.path:
            selected_categories.append('path_traversal')
        if args.interesting:
            selected_categories.append('interesting_files')
        if args.db:
            selected_categories.append('database_operations')
        
        # If any categories were selected, use them; otherwise scan all
        if selected_categories:
            categories = selected_categories
    
    # Create scanner and run scan
    scanner = SecurityScanner()
    
    if args.file:
        # Single file mode
        if not os.path.isfile(args.directory):
            print(f"{Fore.RED}Error: '{args.directory}' is not a valid file")
            sys.exit(1)
            
        print(f"{Fore.CYAN}{Style.BRIGHT}Starting security scan...")
        print(f"File: {os.path.abspath(args.directory)}")
        if categories:
            print(f"Categories: {', '.join(categories)}")
        
        findings = scanner.scan_file(args.directory, categories)
        if findings:
            scanner.print_findings(args.directory, findings)
            print(f"\n{Fore.WHITE}{Style.BRIGHT}{'='*80}")
            print(f"{Fore.WHITE}{Style.BRIGHT}Total findings: {sum(len(items) for items in findings.values())}")
        else:
            print(f"\n{Fore.GREEN}No security issues found in this file.")
    else:
        # Directory mode
        if not os.path.isdir(args.directory):
            print(f"{Fore.RED}Error: '{args.directory}' is not a valid directory")
            sys.exit(1)
            
        print(f"{Fore.CYAN}{Style.BRIGHT}Starting security scan...")
        print(f"Directory: {os.path.abspath(args.directory)}")
        print(f"Mode: {'Recursive' if args.recursive else 'Non-recursive'}")
        if categories:
            print(f"Categories: {', '.join(categories)}")
        
        scanner.scan_directory(args.directory, args.recursive, args.verbose, categories)

if __name__ == '__main__':
    main()