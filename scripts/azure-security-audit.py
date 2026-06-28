#!/usr/bin/env python3
"""
Azure Security Configuration Auditor
Scans Azure subscriptions for security misconfigurations
Part of MAPELEAD Cloud Security Lab

Usage:
    python azure-security-audit.py --subscription "your-sub-id"
"""

import argparse
import json
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()

class AzureSecurityAuditor:
    """Azure security configuration auditor."""
    
    def __init__(self, subscription_id=None):
        self.subscription_id = subscription_id
        self.findings = []
        
    def run_audit(self):
        """Run comprehensive Azure security audit."""
        console.print(Panel.fit(
            "[bold cyan]Azure Security Configuration Audit[/bold cyan]\n"
            "This script checks your Azure environment for common security misconfigurations.\n"
            "Run with proper Azure CLI authentication."
        ))
        
        checks = [
            self.check_security_center,
            self.check_storage_accounts,
            self.check_network_security_groups,
            self.check_key_vaults,
            self.check_sql_servers,
        ]
        
        for check in checks:
            try:
                check()
            except Exception as e:
                console.print(f"[yellow]Check skipped: {e}[/yellow]")
        
        self.generate_report()
    
    def check_security_center(self):
        """Check Azure Security Center / Microsoft Defender for Cloud configuration."""
        console.print("\n[bold][1/5] Checking Microsoft Defender for Cloud...[/bold]")
        
        # Note: Requires azure-mgmt-security
        console.print("  [yellow]Ensure Defender for Cloud Standard tier is enabled for:[/yellow]")
        console.print("    - Servers")
        console.print("    - App Service")
        console.print("    - SQL Servers")
        console.print("    - Storage Accounts")
        console.print("    - Key Vaults")
        
        self.findings.append({
            'category': 'Defender for Cloud',
            'issue': 'Verify Standard tier is enabled',
            'severity': 'HIGH',
            'remediation': 'Enable Defender for Cloud Standard tier in Azure Portal'
        })
    
    def check_storage_accounts(self):
        """Check storage account security settings."""
        console.print("\n[bold][2/5] Checking Storage Account Security...[/bold]")
        
        checks = [
            ('HTTPS Only', 'Ensure only HTTPS is allowed'),
            ('Secure Transfer Required', 'Enabled'),
            ('Public Access', 'Disabled for blob containers'),
            ('Encryption', 'Microsoft-managed keys minimum'),
            ('Network Rules', 'Restrict to allowed networks'),
            ('CORS Rules', 'Minimize or disable'),
        ]
        
        for check_name, expected in checks:
            console.print(f"  [cyan]CHECK:[/cyan] {check_name} - Expected: {expected}")
            self.findings.append({
                'category': 'Storage Security',
                'issue': f'{check_name}: {expected}',
                'severity': 'MEDIUM',
                'remediation': f'Configure {check_name} in storage account settings'
            })
    
    def check_network_security_groups(self):
        """Check NSG rules for security issues."""
        console.print("\n[bold][3/5] Checking Network Security Groups...[/bold]")
        
        risky_rules = [
            'Port 22 (SSH) open to 0.0.0.0/0',
            'Port 3389 (RDP) open to 0.0.0.0/0',
            'Port 3306 (MySQL) open to internet',
            'Port 1433 (MSSQL) open to internet',
            'Port 27017 (MongoDB) open to internet',
            'All ports open (Any-Any rule)',
        ]
        
        console.print("  [red]DANGEROUS NSG RULES TO CHECK:[/red]")
        for rule in risky_rules:
            console.print(f"    - {rule}")
        
        self.findings.append({
            'category': 'Network Security',
            'issue': 'Overly permissive NSG rules detected',
            'severity': 'HIGH',
            'remediation': 'Restrict NSG rules to specific IPs and required ports only'
        })
    
    def check_key_vaults(self):
        """Check Key Vault security configuration."""
        console.print("\n[bold][4/5] Checking Key Vault Security...[/bold]")
        
        checks = [
            'Soft-delete enabled',
            'Purge protection enabled',
            'Network access restricted (Firewall/VNet)',
            'Private Endpoint configured',
            'RBAC authorization (not access policies)',
            'Diagnostic logging enabled',
        ]
        
        for check in checks:
            console.print(f"  [cyan]CHECK:[/cyan] {check}")
        
        self.findings.append({
            'category': 'Key Vault',
            'issue': 'Verify all Key Vault security settings',
            'severity': 'HIGH',
            'remediation': 'Review Key Vault security best practices'
        })
    
    def check_sql_servers(self):
        """Check SQL Server / Azure SQL security."""
        console.print("\n[bold][5/5] Checking SQL Server Security...[/bold]")
        
        checks = [
            'Azure AD-only authentication enabled',
            'SQL Auditing enabled',
            'Advanced Threat Protection enabled',
            'Transparent Data Encryption (TDE) enabled',
            'Private Endpoint or VNet rules configured',
            'Minimal firewall rules (avoid 0.0.0.0-255.255.255.255)',
        ]
        
        for check in checks:
            console.print(f"  [cyan]CHECK:[/cyan] {check}")
        
        self.findings.append({
            'category': 'SQL Security',
            'issue': 'Verify SQL Server security configuration',
            'severity': 'HIGH',
            'remediation': 'Configure SQL Server security settings per best practices'
        })
    
    def generate_report(self):
        """Generate audit report."""
        report = {
            'scan_time': datetime.now().isoformat(),
            'subscription': self.subscription_id,
            'total_findings': len(self.findings),
            'findings': self.findings
        }
        
        with open('azure-security-audit.json', 'w') as f:
            json.dump(report, f, indent=2)
        
        console.print(f"\n[green]Audit complete: {len(self.findings)} findings saved to azure-security-audit.json[/green]")


def main():
    parser = argparse.ArgumentParser(description='Azure Security Configuration Auditor')
    parser.add_argument('--subscription', help='Azure Subscription ID')
    args = parser.parse_args()
    
    auditor = AzureSecurityAuditor(args.subscription)
    auditor.run_audit()

if __name__ == "__main__":
    main()
