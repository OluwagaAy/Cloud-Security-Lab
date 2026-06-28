#!/usr/bin/env python3
"""
AWS IAM Security Audit Script
Audits AWS IAM configuration for security best practices
Part of MAPELEAD Cloud Security Lab - Module 01: IAM Security

Usage:
    python iam-security-audit.py --profile default
    python iam-security-audit.py --access-key AKIA... --secret-key ...
"""

import boto3
import json
import argparse
from datetime import datetime, timedelta
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()

class AWSIAMAuditor:
    def __init__(self, profile=None, access_key=None, secret_key=None, region='us-east-1'):
        if profile:
            self.session = boto3.Session(profile_name=profile)
        elif access_key and secret_key:
            self.session = boto3.Session(aws_access_key_id=access_key,
                                         aws_secret_access_key=secret_key,
                                         region_name=region)
        else:
            self.session = boto3.Session()
        
        self.iam = self.session.client('iam')
        self.results = {
            'scan_time': datetime.now().isoformat(),
            'checks': [],
            'findings': []
        }

    def check_root_account(self):
        """Check root account security settings."""
        console.print("[cyan][1/7] Checking Root Account Security...[/cyan]")
        
        try:
            summary = self.iam.get_account_authorization_details()
            
            # Check root MFA
            try:
                mfa_devices = self.iam.list_mfa_devices(UserName='root')
                root_mfa = len(mfa_devices['MFADevices']) > 0
            except:
                root_mfa = False
            
            finding = {
                'check': 'Root Account MFA',
                'status': 'PASS' if root_mfa else 'FAIL',
                'severity': 'CRITICAL',
                'remediation': 'Enable MFA on root account immediately'
            }
            self.results['findings'].append(finding)
            
            status_color = 'green' if root_mfa else 'red'
            console.print(f"  Root MFA: [{status_color}]{'Enabled' if root_mfa else 'NOT ENABLED'}[/{status_color}]")
            
        except Exception as e:
            console.print(f"  [red]Error: {e}[/red]")

    def check_password_policy(self):
        """Check IAM password policy."""
        console.print("[cyan][2/7] Checking Password Policy...[/cyan]")
        
        try:
            policy = self.iam.get_account_password_policy()['PasswordPolicy']
            
            checks = {
                'MinimumPasswordLength': (policy.get('MinimumPasswordLength', 0) >= 14, 'Minimum 14 characters'),
                'RequireSymbols': (policy.get('RequireSymbols', False), 'Require symbols'),
                'RequireNumbers': (policy.get('RequireNumbers', False), 'Require numbers'),
                'RequireUppercaseCharacters': (policy.get('RequireUppercaseCharacters', False), 'Require uppercase'),
                'RequireLowercaseCharacters': (policy.get('RequireLowercaseCharacters', False), 'Require lowercase'),
                'MaxPasswordAge': (policy.get('MaxPasswordAge', 999) <= 90, 'Maximum password age 90 days'),
                'PasswordReusePrevention': (policy.get('PasswordReusePrevention', 0) >= 5, 'Prevent password reuse (5+)'),
            }
            
            for check_name, (passed, description) in checks.items():
                status = 'PASS' if passed else 'WARN'
                color = 'green' if passed else 'yellow'
                console.print(f"  [{color}]{status}[/{color}] {description}")
                
                if not passed:
                    self.results['findings'].append({
                        'check': f'Password Policy: {check_name}',
                        'status': 'WARN',
                        'severity': 'MEDIUM',
                        'remediation': description
                    })
                    
        except self.iam.exceptions.NoSuchEntityException:
            console.print("  [red]No password policy set![/red]")
            self.results['findings'].append({
                'check': 'Password Policy',
                'status': 'FAIL',
                'severity': 'HIGH',
                'remediation': 'Set a strong IAM password policy'
            })

    def check_access_keys(self):
        """Check for old or unused access keys."""
        console.print("[cyan][3/7] Checking Access Keys...[/cyan]")
        
        users = self.iam.list_users()['Users']
        old_keys = 0
        unused_keys = 0
        
        for user in users:
            try:
                keys = self.iam.list_access_keys(UserName=user['UserName'])['AccessKeyMetadata']
                for key in keys:
                    # Check age
                    key_age = (datetime.now(key['CreateDate'].tzinfo) - key['CreateDate']).days
                    if key_age > 90:
                        old_keys += 1
                    
                    # Check last used
                    try:
                        last_used = self.iam.get_access_key_last_used(AccessKeyId=key['AccessKeyId'])
                        if 'LastUsedDate' not in last_used.get('AccessKeyLastUsed', {}):
                            if key_age > 30:
                                unused_keys += 1
                    except:
                        pass
            except Exception as e:
                continue
        
        console.print(f"  Access keys older than 90 days: {old_keys}")
        console.print(f"  Unused access keys: {unused_keys}")
        
        if old_keys > 0:
            self.results['findings'].append({
                'check': 'Old Access Keys',
                'status': 'WARN',
                'severity': 'MEDIUM',
                'remediation': f'Rotate {old_keys} access keys older than 90 days'
            })

    def check_mfa_usage(self):
        """Check MFA enrollment for IAM users."""
        console.print("[cyan][4/7] Checking MFA Enrollment...[/cyan]")
        
        users = self.iam.list_users()['Users']
        total_users = len(users)
        mfa_enabled = 0
        console_access_without_mfa = []
        
        for user in users:
            try:
                mfa_devices = self.iam.list_mfa_devices(UserName=user['UserName'])['MFADevices']
                if mfa_devices:
                    mfa_enabled += 1
                
                # Check if user has console access without MFA
                login_profile = self.iam.get_login_profile(UserName=user['UserName'])
                if login_profile and not mfa_devices:
                    console_access_without_mfa.append(user['UserName'])
            except self.iam.exceptions.NoSuchEntityException:
                # No console access - OK
                pass
            except Exception as e:
                continue
        
        console.print(f"  Users with MFA: {mfa_enabled}/{total_users}")
        console.print(f"  Console access without MFA: {len(console_access_without_mfa)}")
        
        if console_access_without_mfa:
            self.results['findings'].append({
                'check': 'MFA for Console Users',
                'status': 'FAIL',
                'severity': 'HIGH',
                'remediation': f'Enable MFA for {len(console_access_without_mfa)} users with console access'
            })

    def check_unused_credentials(self):
        """Check for unused IAM credentials."""
        console.print("[cyan][5/7] Checking Unused Credentials...[/cyan]")
        
        # Get credential report
        try:
            self.iam.generate_credential_report()
        except:
            pass
        
        import time
        time.sleep(5)  # Wait for report generation
        
        try:
            report = self.iam.get_credential_report()['Content'].decode('utf-8')
            console.print("  [yellow]Review credential report in AWS Console for unused credentials[/yellow]")
        except Exception as e:
            console.print(f"  [yellow]Credential report unavailable: {e}[/yellow]")

    def check_inline_policies(self):
        """Check for overly permissive inline policies."""
        console.print("[cyan][6/7] Checking IAM Policies...[/cyan]")
        
        dangerous_actions = ['*:*', 'iam:*', 's3:*', 'ec2:*']
        risky_policies = []
        
        users = self.iam.list_users()['Users']
        for user in users:
            try:
                policies = self.iam.list_user_policies(UserName=user['UserName'])['PolicyNames']
                for policy_name in policies:
                    policy = self.iam.get_user_policy(UserName=user['UserName'], PolicyName=policy_name)
                    policy_doc = policy['PolicyDocument']
                    
                    # Check for wildcard permissions
                    for statement in policy_doc.get('Statement', []):
                        actions = statement.get('Action', [])
                        if isinstance(actions, str):
                            actions = [actions]
                        for action in actions:
                            if action in dangerous_actions:
                                risky_policies.append({
                                    'user': user['UserName'],
                                    'policy': policy_name,
                                    'action': action
                                })
            except Exception as e:
                continue
        
        console.print(f"  Overly permissive inline policies: {len(risky_policies)}")
        for rp in risky_policies:
            console.print(f"    [red]User: {rp['user']}, Action: {rp['action']}[/red]")
        
        if risky_policies:
            self.results['findings'].append({
                'check': 'Overly Permissive Policies',
                'status': 'FAIL',
                'severity': 'HIGH',
                'remediation': f'Review and restrict {len(risky_policies)} wildcard permissions'
            })

    def generate_report(self):
        """Generate final audit report."""
        critical = len([f for f in self.results['findings'] if f['severity'] == 'CRITICAL'])
        high = len([f for f in self.results['findings'] if f['severity'] == 'HIGH'])
        medium = len([f for f in self.results['findings'] if f['severity'] == 'MEDIUM'])
        
        total_score = max(0, 100 - (critical * 20 + high * 10 + medium * 5))
        
        console.print("\n" + "="*50)
        console.print("[bold]AWS IAM Security Audit Report[/bold]")
        console.print("="*50)
        console.print(f"Critical: {critical} | High: {high} | Medium: {medium}")
        console.print(f"Security Score: {total_score}/100")
        
        # Save to file
        with open('aws-iam-audit-report.json', 'w') as f:
            json.dump(self.results, f, indent=2, default=str)
        console.print("\n[green]Report saved to aws-iam-audit-report.json[/green]")

def main():
    parser = argparse.ArgumentParser(description='AWS IAM Security Auditor')
    parser.add_argument('--profile', help='AWS profile name')
    parser.add_argument('--access-key', help='AWS Access Key ID')
    parser.add_argument('--secret-key', help='AWS Secret Access Key')
    parser.add_argument('--region', default='us-east-1', help='AWS Region')
    args = parser.parse_args()
    
    console.print("[bold]AWS IAM Security Audit[/bold]")
    console.print("Part of MAPELEAD Cloud Security Lab\n")
    
    auditor = AWSIAMAuditor(
        profile=args.profile,
        access_key=args.access_key,
        secret_key=args.secret_key,
        region=args.region
    )
    
    auditor.check_root_account()
    auditor.check_password_policy()
    auditor.check_access_keys()
    auditor.check_mfa_usage()
    auditor.check_unused_credentials()
    auditor.check_inline_policies()
    auditor.generate_report()

if __name__ == "__main__":
    main()
