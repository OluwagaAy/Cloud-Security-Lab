#Requires -Modules Az.Accounts, Az.Resources, Az.KeyVault
<#
.SYNOPSIS
    Azure Entra ID (formerly Azure AD) Security Assessment Script
    
.DESCRIPTION
    Audits Azure tenant security configuration including MFA status,
    privileged roles, guest access, password policies, and conditional access.
    
    Part of MAPELEAD Cloud Security Lab - Module 01: IAM Security
    
.EXAMPLE
    .\entra-id-security-check.ps1 -TenantId "your-tenant-id"
    
.NOTES
    Author: Ayomide Oluwaga (MAPELEAD)
    Requires: Azure PowerShell module, Global Reader or Security Reader role
#>

param(
    [Parameter(Mandatory=$false)]
    [string]$TenantId,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputPath = "./azure-iam-audit-report.json"
)

# Color output
function Write-Status($Message, $Status) {
    switch ($Status) {
        "PASS" { Write-Host "[+] $Message" -ForegroundColor Green }
        "FAIL" { Write-Host "[-] $Message" -ForegroundColor Red }
        "WARN" { Write-Host "[!] $Message" -ForegroundColor Yellow }
        "INFO" { Write-Host "[*] $Message" -ForegroundColor Cyan }
    }
}

# Results collection
$AuditResults = @{
    TenantId = $TenantId
    ScanDate = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    Checks = @()
    Summary = @{}
}

Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  Azure Entra ID Security Assessment" -ForegroundColor Cyan
Write-Host "  MAPELEAD Cloud Security Lab" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

# 1. Check connection
Write-Status "Connecting to Azure..." "INFO"
try {
    $Context = Get-AzContext
    if (-not $Context) {
        Connect-AzAccount -TenantId $TenantId
        $Context = Get-AzContext
    }
    Write-Status "Connected to tenant: $($Context.Tenant.Id)" "PASS"
    $AuditResults.TenantId = $Context.Tenant.Id
} catch {
    Write-Status "Failed to connect: $_" "FAIL"
    exit 1
}

# 2. Check MFA Registration Status
Write-Host "`n[1] Checking MFA Registration Status..." -ForegroundColor Cyan
$Users = Get-AzADUser -All
$TotalUsers = $Users.Count
$MfaRegistered = 0
$MfaNotRegistered = 0

foreach ($User in $Users | Select-Object -First 50) {
    # Note: In production, use Microsoft Graph API for accurate MFA status
    # This is a simplified check for lab purposes
    if ($User.AccountEnabled -eq $true) {
        if ($User.StrongAuthenticationRequirements) {
            $MfaRegistered++
        } else {
            $MfaNotRegistered++
        }
    }
}

$MfaPercentage = if ($TotalUsers -gt 0) { [math]::Round(($MfaRegistered / $TotalUsers) * 100, 1) } else { 0 }

Write-Status "Total users: $TotalUsers" "INFO"
Write-Status "MFA adoption: $MfaPercentage%" $(if ($MfaPercentage -ge 80) { "PASS" } elseif ($MfaPercentage -ge 50) { "WARN" } else { "FAIL" })

$AuditResults.Checks += @{
    Check = "MFA Registration"
    TotalUsers = $TotalUsers
    MfaRegistered = $MfaRegistered
    MfaPercentage = $MfaPercentage
    Status = $(if ($MfaPercentage -ge 80) { "PASS" } else { "FAIL" })
}

# 3. Check Privileged Roles
Write-Host "`n[2] Checking Privileged Role Assignments..." -ForegroundColor Cyan
$PrivilegedRoles = @(
    "Global Administrator",
    "Privileged Role Administrator",
    "Security Administrator",
    "Exchange Administrator",
    "SharePoint Administrator"
)

$AdminCount = 0
$RoleAssignments = @()

foreach ($RoleName in $PrivilegedRoles) {
    try {
        $Role = Get-AzRoleDefinition -Name $RoleName -ErrorAction SilentlyContinue
        if ($Role) {
            $Assignments = Get-AzRoleAssignment -RoleDefinitionName $RoleName
            foreach ($Assignment in $Assignments) {
                $RoleAssignments += @{
                    Role = $RoleName
                    Principal = $Assignment.DisplayName
                    Type = $Assignment.ObjectType
                }
                $AdminCount++
            }
        }
    } catch {
        continue
    }
}

Write-Status "Total privileged assignments: $AdminCount" $(if ($AdminCount -le 10) { "PASS" } elseif ($AdminCount -le 20) { "WARN" } else { "FAIL" })

$AuditResults.Checks += @{
    Check = "Privileged Role Assignments"
    TotalAdmins = $AdminCount
    Assignments = $RoleAssignments
    Status = $(if ($AdminCount -le 10) { "PASS" } else { "WARN" })
}

# 4. Check Guest Access
Write-Host "`n[3] Checking Guest Access..." -ForegroundColor Cyan
$GuestUsers = $Users | Where-Object { $_.UserPrincipalName -like "*#EXT#*" -or $_.UserType -eq "Guest" }
$GuestCount = if ($GuestUsers) { $GuestUsers.Count } else { 0 }

Write-Status "Guest users: $GuestCount" $(if ($GuestCount -le 5) { "PASS" } elseif ($GuestCount -le 20) { "WARN" } else { "FAIL" })

$AuditResults.Checks += @{
    Check = "Guest User Access"
    GuestCount = $GuestCount
    Status = $(if ($GuestCount -le 5) { "PASS" } else { "WARN" })
}

# 5. Check Conditional Access Policies
Write-Host "`n[4] Checking Conditional Access Policies..." -ForegroundColor Cyan
# Note: Conditional Access requires Microsoft Graph API
# This is a placeholder check
Write-Status "Conditional Access: Manual review recommended via Azure Portal > Security > Conditional Access" "WARN"
Write-Status "Key policies to verify:" "INFO"
Write-Status "  - Require MFA for all users" "INFO"
Write-Status "  - Block legacy authentication" "INFO"
Write-Status "  - Require compliant devices" "INFO"
Write-Status "  - Block risky sign-ins" "INFO"

$AuditResults.Checks += @{
    Check = "Conditional Access Policies"
    Note = "Review manually in Azure Portal"
    Recommendations = @(
        "Require MFA for all users",
        "Block legacy authentication",
        "Require compliant devices",
        "Block risky sign-ins"
    )
    Status = "MANUAL_REVIEW"
}

# Summary
$PassCount = ($AuditResults.Checks | Where-Object { $_.Status -eq "PASS" }).Count
$WarnCount = ($AuditResults.Checks | Where-Object { $_.Status -eq "WARN" }).Count
$FailCount = ($AuditResults.Checks | Where-Object { $_.Status -eq "FAIL" }).Count

$AuditResults.Summary = @{
    Pass = $PassCount
    Warn = $WarnCount
    Fail = $FailCount
    Total = $AuditResults.Checks.Count
    Score = [math]::Round(($PassCount / $AuditResults.Checks.Count) * 100, 1)
}

# Save report
$AuditResults | ConvertTo-Json -Depth 10 | Out-File $OutputPath

# Print summary
Write-Host "`n============================================" -ForegroundColor Cyan
Write-Host "  Assessment Summary" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Status "Passed: $PassCount" $(if ($PassCount -gt 0) { "PASS" } else { "INFO" })
Write-Status "Warnings: $WarnCount" $(if ($WarnCount -gt 0) { "WARN" } else { "INFO" })
Write-Status "Failed: $FailCount" $(if ($FailCount -gt 0) { "FAIL" } else { "INFO" })
Write-Host "Security Score: $($AuditResults.Summary.Score)%" -ForegroundColor $(if ($AuditResults.Summary.Score -ge 80) { "Green" } elseif ($AuditResults.Summary.Score -ge 60) { "Yellow" } else { "Red" })
Write-Host "`nReport saved to: $OutputPath" -ForegroundColor Green
