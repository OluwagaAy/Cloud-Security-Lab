# Lab 01: IAM & Identity Security in Azure

> Duration: 2 hours | Level: Beginner-Intermediate

---

## 🎯 Learning Objectives

By the end of this lab, you will be able to:
- Configure Azure Entra ID security policies
- Implement Multi-Factor Authentication (MFA)
- Manage privileged access with PIM (Privileged Identity Management)
- Create and enforce Conditional Access policies
- Audit identity configurations

---

## 📋 Pre-Lab Setup

### Requirements
- Azure subscription (free tier acceptable)
- Global Administrator or Security Administrator role
- Azure CLI installed

### Setup Steps
```bash
# Login to Azure
az login

# Set your subscription
az account set --subscription "your-subscription-name"

# Verify access
az ad signed-in-user show --query userPrincipalName
```

---

## 🧪 Exercise 1: MFA Enforcement

### Scenario
Your organization requires all users to have MFA enabled. You need to verify current MFA status and enforce it.

### Steps
1. Navigate to **Azure Portal > Entra ID > Users > All Users**
2. Click **Per-user MFA** to check current status
3. Note which users don't have MFA configured
4. Create a Conditional Access policy to enforce MFA

### Verification
```bash
# Check MFA status via CLI (simplified)
az ad user list --query "[].{Name:displayName, UPN:userPrincipalName, Enabled:accountEnabled}"
```

### Key Questions
- What MFA methods are available in Azure?
- What's the difference between Security Defaults and Conditional Access?
- How do you handle MFA for service accounts?

---

## 🧪 Exercise 2: Privileged Access Management with PIM

### Scenario
Too many users have permanent Global Admin access. Implement PIM to require approval and time-limited access.

### Steps
1. Go to **Entra ID > Privileged Identity Management**
2. Configure **Azure AD Roles**
3. Convert permanent Global Admins to **Eligible**
4. Set activation settings:
   - Maximum activation duration: 4 hours
   - Require approval: Yes
   - Require MFA on activation: Yes

### Verification
- Request activation of Global Admin role
- Note the approval workflow
- Observe the time-limited access

---

## 🧪 Exercise 3: Conditional Access Policy

### Scenario
Block legacy authentication and require compliant devices for admin accounts.

### Policy Configuration
```
Name: Block Legacy Auth + Require Compliant Device
Assignments:
  - Users: All users
  - Cloud apps: All cloud apps
Conditions:
  - Client apps: Exchange ActiveSync, Other clients
Access controls:
  - Grant: Block access
```

### Verification
- Attempt login with an older email client
- Verify the block works
- Check sign-in logs for blocked attempts

---

## 📊 Assessment

| Criteria | Points |
|----------|--------|
| MFA configured for all users | 30 |
| PIM activated for privileged roles | 30 |
| Conditional Access policy created | 20 |
| Legacy auth blocked | 20 |
| **Total** | **100** |

---

## 📚 Additional Resources

- [Microsoft Learn: Secure Azure with Entra ID](https://learn.microsoft.com)
- [Azure Security Benchmark - Identity Management](https://learn.microsoft.com)
- [Zero Trust Architecture Guide](https://learn.microsoft.com)

---

*Part of MAPELEAD Cloud Security Lab | Module 01*
