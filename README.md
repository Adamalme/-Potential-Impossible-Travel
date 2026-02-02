🚨 Potential-Impossible Travel-Sentinel Detection & Investigation

-------------------------------------------------------------------------------------

Author: Adam Alme
Date: May 5, 2025
Type: Detection & Incident Response
Tools: Microsoft Sentinel, KQL, Azure AD
MITRE ATT&CK Mapping: T1078: Valid Accounts & T1110: Brute Force (supporting context if credentials were stolen)

<img width="1024" height="1024" alt="image" src="https://github.com/user-attachments/assets/4ef1ff07-e5b6-458d-81a6-eca0965cab9e" />

--------------------------------------------------------------------------------------------------------------------------------------

📘 Scenario Overview
-----------------------------------------------------------------

Some organizations have strict policies against account sharing, VPN obfuscation, or logins from outside designated regions. This lab focuses on identifying "impossible travel" — when a single user logs in from two or more distant geographic locations within a short timeframe.

The objective is to identify anomalous sign-in activity using Azure AD SigninLogs, generate alerts within Microsoft Sentinel, and perform a comprehensive investigation to determine whether the activity represents legitimate user behavior or malicious activity.

--------------------------------------------------------------------------------------------------------------------------------

🔍 Step 1: Query for Impossible Travel (30-day Range)
-------------------------------------------------------------------------------------------------------------------------------

This KQL query detects users logging in from more than one location within the last 30 days:

```KQL
let TimePeriodThreshold = timespan(30d);
let NumberOfDifferentLocationsAllowed = 1;
SigninLogs
| where TimeGenerated > ago(TimePeriodThreshold)
| summarize Count = count() by UserPrincipalName, UserId, 
    City = tostring(parse_json(LocationDetails).city), 
    State = tostring(parse_json(LocationDetails).state), 
    Country = tostring(parse_json(LocationDetails).countryOrRegion)
| project UserPrincipalName, UserId, City, State, Country
| summarize PotentialImpossibleTravelInstances = count() by UserPrincipalName, UserId
| where PotentialImpossibleTravelInstances > NumberOfDifferentLocationsAllowed
```
📌 Sample Output

🌍 Impossible Travel Detection
🎯 Purpose

* Identify users authenticating from multiple countries within unrealistic timeframes
* Detect potential credential compromise, VPN abuse, or session hijacking

```KQL
SigninLogs
| where TimeGenerated > ago(30d)
| extend Loc = parse_json(LocationDetails)
| extend Country = tostring(Loc.countryOrRegion)
| summarize
    SignInCount = count(),
    Countries = make_set(Country)
    by UserPrincipalName
| order by SignInCount desc
```
📸 Evidence

<img width="1081" height="1219" alt="image" src="https://github.com/user-attachments/assets/9a924253-6fbc-4d33-ab6d-e76438f2dbc8" />

-------------------------------------------------------------------------------------------------------------------------------------

🧭 Analyst Assessment & Response

* The user account was observed authenticating from multiple geographic locations, triggering an impossible travel / brute-force detection.
* This behavior may indicate credential compromise or automated attack activity.

🛠️ Remediation & Monitoring Actions

* Account Reset: The user account password was reset to immediately contain potential compromise.
* Security Enforcement: MFA remains enforced to prevent unauthorized access.
* Device Monitoring: The affected device will be closely monitored for any additional suspicious authentication or activity attempts.

📌 Status

* Immediate risk contained
* Ongoing monitoring in place
* 
Validation — Audit Log Review

```kql
AuditLogs
| where OperationName in (
    "Change user password",
    "Reset user password"
)
| extend TargetUser = tostring(TargetResources[0].userPrincipalName)
| project
    TimeGenerated,
    OperationName,
    TargetUser,
    InitiatedBy = tostring(InitiatedBy.user.userPrincipalName),
    Result
| order by TimeGenerated desc
```
<img width="1234" height="496" alt="image" src="https://github.com/user-attachments/assets/f37e1c55-b375-45f3-906c-4129f79da695" />

## 🔎 Account Remediation Verification & Ongoing Monitoring

As part of the incident containment process, the following actions were verified:

- The affected user’s password was successfully reset.
- Azure Audit Logs were reviewed to confirm the password reset was properly recorded and completed.
- No unauthorized or unexpected password changes were detected during log analysis.
- The account remains under continuous monitoring to identify any further authentication attempts or suspicious activity.

## 📌 Status

- ✅ Containment action verified  
- ✅ No additional malicious activity observed  
- 🔄 Ongoing monitoring active




  
  

















