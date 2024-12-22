# Windows Sign-ins
```
let username = "";  
SigninLogs  
| where UserDisplayName has username or UserPrincipalName has username  
| where ResultType == 0 // successful logins  
//| where IPAddress == ""  
| extend FormattedTime = format_datetime(TimeGenerated, "HH:mm:ss - dd/MM/yyyy")  
| order by FormattedTime desc  
| project FormattedTime, IPAddress, Status, DeviceDetail, AuthenticationDetails  
//| summarize Count = count() by ResultType, ResultDescription  
```
# AWS CloudTrail Console Logins
```
let username = "";
AWSCloudTrail
| where UserIdentityPrincipalid has username
| where EventName == "ConsoleLogin"
//| where SourceIpAddress == ""
| extend FormattedTime = format_datetime(TimeGenerated, "HH:mm:ss - dd/MM/yyyy")
| order by FormattedTime desc
```
# Identity Info
Get job title, user type, and assigned roles
```
let username = "";
IdentityInfo
| where AccountName has username or AccountUPN has username or AccountDisplayName has username
| where TimeGenerated > ago(7d)
| order by TimeGenerated desc
| limit 1
| project AccountDisplayName, UserType, JobTitle, Department, AssignedRoles, GroupMembership
```
