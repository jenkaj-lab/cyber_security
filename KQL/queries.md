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
```
// Retrieve a count of logons by Result Type
let usernames = dynamic(["USERNAME1", "USERNAME2"]);  
SigninLogs
| where UserDisplayName in~ (usernames) or UserPrincipalName in~ (usernames)    
//| where AppDisplayName == "Office 365 Exchange Online"
| extend FormattedTime = format_datetime(TimeGenerated, "HH:mm:ss - dd/MM/yyyy")  
| order by FormattedTime desc   
| summarize Count = count() by ResultType, UserDisplayName
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
let username = ""; // paste a username WITHOUT a domain 
IdentityInfo
| where AccountName has username or AccountUPN has username or AccountDisplayName has username
| where TimeGenerated > ago(7d)
| order by TimeGenerated desc
| project AccountDisplayName, UserType, JobTitle, Department, AssignedRoles, GroupMembership
```
# Email Events
Find out what's happened to an email i.e. has it been quarantined?
```
EmailEvents
| where RecipientEmailAddress == ""
| where SenderFromAddress == ""
```
