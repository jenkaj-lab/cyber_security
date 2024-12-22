# Windows Sign-ins
'''
let username = "";
SigninLogs
| where UserDisplayName contains username or UserPrincipalName contains username
| where ResultType == 0 // successful logins
//| where IPAddress == ""
| extend FormattedTime = format_datetime(TimeGenerated, "HH:mm:ss - dd/MM/yyyy")
| order by FormattedTime desc
| project FormattedTime, IPAddress, Status, DeviceDetail, AuthenticationDetails
//| summarize Count = count() by ResultType, ResultDescription
'''
