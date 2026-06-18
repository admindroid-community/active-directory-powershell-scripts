## Get Users True Last Logon Using PowerShell Script in Active Directory
Tracking the true last logon time of Active Directory users can be challenging, as the lastLogon attribute is not replicated between domain controllers. Each DC therefore contains only a partial view of user logon activity. This PowerShell script queries all DCs to provide accurate last logon details for all domain users.  

*Sample Output:*

This script exports accurate Active Directory users’ last logon details to a CSV file. A sample output is shown in the screenshot below.  

![Get users true last logon report](https://o365reports.com/wp-content/uploads/2026/05/Accurate-Last-Logon-Report-Using-PowerShell.png)
## Free Active Directory Reporting Tool by AdminDroid
Need deeper visibility into users' true last logon times without relying on scripts? Try AdminDroid's [free Active Directory reporting tool.](https://admindroid.com/active-directory-reporting-tool/?src=GitHub) With 200+ free reports and 10+ dashboards, you can gain valuable insights into your Active Directory environment and simplify day to day administration.

Get complete visibility and control over Active Directory: <https://demo.admindroid.com/#/AD/50/2/reports/5000118/1/20?nodeId=7191>

