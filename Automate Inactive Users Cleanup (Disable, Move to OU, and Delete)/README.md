
# Clean Up Inactive Active Directory User Accounts with PowerShell

Inactive user accounts can increase security risks and create unnecessary clutter in your Active Directory environment. This PowerShell script helps administrators identify inactive users based on their true last logon activity and automate cleanup actions such as disabling, moving, or deleting accounts in a single execution.

## Sample Output:

The script generates a detailed log of cleanup operations, tracking whether inactive user accounts were successfully disabled, moved, or deleted for auditing purposes.The script exports a CSV file similar to the screenshot below:

![Inactive Active Directory user cleanup report](https://o365reports.com/wp-content/uploads/2026/06/Cleanup-inactive-user-accounts-in-Active-Directory-Sample-Output-1536x385.png?v=1782811670)
The output CSV file includes key inactive user details such as username, UPN, account status, last logon time, inactive days, OU path, and other relevant attributes. 

## Simplify Active Directory Management with AdminDroid

Need more than what this script offers? Simplify inactive user lifecycle management with AdminDroid by identifying inactive users, taking actions directly from reports. Also, manage accounts with built-in actions to move, disable, or delete users. Apply approval workflows for critical tasks and automate routine administration with scheduled reports.

Explore the [AdminDroid Active Directory management tool](https://admindroid.com/active-directory-management-tool?src=GitHub) to access advanced reporting, management actions, automation, and deep security insights. Access 450+ reports, 60+ management actions, interactive dashboards, and more from a single console to efficiently manage Active Directory objects.

*Automate inactive user cleanup and streamline your Active Directory management with AdminDroid.*

*<https://demo.admindroid.com/#/management/all-actions/100/-1?nodeId=6920>*