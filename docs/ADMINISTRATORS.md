# Administrator approvals

With the **Administrator lock** on (Settings → Malware Lockdown), only accounts on an approved list keep administrator rights. Any other account with administrator powers is treated as having no capabilities, however it got them. This stops backdoor administrators such as the one SC writes straight into the database and hides from the Users screen.

## Where it is configured

* Sentinel Shield → Malware Lockdown → Administrators: lists every administrator account read directly from the database, including hidden ones, with Approve and Withdraw approval buttons.
* WP-CLI: `wp sentinel admins`, `wp sentinel approve-admin <user>`, `wp sentinel revoke-admin <user>` (user ID, login or email).
* Settings → Documentation shows the current approved list with who approved each account and when.
* Or fix the list in wp-config.php with `SENTINEL_SHIELD_ADMINS` (below), which replaces the database list entirely.

The list is stored in its own option (`sentinel_shield_admin_approvals`, network-wide on multisite). It is not a settings field, is not included in settings export/import and cannot be changed with `settings-set`, so importing settings never approves accounts. Approving or withdrawing needs full administrator rights (manage_options; manage_network_options on multisite); a locked account cannot approve itself.

## Fixing the list in wp-config.php

A list in the database could be changed by malware that writes to the database. To fix the list in a file instead, add this to wp-config.php above "That's all, stop editing!":

`define( 'SENTINEL_SHIELD_ADMINS', 'admin#1, jane#7' );`

* Entries are logins separated by commas (an array also works), matched without regard to case.
* `#ID` pins an entry to one account: `jane#7` approves login jane only while it belongs to user ID 7. Always pin: without it, if the jane account is deleted, anyone who registers a new account called jane becomes an approved administrator. The Administrators list shows the ID to use.
* While the constant is defined the lock is always enforced, regardless of the "Administrator lock" checkbox, the Malware lockdown module and "Enable protection" (all stored in the database). Only `SENTINEL_SHIELD_DISABLE` switches it off.
* The database list is ignored but kept; remove the constant to return to it. The Approve/Withdraw buttons and `approve-admin` / `revoke-admin` are disabled.
* The list is applied exactly as written: if no entry matches an administrator (a typo, or an empty value), every administrator is locked until wp-config.php is fixed. Check the Administrators list right after saving the file.
* Entries matching no account, or whose login now belongs to another user ID, are shown on the Administrators list, reported by the malware scan and announced in an admin notice.
* Adding an administrator: create or promote the account, then add its `login#ID`. Removing one: delete its entry (and ideally its administrator role).
* Limit: the list is only enforced while Sentinel Shield runs. Malware writing to the database directly could still remove Sentinel Shield from the active plugins (you would see it deactivated), and malware that can edit files can edit wp-config.php.

## Which accounts count as administrators

* Single site: the Administrator role, or any account given one of these capabilities directly whatever its role: manage_options, activate_plugins, install_plugins, edit_plugins, edit_files, update_core. Such accounts are flagged "Admin powers without admin role".
* Multisite: super administrators. Ordinary site administrators are not affected.
* Accounts are found with a direct database query and compared with what the Users screen shows; accounts missing from the Users screen are flagged "Hidden from Users screen".

## How it behaves

* **Turning it on:** if no one is approved yet, every administrator the Users screen shows is approved automatically, plus you. Hidden accounts are never approved automatically. Check the list for accounts you do not recognize first.
* **Empty list:** while no account is approved the lock does nothing, so switching it on (or withdrawing every approval) can never lock out every administrator.
* **New administrators:** have no rights until approved. Approved administrators see a "waiting for approval" notice, and the site admin email gets a "New administrator account" message saying who made the change and from which IP (if "Alert on new administrator accounts" is on).
* **Locked accounts:** can log in and see their profile, but every admin screen and capability is refused, including through the REST API, AJAX and XML-RPC. They see a notice explaining how to get approved. Each locked account is logged once an hour as "Unapproved administrator denied".
* **Withdrawing:** you cannot withdraw your own approval from the admin. Approvals are bound to user ID and login, so an account whose login is changed must be approved again. Removing someone's administrator role does not remove their approval; withdraw it when someone leaves.
* Approvals and withdrawals are written to the Events log.
* **Limit:** without `SENTINEL_SHIELD_ADMINS` the list lives in the database, where malware that specifically targets Sentinel Shield could add itself. Keep the twice-daily scan and the new-administrator alerts on; they report hidden administrators, triggers and new admins independently.
