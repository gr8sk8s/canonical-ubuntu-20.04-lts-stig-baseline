## Automatic Update:  -> 

### New Controls:
+   SV-255912 - The Ubuntu operating system SSH server must be configured to use only FIPS-validated key exchange algorithms.
+   SV-255913 - The Ubuntu operating system must restrict access to the kernel message buffer.


### Updated Check/Fixes:
#### Checks:
<details open>
  <summary>Click to expand.</summary>
SV-238210:
Old: 
```
Verify the Ubuntu operating system has the packages required for multifactor
authentication installed with the following commands:

$ dpkg -l | grep libpam-pkcs11

ii
libpam-pkcs11    0.6.8-4    amd64    Fully featured PAM module for using PKCS#11 smart cards

If the
"libpam-pkcs11" package is not installed, this is a finding.

Verify the sshd daemon allows
public key authentication with the following command:

$ grep -r ^Pubkeyauthentication
/etc/ssh/sshd_config*

PubkeyAuthentication yes

If this option is set to "no" or is
missing, this is a finding.
If conflicting results are returned, this is a finding.

```

Updated:
```
Verify the Ubuntu operating system has the packages required for multifactor authentication installed with the following commands:

$ dpkg -l | grep libpam-pkcs11

ii  libpam-pkcs11    0.6.8-4    amd64    Fully featured PAM module for using PKCS#11 smart cards

If the "libpam-pkcs11" package is not installed, this is a finding.

Verify the sshd daemon allows public key authentication with the following command:
 
$ grep -ir pubkeyauthentication /etc/ssh/sshd_config*

PubkeyAuthentication yes

If this option is set to "no" or is missing, this is a finding.

If conflicting results are returned, this is a finding.

```
---
SV-238236:
Old: 
```
Verify that the Advanced Intrusion Detection Environment (AIDE) default script used to
check file integrity each 30 days or less is unchanged.

Download the original aide-common
package in the /tmp directory:

$ cd /tmp; apt download aide-common

Fetch the SHA1 of the
original script file:

$ dpkg-deb --fsys-tarfile /tmp/aide-common_*.deb | tar -xO
./usr/share/aide/config/cron.daily/aide | sha1sum

32958374f18871e3f7dda27a58d721f471843e26  -

Compare with the SHA1 of the file in the
daily or monthly cron directory:

$ sha1sum /etc/cron.{daily,monthly}/aide
2&gt;/dev/null
32958374f18871e3f7dda27a58d721f471843e26  /etc/cron.daily/aide

If
there is no AIDE script file in the cron directories, or the SHA1 value of at least one file in the
daily or monthly cron directory does not match the SHA1 of the original, this is a finding.

```

Updated:
```
Verify that the Advanced Intrusion Detection Environment (AIDE) default script used to check file integrity each 30 days or less is unchanged. 
 
Download the original aide-common package in the /tmp directory: 
 
$ cd /tmp; apt download aide-common 
 
Fetch the SHA1 of the original script file: 
 
$ dpkg-deb --fsys-tarfile /tmp/aide-common_*.deb | tar -xO ./usr/share/aide/config/cron.daily/aide | sha1sum 
32958374f18871e3f7dda27a58d721f471843e26  - 
 
Compare with the SHA1 of the file in the daily or monthly cron directory: 
 
$ sha1sum /etc/cron.{daily,monthly}/aide 2>/dev/null 
32958374f18871e3f7dda27a58d721f471843e26  /etc/cron.daily/aide 
 
If there is no AIDE script file in the cron directories, or the SHA1 value of at least one file in the daily or monthly cron directory does not match the SHA1 of the original, this is a finding.

```
---
SV-238243:
Old: 
```
Verify that the SA and ISSO (at a minimum) are notified in the event of an audit processing
failure with the following command:

$ sudo grep '^action_mail_acct = root'
/etc/audit/auditd.conf

action_mail_acct = &lt;administrator_account&gt;

If the
value of the "action_mail_acct" keyword is not set to an accounts for security personnel, the
"action_mail_acct" keyword is missing, or the returned line is commented out, this is a
finding.

```

Updated:
```
Verify that the SA and ISSO (at a minimum) are notified in the event of an audit processing failure with the following command: 
 
$ sudo grep '^action_mail_acct = root' /etc/audit/auditd.conf 
 
action_mail_acct = <administrator_account> 
 
If the value of the "action_mail_acct" keyword is not set to an accounts for security personnel, the "action_mail_acct" keyword is missing, or the returned line is commented out, this is a finding.

```
---
SV-238252:
Old: 
```
Verify the Ubuntu operating system generates audit records upon successful/unsuccessful
attempts to use the "su" command.

Check the configured audit rules with the following
commands:

$ sudo auditctl -l | grep '/bin/su'

-a always,exit -F path=/bin/su -F perm=x -F
auid&gt;=1000 -F auid!=4294967295 -k privileged-priv_change

If the command does not
return lines that match the example or the lines are commented out, this is a finding.

Note:
The "-k" allows for specifying an arbitrary identifier, and the string after it does not need
to match the example output above.

```

Updated:
```
Verify the Ubuntu operating system generates audit records upon successful/unsuccessful attempts to use the "su" command. 
 
Check the configured audit rules with the following commands: 
 
$ sudo auditctl -l | grep '/bin/su' 
 
-a always,exit -F path=/bin/su -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-priv_change 
 
If the command does not return lines that match the example or the lines are commented out, this is a finding. 
 
Note: The "-k" allows for specifying an arbitrary identifier, and the string after it does not need to match the example output above.

```
---
SV-238253:
Old: 
```
Verify the Ubuntu operating system generates audit records upon successful/unsuccessful
attempts to use the "chfn" command.

Check the configured audit rules with the following
commands:

$ sudo auditctl -l | grep '/usr/bin/chfn'

-a always,exit -F
path=/usr/bin/chfn -F perm=x -F auid&gt;=1000 -F auid!=-1 -k privileged-chfn

If the
command does not return lines that match the example or the lines are commented out, this is a
finding.

Note: The "-k" allows for specifying an arbitrary identifier, and the string
after it does not need to match the example output above.

```

Updated:
```
Verify the Ubuntu operating system generates audit records upon successful/unsuccessful attempts to use the "chfn" command.  
 
Check the configured audit rules with the following commands: 
 
$ sudo auditctl -l | grep '/usr/bin/chfn' 
 
-a always,exit -F path=/usr/bin/chfn -F perm=x -F auid>=1000 -F auid!=-1 -k privileged-chfn 
 
If the command does not return lines that match the example or the lines are commented out, this is a finding. 
 
Note: The "-k" allows for specifying an arbitrary identifier, and the string after it does not need to match the example output above.

```
---
SV-238254:
Old: 
```
Verify the Ubuntu operating system generates audit records upon successful/unsuccessful
attempts to use the "mount" command.

Check the configured audit rules with the following
commands:

$ sudo auditctl -l | grep '/usr/bin/mount'

-a always,exit -F
path=/usr/bin/mount -F perm=x -F auid&gt;=1000 -F auid!=-1 -k privileged-mount

If the
command does not return lines that match the example or the lines are commented out, this is a
finding.

Note: The "-k" allows for specifying an arbitrary identifier, and the string
after it does not need to match the example output above.

```

Updated:
```
Verify the Ubuntu operating system generates audit records upon successful/unsuccessful attempts to use the "mount" command. 
 
Check the configured audit rules with the following commands: 
 
$ sudo auditctl -l | grep '/usr/bin/mount' 
 
-a always,exit -F path=/usr/bin/mount -F perm=x -F auid>=1000 -F auid!=-1 -k privileged-mount 
 
If the command does not return lines that match the example or the lines are commented out, this is a finding. 
 
Note: The "-k" allows for specifying an arbitrary identifier, and the string after it does not need to match the example output above.

```
---
SV-238255:
Old: 
```
Verify if the Ubuntu operating system generates audit records upon
successful/unsuccessful attempts to use the "umount" command.

Check the configured
audit rules with the following commands:

$ sudo auditctl -l | grep '/usr/bin/umount'

-a
always,exit -F path=/usr/bin/umount -F perm=x -F auid&gt;=1000 -F auid!=-1 -k
privileged-umount

If the command does not return lines that match the example or the lines
are commented out, this is a finding.

Note: The "-k" allows for specifying an arbitrary
identifier, and the string after it does not need to match the example output above.

```

Updated:
```
Verify if the Ubuntu operating system generates audit records upon successful/unsuccessful attempts to use the "umount" command. 
 
Check the configured audit rules with the following commands: 
 
$ sudo auditctl -l | grep '/usr/bin/umount' 
 
-a always,exit -F path=/usr/bin/umount -F perm=x -F auid>=1000 -F auid!=-1 -k privileged-umount 
 
If the command does not return lines that match the example or the lines are commented out, this is a finding. 
 
Note: The "-k" allows for specifying an arbitrary identifier, and the string after it does not need to match the example output above.

```
---
SV-238256:
Old: 
```
Verify the Ubuntu operating system generates an audit record upon successful/unsuccessful
attempts to use the "ssh-agent" command.

Check the configured audit rules with the
following commands:

$ sudo auditctl -l | grep '/usr/bin/ssh-agent'

-a always,exit -F
path=/usr/bin/ssh-agent -F perm=x -F auid&gt;=1000 -F auid!=-1 -k privileged-ssh

If the
command does not return lines that match the example or the lines are commented out, this is a
finding.

Note: The "-k" allows for specifying an arbitrary identifier, and the string
after it does not need to match the example output above.

```

Updated:
```
Verify the Ubuntu operating system generates an audit record upon successful/unsuccessful attempts to use the "ssh-agent" command. 
 
Check the configured audit rules with the following commands: 
 
$ sudo auditctl -l | grep '/usr/bin/ssh-agent' 
 
-a always,exit -F path=/usr/bin/ssh-agent -F perm=x -F auid>=1000 -F auid!=-1 -k privileged-ssh 
 
If the command does not return lines that match the example or the lines are commented out, this is a finding. 
 
Note: The "-k" allows for specifying an arbitrary identifier, and the string after it does not need to match the example output above.

```
---
SV-238257:
Old: 
```
Verify the Ubuntu operating system generates an audit record upon successful/unsuccessful
attempts to use the "ssh-keysign" command.

Check the configured audit rules with the
following commands:

$ sudo auditctl -l | grep ssh-keysign

-a always,exit -F
path=/usr/lib/openssh/ssh-keysign -F perm=x -F auid&gt;=1000 -F auid!=-1 -k
privileged-ssh

If the command does not return lines that match the example or the lines are
commented out, this is a finding.

Note: The "-k" allows for specifying an arbitrary
identifier, and the string after it does not need to match the example output above.

```

Updated:
```
Verify the Ubuntu operating system generates an audit record upon successful/unsuccessful attempts to use the "ssh-keysign" command. 
 
Check the configured audit rules with the following commands: 
 
$ sudo auditctl -l | grep ssh-keysign 
 
-a always,exit -F path=/usr/lib/openssh/ssh-keysign -F perm=x -F auid>=1000 -F auid!=-1 -k privileged-ssh 
 
If the command does not return lines that match the example or the lines are commented out, this is a finding. 
 
Note: The "-k" allows for specifying an arbitrary identifier, and the string after it does not need to match the example output above.

```
---
SV-238258:
Old: 
```
Verify the Ubuntu operating system generates an audit record upon successful/unsuccessful
attempts to use the "setxattr", "fsetxattr", "lsetxattr", "removexattr",
"fremovexattr", and "lremovexattr" system calls.

Check the currently configured audit
rules with the following command:

$ sudo auditctl -l | grep xattr

-a always,exit -F
arch=b32 -S setxattr,fsetxattr,lsetxattr,removexattr,fremovexattr,lremovexattr -F
auid&gt;=1000 -F auid!=-1 -k perm_mod
-a always,exit -F arch=b32 -S
setxattr,fsetxattr,lsetxattr,removexattr,fremovexattr,lremovexattr -F auid=0 -k
perm_mod
-a always,exit -F arch=b64 -S
setxattr,fsetxattr,lsetxattr,removexattr,fremovexattr,lremovexattr -F
auid&gt;=1000 -F auid!=-1 -k perm_mod
-a always,exit -F arch=b64 -S
setxattr,fsetxattr,lsetxattr,removexattr,fremovexattr,lremovexattr -F auid=0 -k
perm_mod

If the command does not return audit rules for the "setxattr", "fsetxattr",
"lsetxattr", "removexattr", "fremovexattr" and "lremovexattr" syscalls or the lines are
commented out, this is a finding.

Notes:
For 32-bit architectures, only the 32-bit
specific output lines from the commands are required.
The "-k" allows for specifying an
arbitrary identifier, and the string after it does not need to match the example output above.

```

Updated:
```
Verify the Ubuntu operating system generates an audit record upon successful/unsuccessful attempts to use the "setxattr", "fsetxattr", "lsetxattr", "removexattr", "fremovexattr", and "lremovexattr" system calls. 
 
Check the currently configured audit rules with the following command: 
 
$ sudo auditctl -l | grep xattr  
 
-a always,exit -F arch=b32 -S setxattr,fsetxattr,lsetxattr,removexattr,fremovexattr,lremovexattr -F auid>=1000 -F auid!=-1 -k perm_mod 
-a always,exit -F arch=b32 -S setxattr,fsetxattr,lsetxattr,removexattr,fremovexattr,lremovexattr -F auid=0 -k perm_mod  
-a always,exit -F arch=b64 -S setxattr,fsetxattr,lsetxattr,removexattr,fremovexattr,lremovexattr -F auid>=1000 -F auid!=-1 -k perm_mod 
-a always,exit -F arch=b64 -S setxattr,fsetxattr,lsetxattr,removexattr,fremovexattr,lremovexattr -F auid=0 -k perm_mod  
 
If the command does not return audit rules for the "setxattr", "fsetxattr", "lsetxattr", "removexattr", "fremovexattr" and "lremovexattr" syscalls or the lines are commented out, this is a finding. 
 
Notes: 
For 32-bit architectures, only the 32-bit specific output lines from the commands are required. 
The "-k" allows for specifying an arbitrary identifier, and the string after it does not need to match the example output above.

```
---
SV-238264:
Old: 
```
Verify the Ubuntu operating system generates an audit record upon successful/unsuccessful
attempts to use the "chown", "fchown", "fchownat", and "lchown" system calls.

Check the
configured audit rules with the following commands:

$ sudo auditctl -l | grep chown

-a
always,exit -F arch=b32 -S chown,fchown,fchownat,lchown -F auid&gt;=1000 -F auid!=-1 -k
perm_chng
-a always,exit -F arch=b64 -S chown,fchown,fchownat,lchown -F auid&gt;=1000
-F auid!=-1 -k perm_chng

If the command does not return audit rules for the "chown",
"fchown", "fchownat", and "lchown" syscalls or the lines are commented out, this is a
finding.

Notes:
For 32-bit architectures, only the 32-bit specific output lines from the
commands are required.
The "-k" allows for specifying an arbitrary identifier, and the
string after it does not need to match the example output above.

```

Updated:
```
Verify the Ubuntu operating system generates an audit record upon successful/unsuccessful attempts to use the "chown", "fchown", "fchownat", and "lchown" system calls. 
 
Check the configured audit rules with the following commands: 
 
$ sudo auditctl -l | grep chown 
 
-a always,exit -F arch=b32 -S chown,fchown,fchownat,lchown -F auid>=1000 -F auid!=-1 -k perm_chng 
-a always,exit -F arch=b64 -S chown,fchown,fchownat,lchown -F auid>=1000 -F auid!=-1 -k perm_chng 
 
If the command does not return audit rules for the "chown", "fchown", "fchownat", and "lchown" syscalls or the lines are commented out, this is a finding. 
 
Notes: 
For 32-bit architectures, only the 32-bit specific output lines from the commands are required. 
The "-k" allows for specifying an arbitrary identifier, and the string after it does not need to match the example output above.

```
---
SV-238268:
Old: 
```
Verify the Ubuntu operating system generates an audit record upon successful/unsuccessful
attempts to use the "chmod", "fchmod", and "fchmodat" system calls.

Check the configured
audit rules with the following commands:

$ sudo auditctl -l | grep chmod

-a always,exit -F
arch=b32 -S chmod,fchmod,fchmodat -F auid&gt;=1000 -F auid!=-1 -k perm_chng
-a
always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid&gt;=1000 -F auid!=-1 -k
perm_chng

If the command does not return audit rules for the "chmod", "fchmod" and
"fchmodat" syscalls or the lines are commented out, this is a finding.

Notes:
For 32-bit
architectures, only the 32-bit specific output lines from the commands are required.
The
"-k" allows for specifying an arbitrary identifier, and the string after it does not need to
match the example output above.

```

Updated:
```
Verify the Ubuntu operating system generates an audit record upon successful/unsuccessful attempts to use the "chmod", "fchmod", and "fchmodat" system calls. 
 
Check the configured audit rules with the following commands: 
 
$ sudo auditctl -l | grep chmod 
 
-a always,exit -F arch=b32 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=-1 -k perm_chng 
-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=-1 -k perm_chng 
 
If the command does not return audit rules for the "chmod", "fchmod" and "fchmodat" syscalls or the lines are commented out, this is a finding. 
 
Notes: 
For 32-bit architectures, only the 32-bit specific output lines from the commands are required. 
The "-k" allows for specifying an arbitrary identifier, and the string after it does not need to match the example output above.

```
---
SV-238271:
Old: 
```
Verify the Ubuntu operating system generates an audit record upon unsuccessful attempts to
use the "creat", "open", "openat", "open_by_handle_at", "truncate", and "ftruncate"
system calls.

Check the configured audit rules with the following commands:

$ sudo
auditctl -l | grep 'open\|truncate\|creat'

-a always,exit -F arch=b32 -S
creat,open,openat,open_by_handle_at,truncate,ftruncate -F exit=-EPERM -F
auid&gt;=1000 -F auid!=-1 -k perm_access
-a always,exit -F arch=b32 -S
creat,open,openat,open_by_handle_at,truncate,ftruncate -F exit=-EACCES -F
auid&gt;=1000 -F auid!=-1 -k perm_access
-a always,exit -F arch=b64 -S
creat,open,openat,open_by_handle_at,truncate,ftruncate -F exit=-EPERM -F
auid&gt;=1000 -F auid!=-1 -k perm_access
-a always,exit -F arch=b64 -S
creat,open,openat,open_by_handle_at,truncate,ftruncate -F exit=-EACCES -F
auid&gt;=1000 -F auid!=-1 -k perm_access

If the command does not return audit rules for the
"creat", "open", "openat", "open_by_handle_at", "truncate", and "ftruncate" syscalls or
the lines are commented out, this is a finding.

Notes:
For 32-bit architectures, only the
32-bit specific output lines from the commands are required.
The "-k" allows for specifying
an arbitrary identifier, and the string after it does not need to match the example output
above.

```

Updated:
```
Verify the Ubuntu operating system generates an audit record upon unsuccessful attempts to use the "creat", "open", "openat", "open_by_handle_at", "truncate", and "ftruncate" system calls. 
 
Check the configured audit rules with the following commands: 
 
$ sudo auditctl -l | grep 'open\|truncate\|creat' 
 
-a always,exit -F arch=b32 -S creat,open,openat,open_by_handle_at,truncate,ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=-1 -k perm_access 
-a always,exit -F arch=b32 -S creat,open,openat,open_by_handle_at,truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=-1 -k perm_access 
-a always,exit -F arch=b64 -S creat,open,openat,open_by_handle_at,truncate,ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=-1 -k perm_access 
-a always,exit -F arch=b64 -S creat,open,openat,open_by_handle_at,truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=-1 -k perm_access  
 
If the command does not return audit rules for the "creat", "open", "openat", "open_by_handle_at", "truncate", and "ftruncate" syscalls or the lines are commented out, this is a finding. 
 
Notes: 
For 32-bit architectures, only the 32-bit specific output lines from the commands are required. 
The "-k" allows for specifying an arbitrary identifier, and the string after it does not need to match the example output above.

```
---
SV-238277:
Old: 
```
Verify that an audit event is generated for any successful/unsuccessful use of the "sudo"
command.

Check the configured audit rules with the following command:

$ sudo auditctl -l
| grep /usr/bin/sudo

-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid&gt;=1000 -F
auid!=-1 -k priv_cmd

If the command does not return a line that matches the example or the
line is commented out, this is a finding.

Note: The "-k" allows for specifying an arbitrary
identifier, and the string after it does not need to match the example output above.

```

Updated:
```
Verify that an audit event is generated for any successful/unsuccessful use of the "sudo" command.  
 
Check the configured audit rules with the following command: 
 
$ sudo auditctl -l | grep /usr/bin/sudo 
 
-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=-1 -k priv_cmd 
 
If the command does not return a line that matches the example or the line is commented out, this is a finding. 
 
Note: The "-k" allows for specifying an arbitrary identifier, and the string after it does not need to match the example output above.

```
---
SV-238278:
Old: 
```
Verify the Ubuntu operating system generates an audit record upon successful/unsuccessful
attempts to use the "sudoedit" command.

Check the configured audit rules with the
following commands:

$ sudo auditctl -l | grep /usr/bin/sudoedit

-a always,exit -F
path=/usr/bin/sudoedit -F perm=x -F auid&gt;=1000 -F auid!=-1 -k priv_cmd

If the command
does not return a line that matches the example or the line is commented out, this is a finding.


Note: The "-k" allows for specifying an arbitrary identifier, and the string after it does
not need to match the example output above.

```

Updated:
```
Verify the Ubuntu operating system generates an audit record upon successful/unsuccessful attempts to use the "sudoedit" command. 
 
Check the configured audit rules with the following commands: 
 
$ sudo auditctl -l | grep /usr/bin/sudoedit 
 
-a always,exit -F path=/usr/bin/sudoedit -F perm=x -F auid>=1000 -F auid!=-1 -k priv_cmd 
 
If the command does not return a line that matches the example or the line is commented out, this is a finding. 
 
Note: The "-k" allows for specifying an arbitrary identifier, and the string after it does not need to match the example output above.

```
---
SV-238279:
Old: 
```
Verify the Ubuntu operating system generates an audit record upon successful/unsuccessful
attempts to use the "chsh" command.

Check the configured audit rules with the following
commands:

$ sudo auditctl -l | grep chsh

-a always,exit -F path=/usr/bin/chsh -F perm=x
-F auid&gt;=1000 -F auid!=-1 -k priv_cmd

If the command does not return a line that matches
the example or the line is commented out, this is a finding.

Notes: The "-k" allows for
specifying an arbitrary identifier, and the string after it does not need to match the example
output above.

```

Updated:
```
Verify the Ubuntu operating system generates an audit record upon successful/unsuccessful attempts to use the "chsh" command. 
 
Check the configured audit rules with the following commands: 
 
$ sudo auditctl -l | grep chsh 
 
-a always,exit -F path=/usr/bin/chsh -F perm=x -F auid>=1000 -F auid!=-1 -k priv_cmd 
 
If the command does not return a line that matches the example or the line is commented out, this is a finding. 
 
Notes: The "-k" allows for specifying an arbitrary identifier, and the string after it does not need to match the example output above.

```
---
SV-238280:
Old: 
```
Verify the Ubuntu operating system generates an audit record upon successful/unsuccessful
attempts to use the "newgrp" command.

Check the configured audit rules with the following
commands:

$ sudo auditctl -l | grep newgrp

-a always,exit -F path=/usr/bin/newgrp -F
perm=x -F auid&gt;=1000 -F auid!=-1 -k priv_cmd

If the command does not return a line that
matches the example or the line is commented out, this is a finding.

Note: The "-k" allows for
specifying an arbitrary identifier, and the string after it does not need to match the example
output above.

```

Updated:
```
Verify the Ubuntu operating system generates an audit record upon successful/unsuccessful attempts to use the "newgrp" command. 
 
Check the configured audit rules with the following commands: 
 
$ sudo auditctl -l | grep newgrp 
 
-a always,exit -F path=/usr/bin/newgrp -F perm=x -F auid>=1000 -F auid!=-1 -k priv_cmd 
 
If the command does not return a line that matches the example or the line is commented out, this is a finding. 
 
Note: The "-k" allows for specifying an arbitrary identifier, and the string after it does not need to match the example output above.

```
---
SV-238281:
Old: 
```
Verify the Ubuntu operating system generates an audit record upon successful/unsuccessful
attempts to use the "chcon" command.

Check the currently configured audit rules with the
following command:

$ sudo auditctl -l | grep chcon

-a always,exit -F
path=/usr/bin/chcon -F perm=x -F auid&gt;=1000 -F auid!=-1 -k perm_chng

If the command
does not return a line that matches the example or the line is commented out, this is a finding.


Note: The "-k" allows for specifying an arbitrary identifier, and the string after it does
not need to match the example output above.

```

Updated:
```
Verify the Ubuntu operating system generates an audit record upon successful/unsuccessful attempts to use the "chcon" command. 
 
Check the currently configured audit rules with the following command: 
 
$ sudo auditctl -l | grep chcon 
 
-a always,exit -F path=/usr/bin/chcon -F perm=x -F auid>=1000 -F auid!=-1 -k perm_chng 
 
If the command does not return a line that matches the example or the line is commented out, this is a finding. 
 
Note: The "-k" allows for specifying an arbitrary identifier, and the string after it does not need to match the example output above.

```
---
SV-238282:
Old: 
```
Verify the Ubuntu operating system generates an audit record upon successful/unsuccessful
attempts to use the "apparmor_parser" command.

Check the currently configured audit
rules with the following command:

$ sudo auditctl -l | grep apparmor_parser

-a
always,exit -F path=/sbin/apparmor_parser -F perm=x -F auid&gt;=1000 -F auid!=-1 -k
perm_chng

If the command does not return a line that matches the example or the line is
commented out, this is a finding.

Note: The "-k" allows for specifying an arbitrary
identifier, and the string after it does not need to match the example output above.

```

Updated:
```
Verify the Ubuntu operating system generates an audit record upon successful/unsuccessful attempts to use the "apparmor_parser" command. 
 
Check the currently configured audit rules with the following command: 
 
$ sudo auditctl -l | grep apparmor_parser 
 
-a always,exit -F path=/sbin/apparmor_parser -F perm=x -F auid>=1000 -F auid!=-1 -k perm_chng 
 
If the command does not return a line that matches the example or the line is commented out, this is a finding. 
 
Note: The "-k" allows for specifying an arbitrary identifier, and the string after it does not need to match the example output above.

```
---
SV-238283:
Old: 
```
Verify the Ubuntu operating system generates an audit record upon successful/unsuccessful
attempts to use the "setfacl" command.

Check the currently configured audit rules with the
following command:

$ sudo auditctl -l | grep setfacl

-a always,exit -F
path=/usr/bin/setfacl -F perm=x -F auid&gt;=1000 -F auid!=-1 -k perm_chng

If the command
does not return a line that matches the example or the line is commented out, this is a finding.


Note: The "-k" allows for specifying an arbitrary identifier, and the string after it does
not need to match the example output above.

```

Updated:
```
Verify the Ubuntu operating system generates an audit record upon successful/unsuccessful attempts to use the "setfacl" command. 
 
Check the currently configured audit rules with the following command: 
 
$ sudo auditctl -l | grep setfacl 
 
-a always,exit -F path=/usr/bin/setfacl -F perm=x -F auid>=1000 -F auid!=-1 -k perm_chng 
 
If the command does not return a line that matches the example or the line is commented out, this is a finding. 
 
Note: The "-k" allows for specifying an arbitrary identifier, and the string after it does not need to match the example output above.

```
---
SV-238284:
Old: 
```
Verify the Ubuntu operating system generates an audit record upon successful/unsuccessful
attempts to use the "chacl" command.

Check the currently configured audit rules with the
following command:

$ sudo audtctl -l | grep chacl

-a always,exit -F path=/usr/bin/chacl
-F perm=x -F auid&gt;=1000 -F auid!=-1 -k perm_chng

If the command does not return a line
that matches the example or the line is commented out, this is a finding.

Note: The "-k"
allows for specifying an arbitrary identifier, and the string after it does not need to match
the example output above.

```

Updated:
```
Verify the Ubuntu operating system generates an audit record upon successful/unsuccessful attempts to use the "chacl" command. 
 
Check the currently configured audit rules with the following command: 
 
$ sudo auditctl -l | grep chacl 
 
-a always,exit -F path=/usr/bin/chacl -F perm=x -F auid>=1000 -F auid!=-1 -k perm_chng 
 
If the command does not return a line that matches the example or the line is commented out, this is a finding. 
 
Note: The "-k" allows for specifying an arbitrary identifier, and the string after it does not need to match the example output above.

```
---
SV-238288:
Old: 
```
Verify that an audit event is generated for any successful/unsuccessful use of the "passwd"
command.

Check the currently configured audit rules with the following command:

$ sudo
auditctl -l | grep -w passwd

-a always,exit -S all -F path=/usr/bin/passwd -F perm=x -F
auid&gt;=1000 -F auid!=-1 -F key=privileged-passwd

If the command does not return a line
that matches the example or the line is commented out, this is a finding.

Note: The "key"
allows for specifying an arbitrary identifier, and the string after it does not need to match
the example output above.

```

Updated:
```
Verify that an audit event is generated for any successful/unsuccessful use of the "passwd" command.  
 
Check the currently configured audit rules with the following command: 
 
$ sudo auditctl -l | grep -w passwd 
 
-a always,exit -S all -F path=/usr/bin/passwd -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-passwd 
 
If the command does not return a line that matches the example or the line is commented out, this is a finding. 
 
Note: The "key" allows for specifying an arbitrary identifier, and the string after it does not need to match the example output above.

```
---
SV-238289:
Old: 
```
Verify that an audit event is generated for any successful/unsuccessful use of the
"unix_update" command.

Check the currently configured audit rules with the following
command:

$ sudo auditctl -l | grep -w unix_update

-a always,exit -F
path=/sbin/unix_update -F perm=x -F auid&gt;=1000 -F auid!=-1 -k privileged-unix-update


If the command does not return a line that matches the example or the line is commented out,
this is a finding.

Note: The "-k" allows for specifying an arbitrary identifier, and the
string after it does not need to match the example output above.

```

Updated:
```
Verify that an audit event is generated for any successful/unsuccessful use of the "unix_update" command. 
 
Check the currently configured audit rules with the following command: 
 
$ sudo auditctl -l | grep -w unix_update 
 
-a always,exit -F path=/sbin/unix_update -F perm=x -F auid>=1000 -F auid!=-1 -k privileged-unix-update 
 
If the command does not return a line that matches the example or the line is commented out, this is a finding. 
 
Note: The "-k" allows for specifying an arbitrary identifier, and the string after it does not need to match the example output above.

```
---
SV-238290:
Old: 
```
Verify that an audit event is generated for any successful/unsuccessful use of the "gpasswd"
command.

Check the currently configured audit rules with the following command:

$ sudo
auditctl -l | grep -w gpasswd

-a always,exit -F path=/usr/bin/gpasswd -F perm=x -F
auid&gt;=1000 -F auid!=-1 -k privileged-gpasswd

If the command does not return a line that
matches the example or the line is commented out, this is a finding.

Note: The "-k" allows for
specifying an arbitrary identifier, and the string after it does not need to match the example
output above.

```

Updated:
```
Verify that an audit event is generated for any successful/unsuccessful use of the "gpasswd" command.  
 
Check the currently configured audit rules with the following command: 
 
$ sudo auditctl -l | grep -w gpasswd 
 
-a always,exit -F path=/usr/bin/gpasswd -F perm=x -F auid>=1000 -F auid!=-1 -k privileged-gpasswd 
 
If the command does not return a line that matches the example or the line is commented out, this is a finding. 
 
Note: The "-k" allows for specifying an arbitrary identifier, and the string after it does not need to match the example output above.

```
---
SV-238291:
Old: 
```
Verify that an audit event is generated for any successful/unsuccessful use of the "chage"
command.

Check the currently configured audit rules with the following command:

$ sudo
auditctl -l | grep -w chage

-a always,exit -F path=/usr/bin/chage -F perm=x -F
auid&gt;=1000 -F auid!=-1 -k privileged-chage

If the command does not return a line that
matches the example or the line is commented out, this is a finding.

Note: The "-k" allows for
specifying an arbitrary identifier, and the string after it does not need to match the example
output above.

```

Updated:
```
Verify that an audit event is generated for any successful/unsuccessful use of the "chage" command. 
 
Check the currently configured audit rules with the following command: 
 
$ sudo auditctl -l | grep -w chage 
 
-a always,exit -F path=/usr/bin/chage -F perm=x -F auid>=1000 -F auid!=-1 -k privileged-chage 
 
If the command does not return a line that matches the example or the line is commented out, this is a finding. 
 
Note: The "-k" allows for specifying an arbitrary identifier, and the string after it does not need to match the example output above.

```
---
SV-238292:
Old: 
```
Verify that an audit event is generated for any successful/unsuccessful use of the "usermod"
command.

Check the currently configured audit rules with the following command:

$ sudo
auditctl -l | grep -w usermod

-a always,exit -F path=/usr/sbin/usermod -F perm=x -F
auid&gt;=1000 -F auid!=-1 -k privileged-usermod

If the command does not return a line that
matches the example or the line is commented out, this is a finding.

Note: The "-k" allows for
specifying an arbitrary identifier, and the string after it does not need to match the example
output above.

```

Updated:
```
Verify that an audit event is generated for any successful/unsuccessful use of the "usermod" command. 
 
Check the currently configured audit rules with the following command: 
 
$ sudo auditctl -l | grep -w usermod 
 
-a always,exit -F path=/usr/sbin/usermod -F perm=x -F auid>=1000 -F auid!=-1 -k privileged-usermod 
 
If the command does not return a line that matches the example or the line is commented out, this is a finding. 
 
Note: The "-k" allows for specifying an arbitrary identifier, and the string after it does not need to match the example output above.

```
---
SV-238293:
Old: 
```
Verify that an audit event is generated for any successful/unsuccessful use of the "crontab"
command.

Check the currently configured audit rules with the following command:

$ sudo
auditctl -l | grep -w crontab

-a always,exit -F path=/usr/bin/crontab -F perm=x -F
auid&gt;=1000 -F auid!=-1 -k privileged-crontab

If the command does not return a line that
matches the example or the line is commented out, this is a finding.

Note: The "-k" allows for
specifying an arbitrary identifier, and the string after it does not need to match the example
output above.

```

Updated:
```
Verify that an audit event is generated for any successful/unsuccessful use of the "crontab" command. 
 
Check the currently configured audit rules with the following command: 
 
$ sudo auditctl -l | grep -w crontab 
 
-a always,exit -F path=/usr/bin/crontab -F perm=x -F auid>=1000 -F auid!=-1 -k privileged-crontab 
 
If the command does not return a line that matches the example or the line is commented out, this is a finding. 
 
Note: The "-k" allows for specifying an arbitrary identifier, and the string after it does not need to match the example output above.

```
---
SV-238294:
Old: 
```
Verify that an audit event is generated for any successful/unsuccessful use of the
"pam_timestamp_check" command.

Check the currently configured audit rules with the
following command:

$ sudo auditctl -l | grep -w pam_timestamp_check

-a always,exit -F
path=/usr/sbin/pam_timestamp_check -F perm=x -F auid&gt;=1000 -F auid!=-1 -k
privileged-pam_timestamp_check

If the command does not return a line that matches the
example or the line is commented out, this is a finding.

Note: The "-k" allows for specifying
an arbitrary identifier, and the string after it does not need to match the example output
above.

```

Updated:
```
Verify that an audit event is generated for any successful/unsuccessful use of the "pam_timestamp_check" command. 
 
Check the currently configured audit rules with the following command: 
 
$ sudo auditctl -l | grep -w pam_timestamp_check 
 
-a always,exit -F path=/usr/sbin/pam_timestamp_check -F perm=x -F auid>=1000 -F auid!=-1 -k privileged-pam_timestamp_check 
 
If the command does not return a line that matches the example or the line is commented out, this is a finding. 
 
Note: The "-k" allows for specifying an arbitrary identifier, and the string after it does not need to match the example output above.

```
---
SV-238295:
Old: 
```
Verify the Ubuntu operating system generates an audit record for any
successful/unsuccessful attempts to use the "init_module" and "finit_module" syscalls.


Check the currently configured audit rules with the following command:

$ sudo auditctl -l
| grep init_module

-a always,exit -F arch=b32 -S init_module,finit_module -F
auid&gt;=1000 -F auid!=-1 -k module_chng
-a always,exit -F arch=b64 -S
init_module,finit_module -F auid&gt;=1000 -F auid!=-1 -k module_chng

If the command
does not return audit rules for the "init_module" and "finit_module" syscalls or the lines
are commented out, this is a finding.

Notes:
For 32-bit architectures, only the 32-bit
specific output lines from the commands are required.
The "-k" allows for specifying an
arbitrary identifier, and the string after it does not need to match the example output above.

```

Updated:
```
Verify the Ubuntu operating system generates an audit record for any successful/unsuccessful attempts to use the "init_module" and "finit_module" syscalls. 
 
Check the currently configured audit rules with the following command: 
 
$ sudo auditctl -l | grep init_module 
 
-a always,exit -F arch=b32 -S init_module,finit_module -F auid>=1000 -F auid!=-1 -k module_chng 
-a always,exit -F arch=b64 -S init_module,finit_module -F auid>=1000 -F auid!=-1 -k module_chng  
 
If the command does not return audit rules for the "init_module" and "finit_module" syscalls or the lines are commented out, this is a finding.
 
Notes: 
For 32-bit architectures, only the 32-bit specific output lines from the commands are required. 
The "-k" allows for specifying an arbitrary identifier, and the string after it does not need to match the example output above.

```
---
SV-238297:
Old: 
```
Verify the Ubuntu operating system generates an audit record for any
successful/unsuccessful attempts to use the "delete_module" syscall.

Check the
currently configured audit rules with the following command:

$ sudo auditctl -l | grep -w
delete_module

-a always,exit -F arch=b32 -S delete_module -F auid&gt;=1000 -F auid!=-1
-k module_chng
-a always,exit -F arch=b64 -S delete_module -F auid&gt;=1000 -F auid!=-1 -k
module_chng

If the command does not return a line that matches the example or the line is
commented out, this is a finding.

Notes:
- For 32-bit architectures, only the 32-bit
specific output lines from the commands are required.
- The "-k" allows for specifying an
arbitrary identifier, and the string after it does not need to match the example output above.

```

Updated:
```
Verify the Ubuntu operating system generates an audit record for any successful/unsuccessful attempts to use the "delete_module" syscall. 
 
Check the currently configured audit rules with the following command: 
 
$ sudo auditctl -l | grep -w delete_module 
 
-a always,exit -F arch=b32 -S delete_module -F auid>=1000 -F auid!=-1 -k module_chng 
-a always,exit -F arch=b64 -S delete_module -F auid>=1000 -F auid!=-1 -k module_chng 
 
If the command does not return a line that matches the example or the line is commented out, this is a finding. 
 
Notes: 
- For 32-bit architectures, only the 32-bit specific output lines from the commands are required. 
- The "-k" allows for specifying an arbitrary identifier, and the string after it does not need to match the example output above.

```
---
SV-238310:
Old: 
```
Verify the Ubuntu operating system generates audit records for any
successful/unsuccessful use of "unlink", "unlinkat", "rename", "renameat", and "rmdir"
system calls.

Check the currently configured audit rules with the following command:

$
sudo auditctl -l | grep 'unlink\|rename\|rmdir'

-a always,exit -F arch=b64 -S
unlink,unlinkat,rename,renameat,rmdir -F auid&gt;=1000 -F auid!=-1 -F key=delete
-a
always,exit -F arch=b32 -S unlink,unlinkat,rename,renameat,rmdir -F auid&gt;=1000 -F
auid!=-1 -F key=delete

If the command does not return audit rules for the "unlink",
"unlinkat", "rename", "renameat", and "rmdir" syscalls or the lines are commented out, this
is a finding.

Notes:
For 32-bit architectures, only the 32-bit specific output lines from
the commands are required.
The "key" allows for specifying an arbitrary identifier, and the
string after it does not need to match the example output above.

```

Updated:
```
Verify the Ubuntu operating system generates audit records for any successful/unsuccessful use of "unlink", "unlinkat", "rename", "renameat", and "rmdir" system calls. 
 
Check the currently configured audit rules with the following command: 
 
$ sudo auditctl -l | grep 'unlink\|rename\|rmdir' 
 
-a always,exit -F arch=b64 -S unlink,unlinkat,rename,renameat,rmdir -F auid>=1000 -F auid!=-1 -F key=delete 
-a always,exit -F arch=b32 -S unlink,unlinkat,rename,renameat,rmdir -F auid>=1000 -F auid!=-1 -F key=delete 
 
If the command does not return audit rules for the "unlink", "unlinkat", "rename", "renameat", and "rmdir" syscalls or the lines are commented out, this is a finding. 
 
Notes: 
For 32-bit architectures, only the 32-bit specific output lines from the commands are required. 
The "key" allows for specifying an arbitrary identifier, and the string after it does not need to match the example output above.

```
---
SV-238316:
Old: 
```
Verify the Ubuntu operating system generates audit records showing start and stop times for
user access to the system via the "/var/run/wtmp" file.

Check the currently configured
audit rules with the following command:

$ sudo auditctl -l | grep '/var/run/wtmp'

-w
/var/run/wtmp -p wa -k logins

If the command does not return a line matching the example or
the line is commented out, this is a finding.

Note: The "-k" allows for specifying an
arbitrary identifier, and the string after it does not need to match the example output above.

```

Updated:
```
Verify the Ubuntu operating system generates audit records showing start and stop times for user access to the system via the "/var/run/utmp" file. 
 
Check the currently configured audit rules with the following command: 
 
$ sudo auditctl -l | grep '/var/run/utmp' 
 
-w /var/run/utmp -p wa -k logins 
 
If the command does not return a line matching the example or the line is commented out, this is a finding. 
 
Note: The "-k" allows for specifying an arbitrary identifier, and the string after it does not need to match the example output above.

```
---
SV-238330:
Old: 
```
Verify the account identifiers (individuals, groups, roles, and devices) are disabled
after 35 days of inactivity with the following command:

Check the account inactivity value
by performing the following command:

$ sudo grep INACTIVE /etc/default/useradd


INACTIVE=35

If "INACTIVE" is not set to a value 0&lt;[VALUE]&lt;=35, or is commented out,
this is a finding.

```

Updated:
```
Verify the account identifiers (individuals, groups, roles, and devices) are disabled after 35 days of inactivity with the following command: 
 
Check the account inactivity value by performing the following command: 
 
$ sudo grep INACTIVE /etc/default/useradd 
 
INACTIVE=35 
 
If "INACTIVE" is not set to a value 0<[VALUE]<=35, or is commented out, this is a finding.

```
---
SV-238331:
Old: 
```
Verify the Ubuntu operating system expires emergency  accounts within 72 hours or less.

For
every emergency account, run the following command to obtain its account expiration
information:

$ sudo chage -l account_name | grep expires

Password expires                                        : Aug 07, 2019

Account expires                                           : Aug 07, 2019

Verify each of these accounts has an expiration date set
within 72 hours of account creation.

If any of these accounts do not expire within 72 hours of
that account's creation, this is a finding.

```

Updated:
```
Verify temporary accounts have been provisioned with an expiration date of 72 hours.

For every existing temporary account, run the following command to obtain its account expiration information:

     $ sudo chage -l <temporary_account_name> | grep -i "account expires"

Verify each of these accounts has an expiration date set within 72 hours.
If any temporary accounts have no expiration date set or do not expire within 72 hours, this is a finding.

```
---
SV-238337:
Old: 
```
Verify the Ubuntu operating system has all system log files under the "/var/log" directory
with a permission set to 640 or less permissive by using the following command:

$ sudo find
/var/log -perm /137 -type f -exec stat -c "%n %a" {} \;

If the command displays any output,
this is a finding.

```

Updated:
```
Verify the Ubuntu operating system has all system log files under the "/var/log" directory with a permission set to "640" or less permissive by using the following command:

Note: The btmp, wtmp, and lastlog files are excluded. Refer to the Discussion for details.

$ sudo find /var/log -perm /137 ! -name '*[bw]tmp' ! -name '*lastlog' -type f -exec stat -c "%n %a" {} \;

If the command displays any output, this is a finding.

```
---
SV-238340:
Old: 
```
Verify that the Ubuntu operating system configures the "/var/log" directory with a mode of
750 or less permissive with the following command:

$ stat -c "%n %a" /var/log

/var/log 750


If a value of "750" or less permissive is not returned, this is a finding.

```

Updated:
```
Verify that the Ubuntu operating system configures the "/var/log" directory with a mode of "755" or less permissive with the following command:

Note: If rsyslog is active and enabled on the operating system, this requirement is not applicable.

$ stat -c "%n %a" /var/log

/var/log 755

If a value of "755" or less permissive is not returned, this is a finding.

```
---
SV-238358:
Old: 
```
Verify that Advanced Intrusion Detection Environment (AIDE) notifies the System
Administrator
 when anomalies in the operation of any security functions are discovered
with the following command:

$ grep SILENTREPORTS /etc/default/aide

SILENTREPORTS=no


If SILENTREPORTS is commented out, this is a finding.

If SILENTREPORTS is set to "yes",
this is a finding.

If SILENTREPORTS is not set to "no", this is a finding.

```

Updated:
```
Verify that Advanced Intrusion Detection Environment (AIDE) notifies the SA when anomalies in the operation of any security functions are discovered with the following command: 
 
$ grep SILENTREPORTS /etc/default/aide 
 
SILENTREPORTS=no 
 
If SILENTREPORTS is commented out, this is a finding. 
 
If SILENTREPORTS is set to "yes", this is a finding. 
 
If SILENTREPORTS is not set to "no", this is a finding.

```
---
SV-238364:
Old: 
```
Verify the directory containing the root certificates for the Ubuntu operating system
(/etc/ssl/certs) only contains certificate files for DoD PKI-established certificate
authorities.

Determine if "/etc/ssl/certs" only contains certificate files whose
sha256 fingerprint match the fingerprint of DoD PKI-established certificate authorities
with the following command:

$ for f in $(realpath /etc/ssl/certs/*); do openssl x509
-sha256 -in $f -noout -fingerprint | cut -d= -f2 | tr -d ':' | egrep -vw '(9676F287356C89A12683D65234098CB77C4F1C18F23C0E541DE0E196725B7EBE|B107B33F453E5510F68E513110C6F6944BACC263DF0137F821C1B3C2F8F863D2|559A5189452B13F8233F0022363C06F26E3C517C1D4B77445035959DF3244F74|1F4EDE9DC2A241F6521BF518424ACD49EBE84420E69DAF5BAC57AF1F8EE294A9)';
done

If any entry is found, this is a finding.

```

Updated:
```
Verify the directory containing the root certificates for the Ubuntu operating system contains certificate files for DoD PKI-established certificate authorities by iterating over all files in the "/etc/ssl/certs" directory and checking if, at least one, has the subject matching "DOD ROOT CA".

If none is found, this is a finding.

```
---
SV-238368:
Old: 
```
Verify the NX (no-execution) bit flag is set on the system with the following commands:

$
dmesg | grep -i "execute disable"
[    0.000000] NX (Execute Disable) protection: active

If
"dmesg" does not show "NX (Execute Disable) protection: active", check the cpuinfo settings
with the following command:

$ grep flags /proc/cpuinfo | grep -w nx | sort -u
flags       : fpu vme
de pse tsc ms nx rdtscp lm constant_tsc

If "flags" does not contain the "nx" flag, this is a
finding.

```

Updated:
```
Verify the NX (no-execution) bit flag is set on the system with the following commands: 
 
     $ sudo dmesg | grep -i "execute disable" 
     [    0.000000] NX (Execute Disable) protection: active 
 
If "dmesg" does not show "NX (Execute Disable) protection: active", check the cpuinfo settings with the following command:  
 
     $ grep flags /proc/cpuinfo | grep -w nx | sort -u 
     flags       : fpu vme de pse tsc ms nx rdtscp lm constant_tsc 
 
If "flags" does not contain the "nx" flag, this is a finding.

```
---
SV-238371:
Old: 
```
Verify that Advanced Intrusion Detection Environment (AIDE) is installed and verifies the
correct operation of all security functions.

Check that the AIDE package is installed with
the following command:

$ sudo dpkg -l | grep aide
ii  aide   0.16.1-1build2  amd64    Advanced
Intrusion Detection Environment - static binary

If AIDE is not installed, ask the System
Administrator how file integrity checks are performed on the system.

If no application is
installed to perform integrity checks, this is a finding.

```

Updated:
```
Verify that Advanced Intrusion Detection Environment (AIDE) is installed and verifies the correct operation of all security functions.

Check that the AIDE package is installed with the following command:
     $ sudo dpkg -l | grep aide 
     ii   aide   0.16.1-1build2   amd64   Advanced Intrusion Detection Environment - static binary

If AIDE is not installed, ask the System Administrator how file integrity checks are performed on the system. 

If there is no application installed to perform integrity checks, this is a finding.

If AIDE is installed, check if it has been initialized with the following command:
     $ sudo aide.wrapper --check

If the output is "Couldn't open file /var/lib/aide/aide.db for reading", this is a finding.

```
---
</details>

#### Fixes:
<details open>
  <summary>Click to expand.</summary>
SV-238204:
Old: 
```
Configure the system to require a password for authentication upon booting into single-user
and maintenance modes.

Generate an encrypted (grub) password for root with the following
command:

$ grub-mkpasswd-pbkdf2
Enter Password:
Reenter Password:
PBKDF2 hash of
your password is grub.pbkdf2.sha512.10000.MFU48934NJD84NF8NSD39993JDHF84NG

Using
the hash from the output, modify the "/etc/grub.d/40_custom" file with the following
command to add a boot password:

$ sudo sed -i '$i set
superusers=\"root\"\npassword_pbkdf2 root &lt;hash&gt;' /etc/grub.d/40_custom


where &lt;hash&gt; is the hash generated by grub-mkpasswd-pbkdf2 command.

Generate an
updated "grub.conf" file with the new password by using the following command:

$ sudo
update-grub

```
New:
```
Configure the system to require a password for authentication upon booting into single-user and maintenance modes. 
 
Generate an encrypted (grub) password for root with the following command: 
 
$ grub-mkpasswd-pbkdf2 
Enter Password: 
Reenter Password: 
PBKDF2 hash of your password is grub.pbkdf2.sha512.10000.MFU48934NJD84NF8NSD39993JDHF84NG 
 
Using the hash from the output, modify the "/etc/grub.d/40_custom" file with the following command to add a boot password: 
 
$ sudo sed -i '$i set superusers=\"root\"\npassword_pbkdf2 root <hash>' /etc/grub.d/40_custom 
 
where <hash> is the hash generated by grub-mkpasswd-pbkdf2 command. 
 
Generate an updated "grub.conf" file with the new password by using the following command: 
 
$ sudo update-grub

```
---
SV-238206:
Old: 
```
Configure the sudo group with only members requiring access to security functions.

To
remove a user from the sudo group, run:

$ sudo gpasswd -d &lt;username&gt; sudo

```
New:
```
Configure the sudo group with only members requiring access to security functions. 
 
To remove a user from the sudo group, run: 
 
$ sudo gpasswd -d <username> sudo

```
---
SV-238243:
Old: 
```
Configure "auditd" service to notify the SA and ISSO in the event of an audit processing
failure.

Edit the following line in "/etc/audit/auditd.conf" to ensure administrators
are notified via email for those situations:

action_mail_acct =
&lt;administrator_account&gt;

Note: Change "administrator_account" to an account for
security personnel.

Restart the "auditd" service so the changes take effect:

$ sudo
systemctl restart auditd.service

```
New:
```
Configure "auditd" service to notify the SA and ISSO in the event of an audit processing failure.  
 
Edit the following line in "/etc/audit/auditd.conf" to ensure administrators are notified via email for those situations: 
 
action_mail_acct = <administrator_account> 
 
Note: Change "administrator_account" to an account for security personnel. 
 
Restart the "auditd" service so the changes take effect: 
 
$ sudo systemctl restart auditd.service

```
---
SV-238252:
Old: 
```
Configure the Ubuntu operating system to generate audit records when
successful/unsuccessful attempts to use the "su" command occur.

Add or update the
following rules in the "/etc/audit/rules.d/stig.rules" file:

-a always,exit -F
path=/bin/su -F perm=x -F auid&gt;=1000 -F auid!=4294967295 -k privileged-priv_change


To reload the rules file, issue the following command:

$ sudo augenrules --load

```
New:
```
Configure the Ubuntu operating system to generate audit records when successful/unsuccessful attempts to use the "su" command occur. 
 
Add or update the following rules in the "/etc/audit/rules.d/stig.rules" file: 
 
-a always,exit -F path=/bin/su -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-priv_change  
 
To reload the rules file, issue the following command: 
 
$ sudo augenrules --load

```
---
SV-238253:
Old: 
```
Configure the audit system to generate an audit event for any successful/unsuccessful uses
of the "chfn" command.

Add or update the following rules in the
"/etc/audit/rules.d/stig.rules" file:

-a always,exit -F path=/usr/bin/chfn -F perm=x
-F auid&gt;=1000 -F auid!=4294967295 -k privileged-chfn

To reload the rules file, issue
the following command:

$ sudo augenrules --load

```
New:
```
Configure the audit system to generate an audit event for any successful/unsuccessful uses of the "chfn" command. 
 
Add or update the following rules in the "/etc/audit/rules.d/stig.rules" file: 
 
-a always,exit -F path=/usr/bin/chfn -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-chfn 
 
To reload the rules file, issue the following command: 
 
$ sudo augenrules --load

```
---
SV-238254:
Old: 
```
Configure the audit system to generate an audit event for any successful/unsuccessful use of
the "mount" command.

Add or update the following rules in the
"/etc/audit/rules.d/stig.rules" file:

-a always,exit -F path=/usr/bin/mount -F
perm=x -F auid&gt;=1000 -F auid!=4294967295 -k privileged-mount

To reload the rules
file, issue the following command:

$ sudo augenrules --load

```
New:
```
Configure the audit system to generate an audit event for any successful/unsuccessful use of the "mount" command.  
 
Add or update the following rules in the "/etc/audit/rules.d/stig.rules" file: 
 
-a always,exit -F path=/usr/bin/mount -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-mount 
 
To reload the rules file, issue the following command: 
 
$ sudo augenrules --load

```
---
SV-238255:
Old: 
```
Configure the audit system to generate an audit event for any successful/unsuccessful use of
the "umount" command.

Add or update the following rules in the
"/etc/audit/rules.d/stig.rules" file:

-a always,exit -F path=/usr/bin/umount -F
perm=x -F auid&gt;=1000 -F auid!=4294967295 -k privileged-umount

To reload the rules
file, issue the following command:

$ sudo augenrules --load

```
New:
```
Configure the audit system to generate an audit event for any successful/unsuccessful use of the "umount" command.  
 
Add or update the following rules in the "/etc/audit/rules.d/stig.rules" file: 
 
-a always,exit -F path=/usr/bin/umount -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-umount 
 
To reload the rules file, issue the following command: 
 
$ sudo augenrules --load

```
---
SV-238256:
Old: 
```
Configure the audit system to generate an audit event for any successful/unsuccessful use of
the "ssh-agent" command.

Add or update the following rules in the
"/etc/audit/rules.d/stig.rules" file:

-a always,exit -F path=/usr/bin/ssh-agent -F
perm=x -F auid&gt;=1000 -F auid!=4294967295 -k privileged-ssh

To reload the rules file,
issue the following command:

$ sudo augenrules --load

```
New:
```
Configure the audit system to generate an audit event for any successful/unsuccessful use of the "ssh-agent" command.  
 
Add or update the following rules in the "/etc/audit/rules.d/stig.rules" file: 
 
-a always,exit -F path=/usr/bin/ssh-agent -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-ssh 
 
To reload the rules file, issue the following command: 
 
$ sudo augenrules --load

```
---
SV-238257:
Old: 
```
Configure the audit system to generate an audit event for any successful/unsuccessful use of
the "ssh-keysign" command.

Add or update the following rules in the
"/etc/audit/rules.d/stig.rules" file:

-a always,exit -F
path=/usr/lib/openssh/ssh-keysign -F perm=x -F auid&gt;=1000 -F auid!=4294967295 -k
privileged-ssh

To reload the rules file, issue the following command:

$ sudo augenrules
--load

```
New:
```
Configure the audit system to generate an audit event for any successful/unsuccessful use of the "ssh-keysign" command.  
 
Add or update the following rules in the "/etc/audit/rules.d/stig.rules" file: 
 
-a always,exit -F path=/usr/lib/openssh/ssh-keysign -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-ssh 
 
To reload the rules file, issue the following command: 
 
$ sudo augenrules --load

```
---
SV-238258:
Old: 
```
Configure the audit system to generate an audit event for any successful/unsuccessful use of
the "setxattr", "fsetxattr", "lsetxattr", "removexattr", "fremovexattr", and
"lremovexattr" system calls.

Add or update the following rules in the
"/etc/audit/rules.d/stig.rules" file:

-a always,exit -F arch=b32 -S
setxattr,fsetxattr,lsetxattr,removexattr,fremovexattr,lremovexattr -F
auid&gt;=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S
setxattr,fsetxattr,lsetxattr,removexattr,fremovexattr,lremovexattr -F auid=0 -k
perm_mod
-a always,exit -F arch=b64 -S
setxattr,fsetxattr,lsetxattr,removexattr,fremovexattr,lremovexattr -F
auid&gt;=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S
setxattr,fsetxattr,lsetxattr,removexattr,fremovexattr,lremovexattr -F auid=0 -k
perm_mod

Note: For 32-bit architectures, only the 32-bit specific entries are required.


To reload the rules file, issue the following command:

$ sudo augenrules --load

```
New:
```
Configure the audit system to generate an audit event for any successful/unsuccessful use of the "setxattr", "fsetxattr", "lsetxattr", "removexattr", "fremovexattr", and "lremovexattr" system calls. 
 
Add or update the following rules in the "/etc/audit/rules.d/stig.rules" file: 
 
-a always,exit -F arch=b32 -S setxattr,fsetxattr,lsetxattr,removexattr,fremovexattr,lremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod 
-a always,exit -F arch=b32 -S setxattr,fsetxattr,lsetxattr,removexattr,fremovexattr,lremovexattr -F auid=0 -k perm_mod  
-a always,exit -F arch=b64 -S setxattr,fsetxattr,lsetxattr,removexattr,fremovexattr,lremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod 
-a always,exit -F arch=b64 -S setxattr,fsetxattr,lsetxattr,removexattr,fremovexattr,lremovexattr -F auid=0 -k perm_mod  
 
Note: For 32-bit architectures, only the 32-bit specific entries are required.
 
To reload the rules file, issue the following command: 
 
$ sudo augenrules --load

```
---
SV-238264:
Old: 
```
Configure the audit system to generate an audit event for any successful/unsuccessful use of
the "chown", "fchown", "fchownat", and "lchown" system calls.

Add or update the following
rules in the "/etc/audit/rules.d/stig.rules":

-a always,exit -F arch=b32 -S
chown,fchown,fchownat,lchown -F auid&gt;=1000 -F auid!=4294967295 -k perm_chng
-a
always,exit -F arch=b64 -S chown,fchown,fchownat,lchown -F auid&gt;=1000 -F
auid!=4294967295 -k perm_chng

Note: For 32-bit architectures, only the 32-bit specific
entries are required.

To reload the rules file, issue the following command:

$ sudo
augenrules --load

```
New:
```
Configure the audit system to generate an audit event for any successful/unsuccessful use of the "chown", "fchown", "fchownat", and "lchown" system calls. 
 
Add or update the following rules in the "/etc/audit/rules.d/stig.rules": 
 
-a always,exit -F arch=b32 -S chown,fchown,fchownat,lchown -F auid>=1000 -F auid!=4294967295 -k perm_chng 
-a always,exit -F arch=b64 -S chown,fchown,fchownat,lchown -F auid>=1000 -F auid!=4294967295 -k perm_chng 
 
Note: For 32-bit architectures, only the 32-bit specific entries are required.  
 
To reload the rules file, issue the following command: 
 
$ sudo augenrules --load

```
---
SV-238268:
Old: 
```
Configure the audit system to generate an audit event for any successful/unsuccessful use of
the "chmod", "fchmod", and "fchmodat" system calls.

Add or update the following rules in
the "/etc/audit/rules.d/stig.rules":

-a always,exit -F arch=b32 -S
chmod,fchmod,fchmodat -F auid&gt;=1000 -F auid!=4294967295 -k perm_chng
-a always,exit
-F arch=b64 -S chmod,fchmod,fchmodat -F auid&gt;=1000 -F auid!=4294967295 -k perm_chng


Notes: For 32-bit architectures, only the 32-bit specific entries are required.

To
reload the rules file, issue the following command:

$ sudo augenrules --load

```
New:
```
Configure the audit system to generate an audit event for any successful/unsuccessful use of the "chmod", "fchmod", and "fchmodat" system calls. 
 
Add or update the following rules in the "/etc/audit/rules.d/stig.rules": 
 
-a always,exit -F arch=b32 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_chng 
-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_chng 
 
Notes: For 32-bit architectures, only the 32-bit specific entries are required.  
 
To reload the rules file, issue the following command: 
 
$ sudo augenrules --load

```
---
SV-238271:
Old: 
```
Configure the audit system to generate an audit event for any unsuccessful use of the"creat",
"open", "openat", "open_by_handle_at", "truncate", and "ftruncate" system calls.

Add
or update the following rules in the "/etc/audit/rules.d/stig.rules" file:

-a
always,exit -F arch=b32 -S creat,open,openat,open_by_handle_at,truncate,ftruncate -F
exit=-EPERM -F auid&gt;=1000 -F auid!=4294967295 -k perm_access
-a always,exit -F
arch=b32 -S creat,open,openat,open_by_handle_at,truncate,ftruncate -F exit=-EACCES
-F auid&gt;=1000 -F auid!=4294967295 -k perm_access
-a always,exit -F arch=b64 -S
creat,open,openat,open_by_handle_at,truncate,ftruncate -F exit=-EPERM -F
auid&gt;=1000 -F auid!=4294967295 -k perm_access
-a always,exit -F arch=b64 -S
creat,open,openat,open_by_handle_at,truncate,ftruncate -F exit=-EACCES -F
auid&gt;=1000 -F auid!=4294967295 -k perm_access

Notes: For 32-bit architectures, only
the 32-bit specific entries are required.

To reload the rules file, issue the following
command:

$ sudo augenrules --load

```
New:
```
Configure the audit system to generate an audit event for any unsuccessful use of the"creat", "open", "openat", "open_by_handle_at", "truncate", and "ftruncate" system calls.  
 
Add or update the following rules in the "/etc/audit/rules.d/stig.rules" file: 
 
-a always,exit -F arch=b32 -S creat,open,openat,open_by_handle_at,truncate,ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k perm_access 
-a always,exit -F arch=b32 -S creat,open,openat,open_by_handle_at,truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k perm_access 
-a always,exit -F arch=b64 -S creat,open,openat,open_by_handle_at,truncate,ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k perm_access 
-a always,exit -F arch=b64 -S creat,open,openat,open_by_handle_at,truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k perm_access 
 
Notes: For 32-bit architectures, only the 32-bit specific entries are required.  
 
To reload the rules file, issue the following command: 
 
$ sudo augenrules --load

```
---
SV-238277:
Old: 
```
Configure the audit system to generate an audit event for any successful/unsuccessful use of
the "sudo" command.

Add or update the following rules in the
"/etc/audit/rules.d/stig.rules" file:

-a always,exit -F path=/usr/bin/sudo -F perm=x
-F auid&gt;=1000 -F auid!=4294967295 -k priv_cmd

To reload the rules file, issue the
following command:

$ sudo augenrules --load

```
New:
```
Configure the audit system to generate an audit event for any successful/unsuccessful use of the "sudo" command.  
 
Add or update the following rules in the "/etc/audit/rules.d/stig.rules" file: 
 
-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=4294967295 -k priv_cmd 
   
To reload the rules file, issue the following command: 
 
$ sudo augenrules --load

```
---
SV-238278:
Old: 
```
Configure the audit system to generate an audit event for any successful/unsuccessful use of
the "sudoedit" command.

Add or update the following rules in the
"/etc/audit/rules.d/stig.rules":

-a always,exit -F path=/usr/bin/sudoedit -F perm=x
-F auid&gt;=1000 -F auid!=4294967295 -k priv_cmd

To reload the rules file, issue the
following command:

$ sudo augenrules --load

```
New:
```
Configure the audit system to generate an audit event for any successful/unsuccessful use of the "sudoedit" command.  
 
Add or update the following rules in the "/etc/audit/rules.d/stig.rules": 
 
-a always,exit -F path=/usr/bin/sudoedit -F perm=x -F auid>=1000 -F auid!=4294967295 -k priv_cmd 
   
To reload the rules file, issue the following command: 
 
$ sudo augenrules --load

```
---
SV-238279:
Old: 
```
Configure the audit system to generate an audit event for any successful/unsuccessful use of
the "chsh" command.

Add or update the following rules in the
"/etc/audit/rules.d/stig.rules" file:

-a always,exit -F path=/usr/bin/chsh -F perm=x
-F auid&gt;=1000 -F auid!=4294967295 -k priv_cmd

To reload the rules file, issue the
following command:

$ sudo augenrules --load

```
New:
```
Configure the audit system to generate an audit event for any successful/unsuccessful use of the "chsh" command.  
 
Add or update the following rules in the "/etc/audit/rules.d/stig.rules" file: 
 
-a always,exit -F path=/usr/bin/chsh -F perm=x -F auid>=1000 -F auid!=4294967295 -k priv_cmd 
   
To reload the rules file, issue the following command: 
 
$ sudo augenrules --load

```
---
SV-238280:
Old: 
```
Configure the audit system to generate an audit event for any successful/unsuccessful use of
the "newgrp" command.

Add or update the following rules in the
"/etc/audit/rules.d/stig.rules" file:

-a always,exit -F path=/usr/bin/newgrp -F
perm=x -F auid&gt;=1000 -F auid!=4294967295 -k priv_cmd

To reload the rules file, issue
the following command:

$ sudo augenrules --load

```
New:
```
Configure the audit system to generate an audit event for any successful/unsuccessful use of the "newgrp" command.  
 
Add or update the following rules in the "/etc/audit/rules.d/stig.rules" file: 
 
-a always,exit -F path=/usr/bin/newgrp -F perm=x -F auid>=1000 -F auid!=4294967295 -k priv_cmd 
   
To reload the rules file, issue the following command: 
 
$ sudo augenrules --load

```
---
SV-238281:
Old: 
```
Configure the audit system to generate an audit event for any successful/unsuccessful use of
the "chcon" command.

Add or update the following rules in the
"/etc/audit/rules.d/stig.rules" file:

-a always,exit -F path=/usr/bin/chcon -F
perm=x -F auid&gt;=1000 -F auid!=4294967295 -k perm_chng

To reload the rules file, issue
the following command:

$ sudo augenrules --load

```
New:
```
Configure the audit system to generate an audit event for any successful/unsuccessful use of the "chcon" command.  
 
Add or update the following rules in the "/etc/audit/rules.d/stig.rules" file: 
 
-a always,exit -F path=/usr/bin/chcon -F perm=x -F auid>=1000 -F auid!=4294967295 -k perm_chng 
   
To reload the rules file, issue the following command: 
 
$ sudo augenrules --load

```
---
SV-238282:
Old: 
```
Configure the audit system to generate an audit event for any successful/unsuccessful use of
the "apparmor_parser" command.

Add or update the following rules in the
"/etc/audit/rules.d/stig.rules" file:

-a always,exit -F path=/sbin/apparmor_parser
-F perm=x -F auid&gt;=1000 -F auid!=4294967295 -k perm_chng

To reload the rules file,
issue the following command:

$ sudo augenrules --load

```
New:
```
Configure the audit system to generate an audit event for any successful/unsuccessful use of the "apparmor_parser" command.  
 
Add or update the following rules in the "/etc/audit/rules.d/stig.rules" file: 
 
-a always,exit -F path=/sbin/apparmor_parser -F perm=x -F auid>=1000 -F auid!=4294967295 -k perm_chng 
   
To reload the rules file, issue the following command: 
 
$ sudo augenrules --load

```
---
SV-238283:
Old: 
```
Configure the audit system to generate an audit event for any successful/unsuccessful use of
the "setfacl" command.

Add or update the following rules in the
"/etc/audit/rules.d/stig.rules" file:

-a always,exit -F path=/usr/bin/setfacl -F
perm=x -F auid&gt;=1000 -F auid!=4294967295 -k perm_chng

To reload the rules file, issue
the following command:

$ sudo augenrules --load

```
New:
```
Configure the audit system to generate an audit event for any successful/unsuccessful use of the "setfacl" command.  
 
Add or update the following rules in the "/etc/audit/rules.d/stig.rules" file: 
 
-a always,exit -F path=/usr/bin/setfacl -F perm=x -F auid>=1000 -F auid!=4294967295 -k perm_chng 
   
To reload the rules file, issue the following command: 
 
$ sudo augenrules --load

```
---
SV-238284:
Old: 
```
Configure the audit system to generate an audit event for any successful/unsuccessful use of
the "chacl" command.

Add or update the following rules in the
"/etc/audit/rules.d/stig.rules" file:

-a always,exit -F path=/usr/bin/chacl -F
perm=x -F auid&gt;=1000 -F auid!=4294967295 -k perm_chng

To reload the rules file, issue
the following command:

$ sudo augenrules --load

```
New:
```
Configure the audit system to generate an audit event for any successful/unsuccessful use of the "chacl" command.  
 
Add or update the following rules in the "/etc/audit/rules.d/stig.rules" file: 
 
-a always,exit -F path=/usr/bin/chacl -F perm=x -F auid>=1000 -F auid!=4294967295 -k perm_chng 
    
To reload the rules file, issue the following command: 
 
$ sudo augenrules --load

```
---
SV-238288:
Old: 
```
Configure the audit system to generate an audit event for any successful/unsuccessful uses
of the "passwd" command.

Add or update the following rule in the
"/etc/audit/rules.d/stig.rules" file:

-a always,exit -F path=/usr/bin/passwd -F
perm=x -F auid&gt;=1000 -F auid!=4294967295 -k privileged-passwd

To reload the rules
file, issue the following command:

$ sudo augenrules --load

```
New:
```
Configure the audit system to generate an audit event for any successful/unsuccessful uses of the "passwd" command.  
 
Add or update the following rule in the "/etc/audit/rules.d/stig.rules" file: 
 
-a always,exit -F path=/usr/bin/passwd -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-passwd 
   
To reload the rules file, issue the following command: 
 
$ sudo augenrules --load

```
---
SV-238289:
Old: 
```
Configure the audit system to generate an audit event for any successful/unsuccessful uses
of the "unix_update" command.

Add or update the following rules in the
"/etc/audit/rules.d/stig.rules" file:

-a always,exit -F path=/sbin/unix_update -F
perm=x -F auid&gt;=1000 -F auid!=4294967295 -k privileged-unix-update

To reload the
rules file, issue the following command:

$ sudo augenrules --load

```
New:
```
Configure the audit system to generate an audit event for any successful/unsuccessful uses of the "unix_update" command.  
 
Add or update the following rules in the "/etc/audit/rules.d/stig.rules" file: 
 
-a always,exit -F path=/sbin/unix_update -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-unix-update 
  
To reload the rules file, issue the following command: 
 
$ sudo augenrules --load

```
---
SV-238290:
Old: 
```
Configure the audit system to generate an audit event for any successful/unsuccessful uses
of the "gpasswd" command.

Add or update the following rules in the
"/etc/audit/rules.d/stig.rules" file:

-a always,exit -F path=/usr/bin/gpasswd -F
perm=x -F auid&gt;=1000 -F auid!=4294967295 -k privileged-gpasswd

To reload the rules
file, issue the following command:

$ sudo augenrules --load

```
New:
```
Configure the audit system to generate an audit event for any successful/unsuccessful uses of the "gpasswd" command.  
 
Add or update the following rules in the "/etc/audit/rules.d/stig.rules" file: 
 
-a always,exit -F path=/usr/bin/gpasswd -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-gpasswd 
   
To reload the rules file, issue the following command: 
 
$ sudo augenrules --load

```
---
SV-238291:
Old: 
```
Configure the audit system to generate an audit event for any successful/unsuccessful uses
of the "chage" command.

Add or update the following rules in the
"/etc/audit/rules.d/stig.rules" file:

-a always,exit -F path=/usr/bin/chage -F
perm=x -F auid&gt;=1000 -F auid!=4294967295 -k privileged-chage

To reload the rules
file, issue the following command:

$ sudo augenrules --load

```
New:
```
Configure the audit system to generate an audit event for any successful/unsuccessful uses of the "chage" command.  
 
Add or update the following rules in the "/etc/audit/rules.d/stig.rules" file: 
 
-a always,exit -F path=/usr/bin/chage -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-chage 
   
To reload the rules file, issue the following command: 
 
$ sudo augenrules --load

```
---
SV-238292:
Old: 
```
Configure the audit system to generate an audit event for any successful/unsuccessful uses
of the "usermod" command.

Add or update the following rules in the
"/etc/audit/rules.d/stig.rules" file:

-a always,exit -F path=/usr/sbin/usermod -F
perm=x -F auid&gt;=1000 -F auid!=4294967295 -k privileged-usermod

To reload the rules
file, issue the following command:

$ sudo augenrules --load

```
New:
```
Configure the audit system to generate an audit event for any successful/unsuccessful uses of the "usermod" command.  
 
Add or update the following rules in the "/etc/audit/rules.d/stig.rules" file: 
 
-a always,exit -F path=/usr/sbin/usermod -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-usermod 
   
To reload the rules file, issue the following command: 
 
$ sudo augenrules --load

```
---
SV-238293:
Old: 
```
Configure the audit system to generate an audit event for any successful/unsuccessful uses
of the "crontab" command.

Add or update the following rules in the
"/etc/audit/rules.d/stig.rules" file:

-a always,exit -F path=/usr/bin/crontab -F
perm=x -F auid&gt;=1000 -F auid!=4294967295 -k privileged-crontab

To reload the rules
file, issue the following command:

$ sudo augenrules --load

```
New:
```
Configure the audit system to generate an audit event for any successful/unsuccessful uses of the "crontab" command.  
 
Add or update the following rules in the "/etc/audit/rules.d/stig.rules" file: 
 
-a always,exit -F path=/usr/bin/crontab -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-crontab 
   
To reload the rules file, issue the following command: 
 
$ sudo augenrules --load

```
---
SV-238294:
Old: 
```
Configure the audit system to generate an audit event for any successful/unsuccessful uses
of the "pam_timestamp_check" command.

Add or update the following rules in the
"/etc/audit/rules.d/stig.rules" file:

-a always,exit -F
path=/usr/sbin/pam_timestamp_check -F perm=x -F auid&gt;=1000 -F auid!=4294967295 -k
privileged-pam_timestamp_check

To reload the rules file, issue the following command:


$ sudo augenrules --load

```
New:
```
Configure the audit system to generate an audit event for any successful/unsuccessful uses of the "pam_timestamp_check" command.  
 
Add or update the following rules in the "/etc/audit/rules.d/stig.rules" file: 
 
-a always,exit -F path=/usr/sbin/pam_timestamp_check -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-pam_timestamp_check 
   
To reload the rules file, issue the following command: 
 
$ sudo augenrules --load

```
---
SV-238295:
Old: 
```
Configure the audit system to generate an audit event for any successful/unsuccessful use of
the "init_module" and "finit_module" syscalls.

Add or update the following rules in the
"/etc/audit/rules.d/stig.rules" file:

-a always,exit -F arch=b32 -S
init_module,finit_module -F auid&gt;=1000 -F auid!=4294967295 -k module_chng
-a
always,exit -F arch=b64 -S init_module,finit_module -F auid&gt;=1000 -F
auid!=4294967295 -k module_chng

Notes: For 32-bit architectures, only the 32-bit
specific entries are required.

To reload the rules file, issue the following command:

$
sudo augenrules --load

```
New:
```
Configure the audit system to generate an audit event for any successful/unsuccessful use of the "init_module" and "finit_module" syscalls.  
 
Add or update the following rules in the "/etc/audit/rules.d/stig.rules" file: 
 
-a always,exit -F arch=b32 -S init_module,finit_module -F auid>=1000 -F auid!=4294967295 -k module_chng 
-a always,exit -F arch=b64 -S init_module,finit_module -F auid>=1000 -F auid!=4294967295 -k module_chng 
  
Notes: For 32-bit architectures, only the 32-bit specific entries are required.  
  
To reload the rules file, issue the following command: 
 
$ sudo augenrules --load

```
---
SV-238297:
Old: 
```
Configure the audit system to generate an audit event for any successful/unsuccessful use of
the "delete_module" syscall.

Add or update the following rules in the
"/etc/audit/rules.d/stig.rules" file:

-a always,exit -F arch=b32 -S delete_module -F
auid&gt;=1000 -F auid!=4294967295 -k module_chng
-a always,exit -F arch=b64 -S
delete_module -F auid&gt;=1000 -F auid!=4294967295 -k module_chng

Notes: For 32-bit
architectures, only the 32-bit specific entries are required.

To reload the rules file,
issue the following command:

$ sudo augenrules --load

```
New:
```
Configure the audit system to generate an audit event for any successful/unsuccessful use of the "delete_module" syscall.  
 
Add or update the following rules in the "/etc/audit/rules.d/stig.rules" file: 
 
-a always,exit -F arch=b32 -S delete_module -F auid>=1000 -F auid!=4294967295 -k module_chng 
-a always,exit -F arch=b64 -S delete_module -F auid>=1000 -F auid!=4294967295 -k module_chng 
  
Notes: For 32-bit architectures, only the 32-bit specific entries are required.  
  
To reload the rules file, issue the following command: 
 
$ sudo augenrules --load

```
---
SV-238305:
Old: 
```
Allocate enough storage capacity for at least one week's worth of audit records when audit
records are not immediately sent to a central audit record storage facility.

If audit
records are stored on a partition made specifically for audit records, use the "parted"
program to resize the partition with sufficient space to contain one week's worth of audit
records.

If audit records are not stored on a partition made specifically for audit
records, a new partition with sufficient amount of space will need be to be created.

Set the
auditd server to point to the mount point where the audit records must be located:

$ sudo sed
-i -E 's@^(log_file\s*=\s*).*@\1 &lt;log mountpoint&gt;/audit.log@'
/etc/audit/auditd.conf

where &lt;log mountpoint&gt; is the aforementioned mount
point.

```
New:
```
Allocate enough storage capacity for at least one week's worth of audit records when audit records are not immediately sent to a central audit record storage facility. 
 
If audit records are stored on a partition made specifically for audit records, use the "parted" program to resize the partition with sufficient space to contain one week's worth of audit records. 
 
If audit records are not stored on a partition made specifically for audit records, a new partition with sufficient amount of space will need be to be created. 
 
Set the auditd server to point to the mount point where the audit records must be located: 
 
$ sudo sed -i -E 's@^(log_file\s*=\s*).*@\1 <log mountpoint>/audit.log@' /etc/audit/auditd.conf 
 
where <log mountpoint> is the aforementioned mount point.

```
---
SV-238306:
Old: 
```
Configure the audit event multiplexor to offload audit records to a different system or
storage media from the system being audited.

Install the audisp-remote plugin:

$ sudo
apt-get install audispd-plugins -y

Set the audisp-remote plugin as active by editing the
"/etc/audisp/plugins.d/au-remote.conf" file:

$ sudo sed -i -E
's/active\s*=\s*no/active = yes/' /etc/audisp/plugins.d/au-remote.conf

Set the
address of the remote machine by editing the "/etc/audisp/audisp-remote.conf" file:

$
sudo sed -i -E 's/(remote_server\s*=).*/\1 &lt;remote addr&gt;/'
/etc/audisp/audisp-remote.conf

where &lt;remote addr&gt; must be substituted by the
address of the remote server receiving the audit log.

Make the audit service reload its
configuration files:

$ sudo systemctl restart auditd.service

```
New:
```
Configure the audit event multiplexor to offload audit records to a different system or storage media from the system being audited. 
 
Install the audisp-remote plugin: 
 
$ sudo apt-get install audispd-plugins -y 
 
Set the audisp-remote plugin as active by editing the "/etc/audisp/plugins.d/au-remote.conf" file: 
 
$ sudo sed -i -E 's/active\s*=\s*no/active = yes/' /etc/audisp/plugins.d/au-remote.conf 
 
Set the address of the remote machine by editing the "/etc/audisp/audisp-remote.conf" file: 
 
$ sudo sed -i -E 's/(remote_server\s*=).*/\1 <remote addr>/' /etc/audisp/audisp-remote.conf 
 
where <remote addr> must be substituted by the address of the remote server receiving the audit log. 
 
Make the audit service reload its configuration files: 
 
$ sudo systemctl restart auditd.service

```
---
SV-238310:
Old: 
```
Configure the audit system to generate audit events for any successful/unsuccessful use of
"unlink", "unlinkat", "rename", "renameat", and "rmdir" system calls.

Add or update the
following rules in the "/etc/audit/rules.d/stig.rules" file:

-a always,exit -F
arch=b64 -S unlink,unlinkat,rename,renameat,rmdir -F auid&gt;=1000 -F
auid!=4294967295 -k delete
-a always,exit -F arch=b32 -S
unlink,unlinkat,rename,renameat,rmdir -F auid&gt;=1000 -F auid!=4294967295 -k delete


Notes: For 32-bit architectures, only the 32-bit specific entries are required.

To
reload the rules file, issue the following command:

$ sudo augenrules --load

```
New:
```
Configure the audit system to generate audit events for any successful/unsuccessful use of "unlink", "unlinkat", "rename", "renameat", and "rmdir" system calls. 
 
Add or update the following rules in the "/etc/audit/rules.d/stig.rules" file:
 
-a always,exit -F arch=b64 -S unlink,unlinkat,rename,renameat,rmdir -F auid>=1000 -F auid!=4294967295 -k delete 
-a always,exit -F arch=b32 -S unlink,unlinkat,rename,renameat,rmdir -F auid>=1000 -F auid!=4294967295 -k delete 

Notes: For 32-bit architectures, only the 32-bit specific entries are required. 
 
To reload the rules file, issue the following command: 
 
$ sudo augenrules --load

```
---
SV-238316:
Old: 
```
Configure the audit system to generate audit events showing start and stop times for user
access via the "/var/run/wtmp" file.

Add or update the following rules in the
"/etc/audit/rules.d/stig.rules" file:

-w /var/run/wtmp -p wa -k logins

To reload the
rules file, issue the following command:

$ sudo augenrules --load

```
New:
```
Configure the audit system to generate audit events showing start and stop times for user access via the "/var/run/utmp" file. 
 
Add or update the following rules in the "/etc/audit/rules.d/stig.rules" file: 
 
-w /var/run/utmp -p wa -k logins 
  
To reload the rules file, issue the following command: 
 
$ sudo augenrules --load

```
---
SV-238328:
Old: 
```
Add all ports, protocols, or services allowed by the PPSM CLSA by using the following command:


$ sudo ufw allow &lt;direction&gt; &lt;port/protocol/service&gt;

where the
direction is "in" or "out" and the port is the one corresponding to the protocol  or service
allowed.

To deny access to ports, protocols, or services, use:

$ sudo ufw deny
&lt;direction&gt; &lt;port/protocol/service&gt;

```
New:
```
Add all ports, protocols, or services allowed by the PPSM CLSA by using the following command: 
 
$ sudo ufw allow <direction> <port/protocol/service> 
 
where the direction is "in" or "out" and the port is the one corresponding to the protocol  or service allowed. 
 
To deny access to ports, protocols, or services, use: 
 
$ sudo ufw deny <direction> <port/protocol/service>

```
---
SV-238330:
Old: 
```
Configure the Ubuntu operating system to disable account identifiers after 35 days of
inactivity after the password expiration.

Run the following command to change the
configuration for adduser:

$ sudo useradd -D -f 35

Note: DoD recommendation is 35 days,
but a lower value is acceptable. The value "0" will disable the account immediately after the
password expires.

```
New:
```
Configure the Ubuntu operating system to disable account identifiers after 35 days of inactivity since the password expiration.  
 
Run the following command to change the configuration for adduser: 
 
$ sudo useradd -D -f 35 
 
Note: DoD recommendation is 35 days, but a lower value is acceptable. The value "0" will disable the account immediately after the password expires.

```
---
SV-238331:
Old: 
```
If an emergency account must be created, configure the system to terminate the account after a
72-hour time period with the following command to set an expiration date on it. Substitute
"account_name" with the account to be created.

$ sudo chage -E $(date -d "+3 days" +%F)
account_name

```
New:
```
Configure the operating system to expire temporary accounts after 72 hours with the following command:

     $ sudo chage -E $(date -d +3days +%Y-%m-%d) <temporary_account_name>

```
---
SV-238337:
Old: 
```
Configure the Ubuntu operating system to set permissions of all log files under the
"/var/log" directory to 640 or more restricted by using the following command:

$ sudo find
/var/log -perm /137 -type f -exec chmod 640 '{}' \;

```
New:
```
Configure the Ubuntu operating system to set permissions of all log files under the "/var/log" directory to "640" or more restricted by using the following command:

Note: The btmp, wtmp, and lastlog files are excluded. Refer to the Discussion for details.

$ sudo find /var/log -perm /137 ! -name '*[bw]tmp' ! -name '*lastlog' -type f -exec chmod 640 '{}' \;

```
---
SV-238340:
Old: 
```
Configure the Ubuntu operating system to have permissions of 0750 for the "/var/log"
directory by running the following command:

$ sudo chmod 0750 /var/log

```
New:
```
Configure the Ubuntu operating system to have permissions of "0755" for the "/var/log" directory by running the following command: 
 
$ sudo chmod 0755 /var/log

```
---
SV-238363:
Old: 
```
Configure the system to run in FIPS mode. Add "fips=1" to the kernel parameter during the
Ubuntu operating systems install.

Enabling a FIPS mode on a pre-existing system involves a
number of modifications to the Ubuntu operating system. Refer to the Ubuntu Server 18.04 FIPS
140-2 security policy document for instructions.

A subscription to the "Ubuntu
Advantage" plan is required in order to obtain the FIPS Kernel cryptographic modules and
enable FIPS.

```
New:
```
Configure the system to run in FIPS mode. Add "fips=1" to the kernel parameter during the Ubuntu operating systems install. 
 
Enabling a FIPS mode on a pre-existing system involves a number of modifications to the Ubuntu operating system. Refer to the Ubuntu Server 18.04 FIPS 140-2 security policy document for instructions.  
 
A subscription to the "Ubuntu Pro" plan is required to obtain the FIPS Kernel cryptographic modules and enable FIPS.

```
---
SV-238364:
Old: 
```
Configure the Ubuntu operating system to only allow the use of DoD PKI-established
certificate authorities for verification of the establishment of protected sessions.


Edit the "/etc/ca-certificates.conf" file, adding the character "!" to the beginning of
all uncommented lines that do not start with the "!" character with the following command:

$
sudo sed -i -E 's/^([^!#]+)/!\1/' /etc/ca-certificates.conf

Add at least one DoD
certificate authority to the "/usr/local/share/ca-certificates" directory in the PEM
format.

Update the "/etc/ssl/certs" directory with the following command:

$ sudo
update-ca-certificates

```
New:
```
Configure the Ubuntu operating system to use of DoD PKI-established certificate authorities for verification of the establishment of protected sessions. 
 
Edit the "/etc/ca-certificates.conf" file, adding the character "!" to the beginning of all uncommented lines that do not start with the "!" character with the following command: 
 
     $ sudo sed -i -E 's/^([^!#]+)/!\1/' /etc/ca-certificates.conf 
 
Add at least one DoD certificate authority to the "/usr/local/share/ca-certificates" directory in the PEM format. 
 
Update the "/etc/ssl/certs" directory with the following command: 
 
     $ sudo update-ca-certificates

```
---
SV-238371:
Old: 
```
Install the AIDE package by running the following command:

$ sudo apt-get install aide

```
New:
```
Install AIDE, initialize it, and perform a manual check.

Install AIDE:
     $ sudo apt install aide

Initialize it (this may take a few minutes):
     $ sudo aideinit
     Running aide --init...

Example output:

     Start timestamp: 2022-11-20 11:53:17 -0700 (AIDE 0.16)
     AIDE initialized database at /var/lib/aide/aide.db.new
     Verbose level: 6

     Number of entries:      119543

     ---------------------------------------------------
     The attributes of the (uncompressed) database(s):
     ---------------------------------------------------

     /var/lib/aide/aide.db.new
     RMD160   : PiEP1DX91JMcHnRSPnpFqNfIFr4=
     TIGER    : /zM5yQBnOIoEH0jplJE5v6S0rUErbTXL
     SHA256   : BE2iHtBN9lEX53l4R/p7t1al0dIlsgPc
                       Lg4YI08+/Jk=
     SHA512   : JIdGeNVRgtBPPSwun9St+9cwUrgIIKUW
                       KVTksZXJ29Tt+luC/XNDcjIub7fbPVw/
                       EcTDsvYtt9MBmBxw1wCYng==
     CRC32    : jB2FVw==
     HAVAL    : Jhe+fqaDpkswpWSnOTN28TO05QFHsjdq
                       RcFZwCVUGTQ=
     GOST     : WFrarVyxpXbKdW9SAaOy1Te8rSodV3/q
                     nLsXuP7YujA=


End timestamp: 2022-11-20 11:58:19 -0700 (run time: 5m 2s)

The new database will need to be renamed to be read by AIDE:
     $ sudo cp -p /var/lib/aide/aide.db.new /var/lib/aide/aide.db

Perform a manual check:
     $ sudo aide.wrapper --check

Example output:
     Start timestamp: 2022-11-20 11:59:16 -0700 (AIDE 0.16)
     AIDE found differences between database and filesystem!!
     ...
	 
Done.

```
---
SV-251505:
Old: 
```
Configure the Ubuntu operating system to disable using the USB storage kernel module.


Create a file under "/etc/modprobe.d" to contain the following:

# sudo su -c "echo
install usb-storage /bin/true &gt;&gt; /etc/modprobe.d/DISASTIG.conf"

Configure the
operating system to disable the ability to use USB mass storage devices.

# sudo su -c "echo
blacklist usb-storage &gt;&gt; /etc/modprobe.d/DISASTIG.conf"

```
New:
```
Configure the Ubuntu operating system to disable using the USB storage kernel module. 

Create a file under "/etc/modprobe.d" to contain the following:

# sudo su -c "echo install usb-storage /bin/true >> /etc/modprobe.d/DISASTIG.conf"

Configure the operating system to disable the ability to use USB mass storage devices.

# sudo su -c "echo blacklist usb-storage >> /etc/modprobe.d/DISASTIG.conf"

```
---
SV-252704:
Old: 
```
List all the wireless interfaces with the following command:

$ ls -L -d
/sys/class/net/*/wireless | xargs dirname | xargs basename

For each interface,
configure the system to disable wireless network interfaces with the following command:

$
sudo ifdown &lt;interface name&gt;

For each interface listed, find their respective
module with the following command:

$ basename $(readlink -f
/sys/class/net/&lt;interface name&gt;/device/driver)

where &lt;interface name&gt;
must be substituted by the actual interface name.

Create a file in the "/etc/modprobe.d"
directory and for each module, add the following line:

install &lt;module name&gt;
/bin/true

For each module from the system, execute the  following command to remove it:

$
sudo modprobe -r &lt;module name&gt;

```
New:
```
List all the wireless interfaces with the following command: 
 
$ ls -L -d /sys/class/net/*/wireless | xargs dirname | xargs basename 
 
For each interface, configure the system to disable wireless network interfaces with the following command: 
 
$ sudo ifdown <interface name> 
 
For each interface listed, find their respective module with the following command: 
 
$ basename $(readlink -f /sys/class/net/<interface name>/device/driver) 
 
where <interface name> must be substituted by the actual interface name. 
 
Create a file in the "/etc/modprobe.d" directory and for each module, add the following line: 
 
install <module name> /bin/true 
 
For each module from the system, execute the  following command to remove it: 
 
$ sudo modprobe -r <module name>

```
---
</details>

### Updated Impacts
<details open>
  <summary>Click to expand.</summary>
SV-238198:
Old: 0
New: 0.5
---
SV-238214:
Old: 0
New: 0.5
---
SV-238379:
Old: 0
New: 0.7
---
</details>

### Updated Titles
<details>
  <summary>Click to expand.</summary>
SV-238196:
Old: The Ubuntu operating system must provision temporary user accounts with an expiration time
of 72 hours or less. 
New: The Ubuntu operating system must provision temporary user accounts with an expiration time of 72 hours or less.
---
SV-238197:
Old: The Ubuntu operating system must enable the graphical user logon banner to display the
Standard Mandatory DoD Notice and Consent Banner before granting local access to the system
via a graphical user logon. 
New: The Ubuntu operating system must enable the graphical user logon banner to display the Standard Mandatory DoD Notice and Consent Banner before granting local access to the system via a graphical user logon.
---
SV-238198:
Old: The Ubuntu operating system must display the Standard Mandatory DoD Notice and Consent
Banner before granting local access to the system via a graphical user logon. 
New: The Ubuntu operating system must display the Standard Mandatory DoD Notice and Consent Banner before granting local access to the system via a graphical user logon.
---
SV-238199:
Old: The Ubuntu operating system must retain a user&#39;s session lock until that user reestablishes
access using established identification and authentication procedures. 
New: The Ubuntu operating system must retain a user&#39;s session lock until that user reestablishes access using established identification and authentication procedures.
---
SV-238200:
Old: The Ubuntu operating system must allow users to directly initiate a session lock for all
connection types. 
New: The Ubuntu operating system must allow users to directly initiate a session lock for all connection types.
---
SV-238201:
Old: The Ubuntu operating system must map the authenticated identity to the user or group account
for PKI-based authentication. 
New: The Ubuntu operating system must map the authenticated identity to the user or group account for PKI-based authentication.
---
SV-238202:
Old: The Ubuntu operating system must enforce 24 hours&#x2F;1 day as the minimum password lifetime.
Passwords for new users must have a 24 hours&#x2F;1 day minimum password lifetime restriction. 
New: The Ubuntu operating system must enforce 24 hours&#x2F;1 day as the minimum password lifetime. Passwords for new users must have a 24 hours&#x2F;1 day minimum password lifetime restriction.
---
SV-238203:
Old: The Ubuntu operating system must enforce a 60-day maximum password lifetime restriction.
Passwords for new users must have a 60-day maximum password lifetime restriction. 
New: The Ubuntu operating system must enforce a 60-day maximum password lifetime restriction. Passwords for new users must have a 60-day maximum password lifetime restriction.
---
SV-238204:
Old: Ubuntu operating systems when booted must require authentication upon booting into
single-user and maintenance modes. 
New: Ubuntu operating systems when booted must require authentication upon booting into single-user and maintenance modes.
---
SV-238205:
Old: The Ubuntu operating system must uniquely identify interactive users. 
New: The Ubuntu operating system must uniquely identify interactive users.
---
SV-238206:
Old: The Ubuntu operating system must ensure only users who need access to security functions are
part of sudo group. 
New: The Ubuntu operating system must ensure only users who need access to security functions are part of sudo group.
---
SV-238207:
Old: The Ubuntu operating system must automatically terminate a user session after inactivity
timeouts have expired. 
New: The Ubuntu operating system must automatically terminate a user session after inactivity timeouts have expired.
---
SV-238208:
Old: The Ubuntu operating system must require users to reauthenticate for privilege escalation
or when changing roles. 
New: The Ubuntu operating system must require users to reauthenticate for privilege escalation or when changing roles.
---
SV-238209:
Old: The Ubuntu operating system default filesystem permissions must be defined in such a way that
all authenticated users can read and modify only their own files. 
New: The Ubuntu operating system default filesystem permissions must be defined in such a way that all authenticated users can read and modify only their own files.
---
SV-238210:
Old: The Ubuntu operating system must implement smart card logins for multifactor
authentication for local and network access to privileged and non-privileged accounts. 
New: The Ubuntu operating system must implement smart card logins for multifactor authentication for local and network access to privileged and non-privileged accounts.
---
SV-238211:
Old: The Ubuntu operating system must use strong authenticators in establishing nonlocal
maintenance and diagnostic sessions. 
New: The Ubuntu operating system must use strong authenticators in establishing nonlocal maintenance and diagnostic sessions.
---
SV-238212:
Old: The Ubuntu operating system must immediately terminate all network connections associated
with SSH traffic after a period of inactivity. 
New: The Ubuntu operating system must immediately terminate all network connections associated with SSH traffic after a period of inactivity.
---
SV-238213:
Old: The Ubuntu operating system must immediately terminate all network connections associated
with SSH traffic at the end of the session or after 10 minutes of inactivity. 
New: The Ubuntu operating system must immediately terminate all network connections associated with SSH traffic at the end of the session or after 10 minutes of inactivity.
---
SV-238214:
Old: The Ubuntu operating system must display the Standard Mandatory DoD Notice and Consent
Banner before granting any local or remote connection to the system. 
New: The Ubuntu operating system must display the Standard Mandatory DoD Notice and Consent Banner before granting any local or remote connection to the system.
---
SV-238215:
Old: The Ubuntu operating system must use SSH to protect the confidentiality and integrity of
transmitted information. 
New: The Ubuntu operating system must use SSH to protect the confidentiality and integrity of transmitted information.
---
SV-238216:
Old: The Ubuntu operating system must configure the SSH daemon to use Message Authentication
Codes (MACs) employing FIPS 140-2 approved cryptographic hashes to prevent the
unauthorized disclosure of information and&#x2F;or detect changes to information during
transmission. 
New: The Ubuntu operating system must configure the SSH daemon to use Message Authentication Codes (MACs) employing FIPS 140-2 approved cryptographic hashes to prevent the unauthorized disclosure of information and&#x2F;or detect changes to information during transmission.
---
SV-238217:
Old: The Ubuntu operating system must configure the SSH daemon to use FIPS 140-2 approved ciphers
to prevent the unauthorized disclosure of information and&#x2F;or detect changes to information
during transmission. 
New: The Ubuntu operating system must configure the SSH daemon to use FIPS 140-2 approved ciphers to prevent the unauthorized disclosure of information and&#x2F;or detect changes to information during transmission.
---
SV-238218:
Old: The Ubuntu operating system must not allow unattended or automatic login via SSH. 
New: The Ubuntu operating system must not allow unattended or automatic login via SSH.
---
SV-238219:
Old: The Ubuntu operating system must be configured so that remote X connections are disabled,
unless to fulfill documented and validated mission requirements. 
New: The Ubuntu operating system must be configured so that remote X connections are disabled, unless to fulfill documented and validated mission requirements.
---
SV-238220:
Old: The Ubuntu operating system SSH daemon must prevent remote hosts from connecting to the proxy
display. 
New: The Ubuntu operating system SSH daemon must prevent remote hosts from connecting to the proxy display.
---
SV-238221:
Old: The Ubuntu operating system must enforce password complexity by requiring that at least one
upper-case character be used. 
New: The Ubuntu operating system must enforce password complexity by requiring that at least one upper-case character be used.
---
SV-238222:
Old: The Ubuntu operating system must enforce password complexity by requiring that at least one
lower-case character be used. 
New: The Ubuntu operating system must enforce password complexity by requiring that at least one lower-case character be used.
---
SV-238223:
Old: The Ubuntu operating system must enforce password complexity by requiring that at least one
numeric character be used. 
New: The Ubuntu operating system must enforce password complexity by requiring that at least one numeric character be used.
---
SV-238224:
Old: The Ubuntu operating system must require the change of at least 8 characters when passwords
are changed. 
New: The Ubuntu operating system must require the change of at least 8 characters when passwords are changed.
---
SV-238225:
Old: The Ubuntu operating system must enforce a minimum 15-character password length. 
New: The Ubuntu operating system must enforce a minimum 15-character password length.
---
SV-238226:
Old: The Ubuntu operating system must enforce password complexity by requiring that at least one
special character be used. 
New: The Ubuntu operating system must enforce password complexity by requiring that at least one special character be used.
---
SV-238227:
Old: The Ubuntu operating system must prevent the use of dictionary words for passwords. 
New: The Ubuntu operating system must prevent the use of dictionary words for passwords.
---
SV-238228:
Old: The Ubuntu operating system must be configured so that when passwords are changed or new
passwords are established, pwquality must be used. 
New: The Ubuntu operating system must be configured so that when passwords are changed or new passwords are established, pwquality must be used.
---
SV-238229:
Old: The Ubuntu operating system, for PKI-based authentication, must validate certificates by
constructing a certification path (which includes status information) to an accepted trust
anchor. 
New: The Ubuntu operating system, for PKI-based authentication, must validate certificates by constructing a certification path (which includes status information) to an accepted trust anchor.
---
SV-238230:
Old: The Ubuntu operating system must implement multifactor authentication for remote access to
privileged accounts in such a way that one of the factors is provided by a device separate from
the system gaining access. 
New: The Ubuntu operating system must implement multifactor authentication for remote access to privileged accounts in such a way that one of the factors is provided by a device separate from the system gaining access.
---
SV-238231:
Old: The Ubuntu operating system must accept Personal Identity Verification (PIV) credentials. 
New: The Ubuntu operating system must accept Personal Identity Verification (PIV) credentials.
---
SV-238232:
Old: The Ubuntu operating system must electronically verify Personal Identity Verification
(PIV) credentials. 
New: The Ubuntu operating system must electronically verify Personal Identity Verification (PIV) credentials.
---
SV-238233:
Old: The Ubuntu operating system for PKI-based authentication, must implement a local cache of
revocation data in case of the inability to access revocation information via the network. 
New: The Ubuntu operating system for PKI-based authentication, must implement a local cache of revocation data in case of the inability to access revocation information via the network.
---
SV-238234:
Old: The Ubuntu operating system must prohibit password reuse for a minimum of five generations. 
New: The Ubuntu operating system must prohibit password reuse for a minimum of five generations.
---
SV-238235:
Old: The Ubuntu operating system must automatically lock an account until the locked account is
released by an administrator when three unsuccessful logon attempts have been made. 
New: The Ubuntu operating system must automatically lock an account until the locked account is released by an administrator when three unsuccessful logon attempts have been made.
---
SV-238236:
Old: The Ubuntu operating system must be configured so that the script which runs each 30 days or
less to check file integrity is the default one. 
New: The Ubuntu operating system must be configured so that the script which runs each 30 days or less to check file integrity is the default one.
---
SV-238237:
Old: The Ubuntu operating system must enforce a delay of at least 4 seconds between logon prompts
following a failed logon attempt. 
New: The Ubuntu operating system must enforce a delay of at least 4 seconds between logon prompts following a failed logon attempt.
---
SV-238238:
Old: The Ubuntu operating system must generate audit records for all account creations,
modifications, disabling, and termination events that affect &#x2F;etc&#x2F;passwd. 
New: The Ubuntu operating system must generate audit records for all account creations, modifications, disabling, and termination events that affect &#x2F;etc&#x2F;passwd.
---
SV-238239:
Old: The Ubuntu operating system must generate audit records for all account creations,
modifications, disabling, and termination events that affect &#x2F;etc&#x2F;group. 
New: The Ubuntu operating system must generate audit records for all account creations, modifications, disabling, and termination events that affect &#x2F;etc&#x2F;group.
---
SV-238240:
Old: The Ubuntu operating system must generate audit records for all account creations,
modifications, disabling, and termination events that affect &#x2F;etc&#x2F;shadow. 
New: The Ubuntu operating system must generate audit records for all account creations, modifications, disabling, and termination events that affect &#x2F;etc&#x2F;shadow.
---
SV-238241:
Old: The Ubuntu operating system must generate audit records for all account creations,
modifications, disabling, and termination events that affect &#x2F;etc&#x2F;gshadow. 
New: The Ubuntu operating system must generate audit records for all account creations, modifications, disabling, and termination events that affect &#x2F;etc&#x2F;gshadow.
---
SV-238242:
Old: The Ubuntu operating system must generate audit records for all account creations,
modifications, disabling, and termination events that affect &#x2F;etc&#x2F;opasswd. 
New: The Ubuntu operating system must generate audit records for all account creations, modifications, disabling, and termination events that affect &#x2F;etc&#x2F;opasswd.
---
SV-238243:
Old: The Ubuntu operating system must alert the ISSO and SA (at a minimum) in the event of an audit
processing failure. 
New: The Ubuntu operating system must alert the ISSO and SA (at a minimum) in the event of an audit processing failure.
---
SV-238244:
Old: The Ubuntu operating system must shut down by default upon audit failure (unless
availability is an overriding concern). 
New: The Ubuntu operating system must shut down by default upon audit failure (unless availability is an overriding concern).
---
SV-238245:
Old: The Ubuntu operating system must be configured so that audit log files are not read or
write-accessible by unauthorized users. 
New: The Ubuntu operating system must be configured so that audit log files are not read or write-accessible by unauthorized users.
---
SV-238246:
Old: The Ubuntu operating system must be configured to permit only authorized users ownership of
the audit log files. 
New: The Ubuntu operating system must be configured to permit only authorized users ownership of the audit log files.
---
SV-238247:
Old: The Ubuntu operating system must permit only authorized groups ownership of the audit log
files. 
New: The Ubuntu operating system must permit only authorized groups ownership of the audit log files.
---
SV-238248:
Old: The Ubuntu operating system must be configured so that the audit log directory is not
write-accessible by unauthorized users. 
New: The Ubuntu operating system must be configured so that the audit log directory is not write-accessible by unauthorized users.
---
SV-238249:
Old: The Ubuntu operating system must be configured so that audit configuration files are not
write-accessible by unauthorized users. 
New: The Ubuntu operating system must be configured so that audit configuration files are not write-accessible by unauthorized users.
---
SV-238250:
Old: The Ubuntu operating system must permit only authorized accounts to own the audit
configuration files. 
New: The Ubuntu operating system must permit only authorized accounts to own the audit configuration files.
---
SV-238251:
Old: The Ubuntu operating system must permit only authorized groups to own the audit
configuration files. 
New: The Ubuntu operating system must permit only authorized groups to own the audit configuration files.
---
SV-238252:
Old: The Ubuntu operating system must generate audit records for successful&#x2F;unsuccessful uses
of the su command. 
New: The Ubuntu operating system must generate audit records for successful&#x2F;unsuccessful uses of the su command.
---
SV-238253:
Old: The Ubuntu operating system must generate audit records for successful&#x2F;unsuccessful uses
of the chfn command. 
New: The Ubuntu operating system must generate audit records for successful&#x2F;unsuccessful uses of the chfn command.
---
SV-238254:
Old: The Ubuntu operating system must generate audit records for successful&#x2F;unsuccessful uses
of the mount command. 
New: The Ubuntu operating system must generate audit records for successful&#x2F;unsuccessful uses of the mount command.
---
SV-238255:
Old: The Ubuntu operating system must generate audit records for successful&#x2F;unsuccessful uses
of the umount command. 
New: The Ubuntu operating system must generate audit records for successful&#x2F;unsuccessful uses of the umount command.
---
SV-238256:
Old: The Ubuntu operating system must generate audit records for successful&#x2F;unsuccessful uses
of the ssh-agent command. 
New: The Ubuntu operating system must generate audit records for successful&#x2F;unsuccessful uses of the ssh-agent command.
---
SV-238257:
Old: The Ubuntu operating system must generate audit records for successful&#x2F;unsuccessful uses
of the ssh-keysign command. 
New: The Ubuntu operating system must generate audit records for successful&#x2F;unsuccessful uses of the ssh-keysign command.
---
SV-238258:
Old: The Ubuntu operating system must generate audit records for any use of the setxattr,
fsetxattr, lsetxattr, removexattr, fremovexattr, and lremovexattr system calls. 
New: The Ubuntu operating system must generate audit records for any use of the setxattr, fsetxattr, lsetxattr, removexattr, fremovexattr, and lremovexattr system calls.
---
SV-238264:
Old: The Ubuntu operating system must generate audit records for successful&#x2F;unsuccessful uses
of the chown, fchown, fchownat, and lchown system calls. 
New: The Ubuntu operating system must generate audit records for successful&#x2F;unsuccessful uses of the chown, fchown, fchownat, and lchown system calls.
---
SV-238268:
Old: The Ubuntu operating system must generate audit records for successful&#x2F;unsuccessful uses
of the chmod, fchmod, and fchmodat system calls. 
New: The Ubuntu operating system must generate audit records for successful&#x2F;unsuccessful uses of the chmod, fchmod, and fchmodat system calls.
---
SV-238271:
Old: The Ubuntu operating system must generate audit records for successful&#x2F;unsuccessful uses
of the creat, open, openat, open_by_handle_at, truncate, and ftruncate system calls. 
New: The Ubuntu operating system must generate audit records for successful&#x2F;unsuccessful uses of the creat, open, openat, open_by_handle_at, truncate, and ftruncate system calls.
---
SV-238277:
Old: The Ubuntu operating system must generate audit records for successful&#x2F;unsuccessful uses
of the sudo command. 
New: The Ubuntu operating system must generate audit records for successful&#x2F;unsuccessful uses of the sudo command.
---
SV-238278:
Old: The Ubuntu operating system must generate audit records for successful&#x2F;unsuccessful uses
of the sudoedit command. 
New: The Ubuntu operating system must generate audit records for successful&#x2F;unsuccessful uses of the sudoedit command.
---
SV-238279:
Old: The Ubuntu operating system must generate audit records for successful&#x2F;unsuccessful uses
of the chsh command. 
New: The Ubuntu operating system must generate audit records for successful&#x2F;unsuccessful uses of the chsh command.
---
SV-238280:
Old: The Ubuntu operating system must generate audit records for successful&#x2F;unsuccessful uses
of the newgrp command. 
New: The Ubuntu operating system must generate audit records for successful&#x2F;unsuccessful uses of the newgrp command.
---
SV-238281:
Old: The Ubuntu operating system must generate audit records for successful&#x2F;unsuccessful uses
of the chcon command. 
New: The Ubuntu operating system must generate audit records for successful&#x2F;unsuccessful uses of the chcon command.
---
SV-238282:
Old: The Ubuntu operating system must generate audit records for successful&#x2F;unsuccessful uses
of the apparmor_parser command. 
New: The Ubuntu operating system must generate audit records for successful&#x2F;unsuccessful uses of the apparmor_parser command.
---
SV-238283:
Old: The Ubuntu operating system must generate audit records for successful&#x2F;unsuccessful uses
of the setfacl command. 
New: The Ubuntu operating system must generate audit records for successful&#x2F;unsuccessful uses of the setfacl command.
---
SV-238284:
Old: The Ubuntu operating system must generate audit records for successful&#x2F;unsuccessful uses
of the chacl command. 
New: The Ubuntu operating system must generate audit records for successful&#x2F;unsuccessful uses of the chacl command.
---
SV-238285:
Old: The Ubuntu operating system must generate audit records for the use and modification of the
tallylog file. 
New: The Ubuntu operating system must generate audit records for the use and modification of the tallylog file.
---
SV-238286:
Old: The Ubuntu operating system must generate audit records for the use and modification of
faillog file. 
New: The Ubuntu operating system must generate audit records for the use and modification of faillog file.
---
SV-238287:
Old: The Ubuntu operating system must generate audit records for the use and modification of the
lastlog file. 
New: The Ubuntu operating system must generate audit records for the use and modification of the lastlog file.
---
SV-238288:
Old: The Ubuntu operating system must generate audit records for successful&#x2F;unsuccessful uses
of the passwd command. 
New: The Ubuntu operating system must generate audit records for successful&#x2F;unsuccessful uses of the passwd command.
---
SV-238289:
Old: The Ubuntu operating system must generate audit records for successful&#x2F;unsuccessful uses
of the unix_update command. 
New: The Ubuntu operating system must generate audit records for successful&#x2F;unsuccessful uses of the unix_update command.
---
SV-238290:
Old: The Ubuntu operating system must generate audit records for successful&#x2F;unsuccessful uses
of the gpasswd command. 
New: The Ubuntu operating system must generate audit records for successful&#x2F;unsuccessful uses of the gpasswd command.
---
SV-238291:
Old: The Ubuntu operating system must generate audit records for successful&#x2F;unsuccessful uses
of the chage command. 
New: The Ubuntu operating system must generate audit records for successful&#x2F;unsuccessful uses of the chage command.
---
SV-238292:
Old: The Ubuntu operating system must generate audit records for successful&#x2F;unsuccessful uses
of the usermod command. 
New: The Ubuntu operating system must generate audit records for successful&#x2F;unsuccessful uses of the usermod command.
---
SV-238293:
Old: The Ubuntu operating system must generate audit records for successful&#x2F;unsuccessful uses
of the crontab command. 
New: The Ubuntu operating system must generate audit records for successful&#x2F;unsuccessful uses of the crontab command.
---
SV-238294:
Old: The Ubuntu operating system must generate audit records for successful&#x2F;unsuccessful uses
of the pam_timestamp_check command. 
New: The Ubuntu operating system must generate audit records for successful&#x2F;unsuccessful uses of the pam_timestamp_check command.
---
SV-238295:
Old: The Ubuntu operating system must generate audit records for successful&#x2F;unsuccessful uses
of the init_module and finit_module syscalls. 
New: The Ubuntu operating system must generate audit records for successful&#x2F;unsuccessful uses of the init_module and finit_module syscalls.
---
SV-238297:
Old: The Ubuntu operating system must generate audit records for successful&#x2F;unsuccessful uses
of the delete_module syscall. 
New: The Ubuntu operating system must generate audit records for successful&#x2F;unsuccessful uses of the delete_module syscall.
---
SV-238298:
Old: The Ubuntu operating system must produce audit records and reports containing information
to establish when, where, what type, the source, and the outcome for all DoD-defined
auditable events and actions in near real time. 
New: The Ubuntu operating system must produce audit records and reports containing information to establish when, where, what type, the source, and the outcome for all DoD-defined auditable events and actions in near real time.
---
SV-238299:
Old: The Ubuntu operating system must initiate session audits at system start-up. 
New: The Ubuntu operating system must initiate session audits at system start-up.
---
SV-238300:
Old: The Ubuntu operating system must configure audit tools with a mode of 0755 or less permissive. 
New: The Ubuntu operating system must configure audit tools with a mode of 0755 or less permissive.
---
SV-238301:
Old: The Ubuntu operating system must configure audit tools to be owned by root. 
New: The Ubuntu operating system must configure audit tools to be owned by root.
---
SV-238302:
Old: The Ubuntu operating system must configure the audit tools to be group-owned by root. 
New: The Ubuntu operating system must configure the audit tools to be group-owned by root.
---
SV-238303:
Old: The Ubuntu operating system must use cryptographic mechanisms to protect the integrity of
audit tools. 
New: The Ubuntu operating system must use cryptographic mechanisms to protect the integrity of audit tools.
---
SV-238304:
Old: The Ubuntu operating system must prevent all software from executing at higher privilege
levels than users executing the software and the audit system must be configured to audit the
execution of privileged functions. 
New: The Ubuntu operating system must prevent all software from executing at higher privilege levels than users executing the software and the audit system must be configured to audit the execution of privileged functions.
---
SV-238305:
Old: The Ubuntu operating system must allocate audit record storage capacity to store at least one
weeks&#39; worth of audit records, when audit records are not immediately sent to a central audit
record storage facility. 
New: The Ubuntu operating system must allocate audit record storage capacity to store at least one weeks&#39; worth of audit records, when audit records are not immediately sent to a central audit record storage facility.
---
SV-238306:
Old: The Ubuntu operating system audit event multiplexor must be configured to off-load audit
logs onto a different system or storage media from the system being audited. 
New: The Ubuntu operating system audit event multiplexor must be configured to off-load audit logs onto a different system or storage media from the system being audited.
---
SV-238307:
Old: The Ubuntu operating system must immediately notify the SA and ISSO (at a minimum) when
allocated audit record storage volume reaches 75% of the repository maximum audit record
storage capacity. 
New: The Ubuntu operating system must immediately notify the SA and ISSO (at a minimum) when allocated audit record storage volume reaches 75% of the repository maximum audit record storage capacity.
---
SV-238308:
Old: The Ubuntu operating system must record time stamps for audit records that can be mapped to
Coordinated Universal Time (UTC) or Greenwich Mean Time (GMT). 
New: The Ubuntu operating system must record time stamps for audit records that can be mapped to Coordinated Universal Time (UTC) or Greenwich Mean Time (GMT).
---
SV-238309:
Old: The Ubuntu operating system must generate audit records for privileged activities,
nonlocal maintenance, diagnostic sessions and other system-level access. 
New: The Ubuntu operating system must generate audit records for privileged activities, nonlocal maintenance, diagnostic sessions and other system-level access.
---
SV-238310:
Old: The Ubuntu operating system must generate audit records for any successful&#x2F;unsuccessful
use of unlink, unlinkat, rename, renameat, and rmdir system calls. 
New: The Ubuntu operating system must generate audit records for any successful&#x2F;unsuccessful use of unlink, unlinkat, rename, renameat, and rmdir system calls.
---
SV-238315:
Old: The Ubuntu operating system must generate audit records for the &#x2F;var&#x2F;log&#x2F;wtmp file. 
New: The Ubuntu operating system must generate audit records for the &#x2F;var&#x2F;log&#x2F;wtmp file.
---
SV-238316:
Old: The Ubuntu operating system must generate audit records for the &#x2F;var&#x2F;run&#x2F;wtmp file. 
New: The Ubuntu operating system must generate audit records for the &#x2F;var&#x2F;run&#x2F;utmp file.
---
SV-238317:
Old: The Ubuntu operating system must generate audit records for the &#x2F;var&#x2F;log&#x2F;btmp file. 
New: The Ubuntu operating system must generate audit records for the &#x2F;var&#x2F;log&#x2F;btmp file.
---
SV-238318:
Old: The Ubuntu operating system must generate audit records when successful&#x2F;unsuccessful
attempts to use modprobe command. 
New: The Ubuntu operating system must generate audit records when successful&#x2F;unsuccessful attempts to use modprobe command.
---
SV-238319:
Old: The Ubuntu operating system must generate audit records when successful&#x2F;unsuccessful
attempts to use the kmod command. 
New: The Ubuntu operating system must generate audit records when successful&#x2F;unsuccessful attempts to use the kmod command.
---
SV-238320:
Old: The Ubuntu operating system must generate audit records when successful&#x2F;unsuccessful
attempts to use the fdisk command. 
New: The Ubuntu operating system must generate audit records when successful&#x2F;unsuccessful attempts to use the fdisk command.
---
SV-238321:
Old: The Ubuntu operating system must have a crontab script running weekly to offload audit events
of standalone systems. 
New: The Ubuntu operating system must have a crontab script running weekly to offload audit events of standalone systems.
---
SV-238323:
Old: The Ubuntu operating system must limit the number of concurrent sessions to ten for all
accounts and&#x2F;or account types. 
New: The Ubuntu operating system must limit the number of concurrent sessions to ten for all accounts and&#x2F;or account types.
---
SV-238324:
Old: The Ubuntu operating system must monitor remote access methods. 
New: The Ubuntu operating system must monitor remote access methods.
---
SV-238325:
Old: The Ubuntu operating system must encrypt all stored passwords with a FIPS 140-2 approved
cryptographic hashing algorithm. 
New: The Ubuntu operating system must encrypt all stored passwords with a FIPS 140-2 approved cryptographic hashing algorithm.
---
SV-238326:
Old: The Ubuntu operating system must not have the telnet package installed. 
New: The Ubuntu operating system must not have the telnet package installed.
---
SV-238327:
Old: The Ubuntu operating system must not have the rsh-server package installed. 
New: The Ubuntu operating system must not have the rsh-server package installed.
---
SV-238328:
Old: The Ubuntu operating system must be configured to prohibit or restrict the use of functions,
ports, protocols, and&#x2F;or services, as defined in the PPSM CAL and vulnerability
assessments. 
New: The Ubuntu operating system must be configured to prohibit or restrict the use of functions, ports, protocols, and&#x2F;or services, as defined in the PPSM CAL and vulnerability assessments.
---
SV-238329:
Old: The Ubuntu operating system must prevent direct login into the root account. 
New: The Ubuntu operating system must prevent direct login into the root account.
---
SV-238330:
Old: The Ubuntu operating system must disable account identifiers (individuals, groups, roles,
and devices) after 35 days of inactivity. 
New: The Ubuntu operating system must disable account identifiers (individuals, groups, roles, and devices) after 35 days of inactivity.
---
SV-238331:
Old: The Ubuntu operating system must automatically remove or disable emergency accounts after
72 hours. 
New: The Ubuntu operating system must automatically expire temporary accounts within 72 hours.
---
SV-238332:
Old: The Ubuntu operating system must set a sticky bit  on all public directories to prevent
unauthorized and unintended information transferred via shared system resources. 
New: The Ubuntu operating system must set a sticky bit  on all public directories to prevent unauthorized and unintended information transferred via shared system resources.
---
SV-238333:
Old: The Ubuntu operating system must be configured to use TCP syncookies. 
New: The Ubuntu operating system must be configured to use TCP syncookies.
---
SV-238334:
Old: The Ubuntu operating system must disable kernel core dumps  so that it can fail to a secure state
if system initialization fails, shutdown fails or aborts fail. 
New: The Ubuntu operating system must disable kernel core dumps  so that it can fail to a secure state if system initialization fails, shutdown fails or aborts fail.
---
SV-238335:
Old: Ubuntu operating systems handling data requiring &quot;data at rest&quot; protections must employ
cryptographic mechanisms to prevent unauthorized disclosure and modification of the
information at rest. 
New: Ubuntu operating systems handling data requiring &quot;data at rest&quot; protections must employ cryptographic mechanisms to prevent unauthorized disclosure and modification of the information at rest.
---
SV-238336:
Old: The Ubuntu operating system must deploy Endpoint Security for Linux Threat Prevention
(ENSLTP). 
New: The Ubuntu operating system must deploy Endpoint Security for Linux Threat Prevention (ENSLTP).
---
SV-238337:
Old: The Ubuntu operating system must generate error messages that provide information
necessary for corrective actions without revealing information that could be exploited by
adversaries. 
New: The Ubuntu operating system must generate error messages that provide information necessary for corrective actions without revealing information that could be exploited by adversaries.
---
SV-238338:
Old: The Ubuntu operating system must configure the &#x2F;var&#x2F;log directory to be group-owned by
syslog. 
New: The Ubuntu operating system must configure the &#x2F;var&#x2F;log directory to be group-owned by syslog.
---
SV-238339:
Old: The Ubuntu operating system must configure the &#x2F;var&#x2F;log directory to be owned by root. 
New: The Ubuntu operating system must configure the &#x2F;var&#x2F;log directory to be owned by root.
---
SV-238340:
Old: The Ubuntu operating system must configure the &#x2F;var&#x2F;log directory to have mode 0750 or less
permissive. 
New: The Ubuntu operating system must configure the &#x2F;var&#x2F;log directory to have mode &quot;0755&quot; or less permissive.
---
SV-238341:
Old: The Ubuntu operating system must configure the &#x2F;var&#x2F;log&#x2F;syslog file to be group-owned by
adm. 
New: The Ubuntu operating system must configure the &#x2F;var&#x2F;log&#x2F;syslog file to be group-owned by adm.
---
SV-238342:
Old: The Ubuntu operating system must configure &#x2F;var&#x2F;log&#x2F;syslog file to be owned by syslog. 
New: The Ubuntu operating system must configure &#x2F;var&#x2F;log&#x2F;syslog file to be owned by syslog.
---
SV-238343:
Old: The Ubuntu operating system must configure &#x2F;var&#x2F;log&#x2F;syslog file with mode 0640 or less
permissive. 
New: The Ubuntu operating system must configure &#x2F;var&#x2F;log&#x2F;syslog file with mode 0640 or less permissive.
---
SV-238344:
Old: The Ubuntu operating system must have directories that contain system commands set to a mode
of 0755 or less permissive. 
New: The Ubuntu operating system must have directories that contain system commands set to a mode of 0755 or less permissive.
---
SV-238345:
Old: The Ubuntu operating system must have directories that contain system commands owned by
root. 
New: The Ubuntu operating system must have directories that contain system commands owned by root.
---
SV-238346:
Old: The Ubuntu operating system must have directories that contain system commands group-owned
by root. 
New: The Ubuntu operating system must have directories that contain system commands group-owned by root.
---
SV-238347:
Old: The Ubuntu operating system library files must have mode 0755 or less permissive. 
New: The Ubuntu operating system library files must have mode 0755 or less permissive.
---
SV-238348:
Old: The Ubuntu operating system library directories must have mode 0755 or less permissive. 
New: The Ubuntu operating system library directories must have mode 0755 or less permissive.
---
SV-238349:
Old: The Ubuntu operating system library files must be owned by root. 
New: The Ubuntu operating system library files must be owned by root.
---
SV-238350:
Old: The Ubuntu operating system library directories must be owned by root. 
New: The Ubuntu operating system library directories must be owned by root.
---
SV-238351:
Old: The Ubuntu operating system library files must be group-owned by root or a system account. 
New: The Ubuntu operating system library files must be group-owned by root or a system account.
---
SV-238352:
Old: The Ubuntu operating system library directories must be group-owned by root. 
New: The Ubuntu operating system library directories must be group-owned by root.
---
SV-238353:
Old: The Ubuntu operating system must be configured to preserve log records from failure events. 
New: The Ubuntu operating system must be configured to preserve log records from failure events.
---
SV-238354:
Old: The Ubuntu operating system must have an application firewall installed in order to control
remote access methods. 
New: The Ubuntu operating system must have an application firewall installed in order to control remote access methods.
---
SV-238355:
Old: The Ubuntu operating system must enable and run the uncomplicated firewall(ufw). 
New: The Ubuntu operating system must enable and run the uncomplicated firewall(ufw).
---
SV-238356:
Old: The Ubuntu operating system must, for networked systems, compare internal information
system clocks at least every 24 hours with a server which is synchronized to one of the
redundant United States Naval Observatory (USNO) time servers, or a time server designated
for the appropriate DoD network (NIPRNet&#x2F;SIPRNet), and&#x2F;or the Global Positioning System
(GPS). 
New: The Ubuntu operating system must, for networked systems, compare internal information system clocks at least every 24 hours with a server which is synchronized to one of the redundant United States Naval Observatory (USNO) time servers, or a time server designated for the appropriate DoD network (NIPRNet&#x2F;SIPRNet), and&#x2F;or the Global Positioning System (GPS).
---
SV-238357:
Old: The Ubuntu operating system must synchronize internal information system clocks to the
authoritative time source when the time difference is greater than one second. 
New: The Ubuntu operating system must synchronize internal information system clocks to the authoritative time source when the time difference is greater than one second.
---
SV-238358:
Old: The Ubuntu operating system must notify designated personnel if baseline configurations
are changed in an unauthorized manner. The file integrity tool must notify the System
Administrator when changes to the baseline configuration or anomalies in the oper 
New: The Ubuntu operating system must notify designated personnel if baseline configurations are changed in an unauthorized manner. The file integrity tool must notify the system administrator (SA) when changes to the baseline configuration or anomalies in the operation of any security functions are discovered.
---
SV-238359:
Old: The Ubuntu operating system&#39;s Advance Package Tool (APT) must be configured to prevent the
installation of patches, service packs, device drivers, or Ubuntu operating system
components without verification they have been digitally signed using a certificate that is
recognized and approved by the organization. 
New: The Ubuntu operating system&#39;s Advance Package Tool (APT) must be configured to prevent the installation of patches, service packs, device drivers, or Ubuntu operating system components without verification they have been digitally signed using a certificate that is recognized and approved by the organization.
---
SV-238360:
Old: The Ubuntu operating system must be configured to use AppArmor. 
New: The Ubuntu operating system must be configured to use AppArmor.
---
SV-238361:
Old: The Ubuntu operating system must allow the use of a temporary password for system logons with
an immediate change to a permanent password. 
New: The Ubuntu operating system must allow the use of a temporary password for system logons with an immediate change to a permanent password.
---
SV-238362:
Old: The Ubuntu operating system must be configured such that Pluggable Authentication Module
(PAM) prohibits the use of cached authentications after one day. 
New: The Ubuntu operating system must be configured such that Pluggable Authentication Module (PAM) prohibits the use of cached authentications after one day.
---
SV-238363:
Old: The Ubuntu operating system must implement NIST FIPS-validated cryptography  to protect
classified information and for the following: to provision digital signatures, to generate
cryptographic hashes, and to protect unclassified information requiring confidentiality
and cryptographic protection in accordance with applicable federal laws, Executive
Orders, directives, policies, regulations, and standards. 
New: The Ubuntu operating system must implement NIST FIPS-validated cryptography to protect classified information and for the following: To provision digital signatures, to generate cryptographic hashes, and to protect unclassified information requiring confidentiality and cryptographic protection in accordance with applicable federal laws, Executive Orders, directives, policies, regulations, and standards.
---
SV-238364:
Old: The Ubuntu operating system must only allow the use of DoD PKI-established certificate
authorities for verification of the establishment of protected sessions. 
New: The Ubuntu operating system must use DoD PKI-established certificate authorities for verification of the establishment of protected sessions.
---
SV-238365:
Old: Ubuntu operating system must implement cryptographic mechanisms to prevent unauthorized
modification of all information at rest. 
New: Ubuntu operating system must implement cryptographic mechanisms to prevent unauthorized modification of all information at rest.
---
SV-238366:
Old: Ubuntu operating system must implement cryptographic mechanisms to prevent unauthorized
disclosure of all information at rest. 
New: Ubuntu operating system must implement cryptographic mechanisms to prevent unauthorized disclosure of all information at rest.
---
SV-238367:
Old: The Ubuntu operating system must configure the uncomplicated firewall to rate-limit
impacted network interfaces. 
New: The Ubuntu operating system must configure the uncomplicated firewall to rate-limit impacted network interfaces.
---
SV-238368:
Old: The Ubuntu operating system must implement non-executable data to protect its memory from
unauthorized code execution. 
New: The Ubuntu operating system must implement nonexecutable data to protect its memory from unauthorized code execution.
---
SV-238369:
Old: The Ubuntu operating system must implement address space layout randomization to protect
its memory from unauthorized code execution. 
New: The Ubuntu operating system must implement address space layout randomization to protect its memory from unauthorized code execution.
---
SV-238370:
Old: The Ubuntu operating system must be configured so that Advance Package Tool (APT) removes all
software components after updated versions have been installed. 
New: The Ubuntu operating system must be configured so that Advance Package Tool (APT) removes all software components after updated versions have been installed.
---
SV-238371:
Old: The Ubuntu operating system must use a file integrity tool to verify correct operation of all
security functions. 
New: The Ubuntu operating system must use a file integrity tool to verify correct operation of all security functions.
---
SV-238372:
Old: The Ubuntu operating system must notify designated personnel if baseline configurations
are changed in an unauthorized manner. The file integrity tool must notify the System
Administrator when changes to the baseline configuration or anomalies in the operation of
any security functions are discovered. 
New: The Ubuntu operating system must notify designated personnel if baseline configurations are changed in an unauthorized manner. The file integrity tool must notify the System Administrator when changes to the baseline configuration or anomalies in the operation of any security functions are discovered.
---
SV-238373:
Old: The Ubuntu operating system must display the date and time of the last successful account
logon upon logon. 
New: The Ubuntu operating system must display the date and time of the last successful account logon upon logon.
---
SV-238374:
Old: The Ubuntu operating system must have an application firewall enabled. 
New: The Ubuntu operating system must have an application firewall enabled.
---
SV-238376:
Old: The Ubuntu operating system must have system commands set to a mode of 0755 or less permissive. 
New: The Ubuntu operating system must have system commands set to a mode of 0755 or less permissive.
---
SV-238377:
Old: The Ubuntu operating system must have system commands owned by root or a system account. 
New: The Ubuntu operating system must have system commands owned by root or a system account.
---
SV-238378:
Old: The Ubuntu operating system must have system commands group-owned by root or a system
account. 
New: The Ubuntu operating system must have system commands group-owned by root or a system account.
---
SV-238379:
Old: The Ubuntu operating system must disable the x86 Ctrl-Alt-Delete key sequence if a graphical
user interface is installed. 
New: The Ubuntu operating system must disable the x86 Ctrl-Alt-Delete key sequence if a graphical user interface is installed.
---
SV-238380:
Old: The Ubuntu operating system must disable the x86 Ctrl-Alt-Delete key sequence. 
New: The Ubuntu operating system must disable the x86 Ctrl-Alt-Delete key sequence.
---
SV-251503:
Old: The Ubuntu operating system must not have accounts configured with blank or null passwords. 
New: The Ubuntu operating system must not have accounts configured with blank or null passwords.
---
SV-251504:
Old: The Ubuntu operating system must not allow accounts configured with blank or null passwords. 
New: The Ubuntu operating system must not allow accounts configured with blank or null passwords.
---
SV-251505:
Old: The Ubuntu operating system must disable automatic mounting of Universal Serial Bus (USB)
mass storage driver. 
New: The Ubuntu operating system must disable automatic mounting of Universal Serial Bus (USB) mass storage driver.
---
SV-252704:
Old: The Ubuntu operating system must disable all wireless network adapters. 
New: The Ubuntu operating system must disable all wireless network adapters.
---
</details>

### Updated Descriptions
<details>
  <summary>Click to expand.</summary>
SV-238196:
Old:
```
If temporary user accounts remain active when no longer needed or for an excessive period,
these accounts may be used to gain unauthorized access. To mitigate this risk, automated
termination of all temporary accounts must be set upon account creation.

Temporary
accounts are established as part of normal account activation procedures when there is a need
for short-term accounts without the demand for immediacy in account activation.

If
temporary accounts are used, the operating system must be configured to automatically
terminate these types of accounts after a DoD-defined time period of 72 hours.

To address
access requirements, many operating systems may be integrated with enterprise-level
authentication/access mechanisms that meet or exceed access control policy requirements.

```
New:
```
If temporary user accounts remain active when no longer needed or for an excessive period, these accounts may be used to gain unauthorized access. To mitigate this risk, automated termination of all temporary accounts must be set upon account creation. 
 
Temporary accounts are established as part of normal account activation procedures when there is a need for short-term accounts without the demand for immediacy in account activation. 
 
If temporary accounts are used, the operating system must be configured to automatically terminate these types of accounts after a DoD-defined time period of 72 hours. 
 
To address access requirements, many operating systems may be integrated with enterprise-level authentication/access mechanisms that meet or exceed access control policy requirements.

```
---
SV-238197:
Old:
```
Display of a standardized and approved use notification before granting access to the Ubuntu
operating system ensures privacy and security notification verbiage used is consistent
with applicable federal laws, Executive Orders, directives, policies, regulations,
standards, and guidance.

System use notifications are required only for access via logon
interfaces with human users and are not required when such human interfaces do not exist.


The banner must be formatted in accordance with applicable DoD policy. Use the following
verbiage for operating systems that can accommodate banners of 1300 characters:

"You are
accessing a U.S. Government (USG) Information System (IS) that is provided for
USG-authorized use only.

By using this IS (which includes any device attached to this IS),
you consent to the following conditions:

-The USG routinely intercepts and monitors
communications on this IS for purposes including, but not limited to, penetration testing,
COMSEC monitoring, network operations and defense, personnel misconduct (PM), law
enforcement (LE), and counterintelligence (CI) investigations.

-At any time, the USG may
inspect and seize data stored on this IS.

-Communications using, or data stored on, this IS
are not private, are subject to routine monitoring, interception, and search, and may be
disclosed or used for any USG-authorized purpose.

-This IS includes security measures
(e.g., authentication and access controls) to protect USG interests--not for your personal
benefit or privacy.

-Notwithstanding the above, using this IS does not constitute consent
to PM, LE or CI investigative searching or monitoring of the content of privileged
communications, or work product, related to personal representation or services by
attorneys, psychotherapists, or clergy, and their assistants. Such communications and
work product are private and confidential. See User Agreement for details."

Use the
following verbiage for operating systems that have severe limitations on the number of
characters that can be displayed in the banner:

"I've read & consent to terms in IS user
agreem't."

```
New:
```
Display of a standardized and approved use notification before granting access to the Ubuntu operating system ensures privacy and security notification verbiage used is consistent with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance. 
 
System use notifications are required only for access via logon interfaces with human users and are not required when such human interfaces do not exist. 
 
The banner must be formatted in accordance with applicable DoD policy. Use the following verbiage for operating systems that can accommodate banners of 1300 characters: 
 
"You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only. 
 
By using this IS (which includes any device attached to this IS), you consent to the following conditions: 
 
-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations. 
 
-At any time, the USG may inspect and seize data stored on this IS. 
 
-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose. 
 
-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy. 
 
-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details." 
 
Use the following verbiage for operating systems that have severe limitations on the number of characters that can be displayed in the banner: 
 
"I've read & consent to terms in IS user agreem't."

```
---
SV-238198:
Old:
```
Display of a standardized and approved use notification before granting access to the Ubuntu
operating system ensures privacy and security notification verbiage used is consistent
with applicable federal laws, Executive Orders, directives, policies, regulations,
standards, and guidance.

System use notifications are required only for access via logon
interfaces with human users and are not required when such human interfaces do not exist.


The banner must be formatted in accordance with applicable DoD policy. Use the following
verbiage for operating systems that can accommodate banners of 1300 characters:

"You are
accessing a U.S. Government (USG) Information System (IS) that is provided for
USG-authorized use only.

By using this IS (which includes any device attached to this IS),
you consent to the following conditions:

-The USG routinely intercepts and monitors
communications on this IS for purposes including, but not limited to, penetration testing,
COMSEC monitoring, network operations and defense, personnel misconduct (PM), law
enforcement (LE), and counterintelligence (CI) investigations.

-At any time, the USG may
inspect and seize data stored on this IS.

-Communications using, or data stored on, this IS
are not private, are subject to routine monitoring, interception, and search, and may be
disclosed or used for any USG-authorized purpose.

-This IS includes security measures
(e.g., authentication and access controls) to protect USG interests--not for your personal
benefit or privacy.

-Notwithstanding the above, using this IS does not constitute consent
to PM, LE or CI investigative searching or monitoring of the content of privileged
communications, or work product, related to personal representation or services by
attorneys, psychotherapists, or clergy, and their assistants. Such communications and
work product are private and confidential. See User Agreement for details."

Use the
following verbiage for operating systems that have severe limitations on the number of
characters that can be displayed in the banner:

"I've read & consent to terms in IS user
agreem't."

```
New:
```
Display of a standardized and approved use notification before granting access to the Ubuntu operating system ensures privacy and security notification verbiage used is consistent with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance. 
 
System use notifications are required only for access via logon interfaces with human users and are not required when such human interfaces do not exist. 
 
The banner must be formatted in accordance with applicable DoD policy. Use the following verbiage for operating systems that can accommodate banners of 1300 characters: 
 
"You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only. 
 
By using this IS (which includes any device attached to this IS), you consent to the following conditions: 
 
-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations. 
 
-At any time, the USG may inspect and seize data stored on this IS. 
 
-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose. 
 
-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy. 
 
-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details." 
 
Use the following verbiage for operating systems that have severe limitations on the number of characters that can be displayed in the banner: 
 
"I've read & consent to terms in IS user agreem't."

```
---
SV-238199:
Old:
```
A session lock is a temporary action taken when a user stops work and moves away from the
immediate physical vicinity of the information system but does not want to log out because of
the temporary nature of the absence.

The session lock is implemented at the point where
session activity can be determined.

Regardless of where the session lock is determined and
implemented, once invoked, a session lock of the Ubuntu operating system must remain in place
until the user reauthenticates. No other activity aside from reauthentication must unlock
the system.

```
New:
```
A session lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system but does not want to log out because of the temporary nature of the absence. 
 
The session lock is implemented at the point where session activity can be determined. 
 
Regardless of where the session lock is determined and implemented, once invoked, a session lock of the Ubuntu operating system must remain in place until the user reauthenticates. No other activity aside from reauthentication must unlock the system.



```
---
SV-238200:
Old:
```
A session lock is a temporary action taken when a user stops work and moves away from the
immediate physical vicinity of the information system but does not want to log out because of
the temporary nature of the absence.

The session lock is implemented at the point where
session activity can be determined. Rather than be forced to wait for a period of time to expire
before the user session can be locked, the Ubuntu operating systems need to provide users with
the ability to manually invoke a session lock so users may secure their session if they need to
temporarily vacate the immediate physical vicinity.

```
New:
```
A session lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system but does not want to log out because of the temporary nature of the absence. 
 
The session lock is implemented at the point where session activity can be determined. Rather than be forced to wait for a period of time to expire before the user session can be locked, the Ubuntu operating systems need to provide users with the ability to manually invoke a session lock so users may secure their session if they need to temporarily vacate the immediate physical vicinity.



```
---
SV-238201:
Old:
```
Without mapping the certificate used to authenticate to the user account, the ability to
determine the identity of the individual user or group will not be available for forensic
analysis.

```
New:
```
Without mapping the certificate used to authenticate to the user account, the ability to determine the identity of the individual user or group will not be available for forensic analysis.

```
---
SV-238202:
Old:
```
Enforcing a minimum password lifetime helps to prevent repeated password changes to defeat
the password reuse or history enforcement requirement. If users are allowed to immediately
and continually change their password, then the password could be repeatedly changed in a
short period of time to defeat the organization's policy regarding password reuse.

```
New:
```
Enforcing a minimum password lifetime helps to prevent repeated password changes to defeat the password reuse or history enforcement requirement. If users are allowed to immediately and continually change their password, then the password could be repeatedly changed in a short period of time to defeat the organization's policy regarding password reuse.

```
---
SV-238203:
Old:
```
Any password, no matter how complex, can eventually be cracked. Therefore, passwords need to
be changed periodically. If the operating system does not limit the lifetime of passwords and
force users to change their passwords, there is the risk that the operating system passwords
could be compromised.

```
New:
```
Any password, no matter how complex, can eventually be cracked. Therefore, passwords need to be changed periodically. If the operating system does not limit the lifetime of passwords and force users to change their passwords, there is the risk that the operating system passwords could be compromised.

```
---
SV-238204:
Old:
```
To mitigate the risk of unauthorized access to sensitive information by entities that have
been issued certificates by DoD-approved PKIs, all DoD systems (e.g., web servers and web
portals) must be properly configured to incorporate access control methods that do not rely
solely on the possession of a certificate for access.

Successful authentication must not
automatically give an entity access to an asset or security boundary. Authorization
procedures and controls must be implemented to ensure each authenticated entity also has a
validated and current authorization. Authorization is the process of determining whether
an entity, once authenticated, is permitted to access a specific asset. Information systems
use access control policies and enforcement mechanisms to implement this requirement.


Access control policies include identity-based policies, role-based policies, and
attribute-based policies. Access enforcement mechanisms include access control lists,
access control matrices, and cryptography. These policies and mechanisms must be employed
by the application to control access between users (or processes acting on behalf of users)
and objects (e.g., devices, files, records, processes, programs, and domains) in the
information system.

```
New:
```
To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., web servers and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access.  
 
Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement. 
 
Access control policies include identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include access control lists, access control matrices, and cryptography. These policies and mechanisms must be employed by the application to control access between users (or processes acting on behalf of users) and objects (e.g., devices, files, records, processes, programs, and domains) in the information system.

```
---
SV-238205:
Old:
```
To assure accountability and prevent unauthenticated access, organizational users must be
identified and authenticated to prevent potential misuse and compromise of the system.


Organizational users include organizational employees or individuals the organization
deems to have equivalent status of employees (e.g., contractors). Organizational users
(and processes acting on behalf of users) must be uniquely identified and authenticated to
all accesses, except for the following:

1) Accesses explicitly identified and documented
by the organization. Organizations document specific user actions that can be performed on
the information system without identification or authentication; and

2) Accesses that
occur through authorized use of group authenticators without individual authentication.
Organizations may require unique identification of individuals in group accounts (e.g.,
shared privilege accounts) or for detailed accountability of individual activity.

```
New:
```
To assure accountability and prevent unauthenticated access, organizational users must be identified and authenticated to prevent potential misuse and compromise of the system. 
 
Organizational users include organizational employees or individuals the organization deems to have equivalent status of employees (e.g., contractors). Organizational users (and processes acting on behalf of users) must be uniquely identified and authenticated to all accesses, except for the following:  
 
1) Accesses explicitly identified and documented by the organization. Organizations document specific user actions that can be performed on the information system without identification or authentication; and 
 
2) Accesses that occur through authorized use of group authenticators without individual authentication. Organizations may require unique identification of individuals in group accounts (e.g., shared privilege accounts) or for detailed accountability of individual activity.



```
---
SV-238206:
Old:
```
An isolation boundary provides access control and protects the integrity of the hardware,
software, and firmware that perform security functions.

Security functions are the
hardware, software, and/or firmware of the information system responsible for enforcing
the system security policy and supporting the isolation of code and data on which the
protection is based. Operating systems implement code separation (i.e., separation of
security functions from nonsecurity functions) in a number of ways, including through the
provision of security kernels via processor rings or processor modes. For non-kernel code,
security function isolation is often achieved through file system protections that serve to
protect the code on disk and address space protections that protect executing code.


Developers and implementers can increase the assurance in security functions by employing
well-defined security policy models; structured, disciplined, and rigorous hardware and
software development techniques; and sound system/security engineering principles.
Implementation may include isolation of memory space and libraries.

The Ubuntu operating
system restricts access to security functions through the use of access control mechanisms
and by implementing least privilege capabilities.

```
New:
```
An isolation boundary provides access control and protects the integrity of the hardware, software, and firmware that perform security functions. 
 
Security functions are the hardware, software, and/or firmware of the information system responsible for enforcing the system security policy and supporting the isolation of code and data on which the protection is based. Operating systems implement code separation (i.e., separation of security functions from nonsecurity functions) in a number of ways, including through the provision of security kernels via processor rings or processor modes. For non-kernel code, security function isolation is often achieved through file system protections that serve to protect the code on disk and address space protections that protect executing code. 
 
Developers and implementers can increase the assurance in security functions by employing well-defined security policy models; structured, disciplined, and rigorous hardware and software development techniques; and sound system/security engineering principles. Implementation may include isolation of memory space and libraries.  
 
The Ubuntu operating system restricts access to security functions through the use of access control mechanisms and by implementing least privilege capabilities.

```
---
SV-238207:
Old:
```
Automatic session termination addresses the termination of user-initiated logical
sessions in contrast to the termination of network connections that are associated with
communications sessions (i.e., network disconnect). A logical session (for local,
network, and remote access) is initiated whenever a user (or process acting on behalf of a
user) accesses an organizational information system. Such user sessions can be terminated
(and thus terminate user access) without terminating network sessions.

Session
termination terminates all processes associated with a user's logical session except those
processes that are specifically created by the user (i.e., session owner) to continue after
the session is terminated.

Conditions or trigger events requiring automatic session
termination can include, for example, organization-defined periods of user inactivity,
targeted responses to certain types of incidents, and time-of-day restrictions on
information system use.

This capability is typically reserved for specific operating
system functionality where the system owner, data owner, or organization requires
additional assurance.

```
New:
```
Automatic session termination addresses the termination of user-initiated logical sessions in contrast to the termination of network connections that are associated with communications sessions (i.e., network disconnect). A logical session (for local, network, and remote access) is initiated whenever a user (or process acting on behalf of a user) accesses an organizational information system. Such user sessions can be terminated (and thus terminate user access) without terminating network sessions. 
 
Session termination terminates all processes associated with a user's logical session except those processes that are specifically created by the user (i.e., session owner) to continue after the session is terminated. 
 
Conditions or trigger events requiring automatic session termination can include, for example, organization-defined periods of user inactivity, targeted responses to certain types of incidents, and time-of-day restrictions on information system use. 
 
This capability is typically reserved for specific operating system functionality where the system owner, data owner, or organization requires additional assurance.

```
---
SV-238208:
Old:
```
Without reauthentication, users may access resources or perform tasks for which they do not
have authorization.

When operating systems provide the capability to escalate a
functional capability, it is critical the user reauthenticate.

```
New:
```
Without reauthentication, users may access resources or perform tasks for which they do not have authorization.  
 
When operating systems provide the capability to escalate a functional capability, it is critical the user reauthenticate.



```
---
SV-238209:
Old:
```
Setting the most restrictive default permissions ensures that when new accounts are created
they do not have unnecessary access.

```
New:
```
Setting the most restrictive default permissions ensures that when new accounts are created they do not have unnecessary access.

```
---
SV-238210:
Old:
```
Without the use of multifactor authentication, the ease of access to privileged functions is
greatly increased.

Multifactor authentication requires using two or more factors to
achieve authentication.

Factors include:
1) something a user knows (e.g.,
password/PIN);
2) something a user has (e.g., cryptographic identification device,
token); and
3) something a user is (e.g., biometric).

A privileged account is defined as an
information system account with authorizations of a privileged user.

Network access is
defined as access to an information system by a user (or a process acting on behalf of a user)
communicating through a network (e.g., local area network, wide area network, or the
internet).

The DoD CAC with DoD-approved PKI is an example of multifactor
authentication.

```
New:
```
Without the use of multifactor authentication, the ease of access to privileged functions is greatly increased. 
 
Multifactor authentication requires using two or more factors to achieve authentication. 
 
Factors include:  
1) something a user knows (e.g., password/PIN); 
2) something a user has (e.g., cryptographic identification device, token); and 
3) something a user is (e.g., biometric). 
 
A privileged account is defined as an information system account with authorizations of a privileged user. 
 
Network access is defined as access to an information system by a user (or a process acting on behalf of a user) communicating through a network (e.g., local area network, wide area network, or the internet). 
 
The DoD CAC with DoD-approved PKI is an example of multifactor authentication.



```
---
SV-238211:
Old:
```
Nonlocal maintenance and diagnostic activities are those activities conducted by
individuals communicating through a network, either an external network (e.g., the
internet) or an internal network. Local maintenance and diagnostic activities are those
activities carried out by individuals physically present at the information system or
information system component and not communicating across a network connection.
Typically, strong authentication requires authenticators that are resistant to replay
attacks and employ multifactor authentication. Strong authenticators include, for
example, PKI where certificates are stored on a token protected by a password, passphrase, or
biometric.

```
New:
```
Nonlocal maintenance and diagnostic activities are those activities conducted by individuals communicating through a network, either an external network (e.g., the internet) or an internal network. Local maintenance and diagnostic activities are those activities carried out by individuals physically present at the information system or information system component and not communicating across a network connection. Typically, strong authentication requires authenticators that are resistant to replay attacks and employ multifactor authentication. Strong authenticators include, for example, PKI where certificates are stored on a token protected by a password, passphrase, or biometric.

```
---
SV-238212:
Old:
```
Automatic session termination addresses the termination of user-initiated logical
sessions in contrast to the termination of network connections that are associated with
communications sessions (i.e., network disconnect). A logical session (for local,
network, and remote access) is initiated whenever a user (or process acting on behalf of a
user) accesses an organizational information system. Such user sessions can be terminated
(and thus terminate user access) without terminating network sessions.

Session
termination terminates all processes associated with a user's logical session except those
processes that are specifically created by the user (i.e., session owner) to continue after
the session is terminated.

Conditions or trigger events requiring automatic session
termination can include, for example, organization-defined periods of user inactivity,
targeted responses to certain types of incidents, and time-of-day restrictions on
information system use.

This capability is typically reserved for specific Ubuntu
operating system functionality where the system owner, data owner, or organization
requires additional assurance.

```
New:
```
Automatic session termination addresses the termination of user-initiated logical sessions in contrast to the termination of network connections that are associated with communications sessions (i.e., network disconnect). A logical session (for local, network, and remote access) is initiated whenever a user (or process acting on behalf of a user) accesses an organizational information system. Such user sessions can be terminated (and thus terminate user access) without terminating network sessions. 
 
Session termination terminates all processes associated with a user's logical session except those processes that are specifically created by the user (i.e., session owner) to continue after the session is terminated. 
 
Conditions or trigger events requiring automatic session termination can include, for example, organization-defined periods of user inactivity, targeted responses to certain types of incidents, and time-of-day restrictions on information system use. 
 
This capability is typically reserved for specific Ubuntu operating system functionality where the system owner, data owner, or organization requires additional assurance.

```
---
SV-238213:
Old:
```
Terminating an idle session within a short time period reduces the window of opportunity for
unauthorized personnel to take control of a management session enabled on the console or
console port that has been left unattended. In addition, quickly terminating an idle session
will also free up resources committed by the managed network element.

Terminating network
connections associated with communications sessions includes, for example,
de-allocating associated TCP/IP address/port pairs at the operating system level, and
de-allocating networking assignments at the application level if multiple application
sessions are using a single operating system-level network connection. This does not mean
that the operating system terminates all sessions or network access; it only ends the
inactive session and releases the resources associated with that session.

```
New:
```
Terminating an idle session within a short time period reduces the window of opportunity for unauthorized personnel to take control of a management session enabled on the console or console port that has been left unattended. In addition, quickly terminating an idle session will also free up resources committed by the managed network element.  
 
Terminating network connections associated with communications sessions includes, for example, de-allocating associated TCP/IP address/port pairs at the operating system level, and de-allocating networking assignments at the application level if multiple application sessions are using a single operating system-level network connection. This does not mean that the operating system terminates all sessions or network access; it only ends the inactive session and releases the resources associated with that session.

```
---
SV-238214:
Old:
```
Display of a standardized and approved use notification before granting access to the
publicly accessible operating system ensures privacy and security notification verbiage
used is consistent with applicable federal laws, Executive Orders, directives, policies,
regulations, standards, and guidance.

System use notifications are required only for
access via logon interfaces with human users and are not required when such human interfaces
do not exist.

The banner must be formatted in accordance with applicable DoD policy. Use the
following verbiage for operating systems that can accommodate banners of 1300 characters:


"You are accessing a U.S. Government (USG) Information System (IS) that is provided for
USG-authorized use only.

By using this IS (which includes any device attached to this IS),
you consent to the following conditions:

-The USG routinely intercepts and monitors
communications on this IS for purposes including, but not limited to, penetration testing,
COMSEC monitoring, network operations and defense, personnel misconduct (PM), law
enforcement (LE), and counterintelligence (CI) investigations.

-At any time, the USG may
inspect and seize data stored on this IS.

-Communications using, or data stored on, this IS
are not private, are subject to routine monitoring, interception, and search, and may be
disclosed or used for any USG-authorized purpose.

-This IS includes security measures
(e.g., authentication and access controls) to protect USG interests--not for your personal
benefit or privacy.

-Notwithstanding the above, using this IS does not constitute consent
to PM, LE or CI investigative searching or monitoring of the content of privileged
communications, or work product, related to personal representation or services by
attorneys, psychotherapists, or clergy, and their assistants. Such communications and
work product are private and confidential. See User Agreement for details."

Use the
following verbiage for operating systems that have severe limitations on the number of
characters that can be displayed in the banner:

"I've read & consent to terms in IS user
agreem't."

```
New:
```
Display of a standardized and approved use notification before granting access to the publicly accessible operating system ensures privacy and security notification verbiage used is consistent with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance. 
 
System use notifications are required only for access via logon interfaces with human users and are not required when such human interfaces do not exist. 
 
The banner must be formatted in accordance with applicable DoD policy. Use the following verbiage for operating systems that can accommodate banners of 1300 characters: 
 
"You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only. 
 
By using this IS (which includes any device attached to this IS), you consent to the following conditions: 
 
-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations. 
 
-At any time, the USG may inspect and seize data stored on this IS. 
 
-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose. 
 
-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy. 
 
-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details." 
 
Use the following verbiage for operating systems that have severe limitations on the number of characters that can be displayed in the banner: 
 
"I've read & consent to terms in IS user agreem't."



```
---
SV-238215:
Old:
```
Without protection of the transmitted information, confidentiality and integrity may be
compromised because unprotected communications can be intercepted and either read or
altered.

This requirement applies to both internal and external networks and all types of
information system components from which information can be transmitted (e.g., servers,
mobile devices, notebook computers, printers, copiers, scanners, and facsimile
machines). Communication paths outside the physical protection of a controlled boundary
are exposed to the possibility of interception and modification.

Protecting the
confidentiality and integrity of organizational information can be accomplished by
physical means (e.g., employing physical distribution systems) or by logical means (e.g.,
employing cryptographic techniques). If physical means of protection are employed, then
logical means (cryptography) do not have to be employed, and vice versa.

```
New:
```
Without protection of the transmitted information, confidentiality and integrity may be compromised because unprotected communications can be intercepted and either read or altered.  
 
This requirement applies to both internal and external networks and all types of information system components from which information can be transmitted (e.g., servers, mobile devices, notebook computers, printers, copiers, scanners, and facsimile machines). Communication paths outside the physical protection of a controlled boundary are exposed to the possibility of interception and modification.  
 
Protecting the confidentiality and integrity of organizational information can be accomplished by physical means (e.g., employing physical distribution systems) or by logical means (e.g., employing cryptographic techniques). If physical means of protection are employed, then logical means (cryptography) do not have to be employed, and vice versa.



```
---
SV-238216:
Old:
```
Without cryptographic integrity protections, information can be altered by unauthorized
users without detection.

Remote access (e.g., RDP) is access to DoD nonpublic information
systems by an authorized user (or an information system) communicating through an external,
non-organization-controlled network. Remote access methods include, for example,
dial-up, broadband, and wireless. Nonlocal maintenance and diagnostic activities are
those activities conducted by individuals communicating through a network, either an
external network (e.g., the internet) or an internal network.

Local maintenance and
diagnostic activities are those activities carried out by individuals physically present
at the information system or information system component and not communicating across a
network connection.

Encrypting information for transmission protects information from
unauthorized disclosure and modification. Cryptographic mechanisms implemented to
protect information integrity include, for example, cryptographic hash functions which
have common application in digital signatures, checksums, and message authentication
codes.

```
New:
```
Without cryptographic integrity protections, information can be altered by unauthorized users without detection.  
 
Remote access (e.g., RDP) is access to DoD nonpublic information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless. Nonlocal maintenance and diagnostic activities are those activities conducted by individuals communicating through a network, either an external network (e.g., the internet) or an internal network.  
 
Local maintenance and diagnostic activities are those activities carried out by individuals physically present at the information system or information system component and not communicating across a network connection.  
 
Encrypting information for transmission protects information from unauthorized disclosure and modification. Cryptographic mechanisms implemented to protect information integrity include, for example, cryptographic hash functions which have common application in digital signatures, checksums, and message authentication codes.



```
---
SV-238217:
Old:
```
Without cryptographic integrity protections, information can be altered by unauthorized
users without detection.

Remote access (e.g., RDP) is access to DoD nonpublic information
systems by an authorized user (or an information system) communicating through an external,
non-organization-controlled network. Remote access methods include, for example,
dial-up, broadband, and wireless.

Nonlocal maintenance and diagnostic activities are
those activities conducted by individuals communicating through a network, either an
external network (e.g., the internet) or an internal network.

Local maintenance and
diagnostic activities are those activities carried out by individuals physically present
at the information system or information system component and not communicating across a
network connection.

Encrypting information for transmission protects information from
unauthorized disclosure and modification. Cryptographic mechanisms implemented to
protect information integrity include, for example, cryptographic hash functions which
have common application in digital signatures, checksums, and message authentication
codes.

By specifying a cipher list with the order of ciphers being in a "strongest to
weakest" orientation, the system will automatically attempt to use the strongest cipher for
securing SSH connections.

```
New:
```
Without cryptographic integrity protections, information can be altered by unauthorized users without detection.  
 
Remote access (e.g., RDP) is access to DoD nonpublic information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless.  
 
Nonlocal maintenance and diagnostic activities are those activities conducted by individuals communicating through a network, either an external network (e.g., the internet) or an internal network.  
 
Local maintenance and diagnostic activities are those activities carried out by individuals physically present at the information system or information system component and not communicating across a network connection.  
 
Encrypting information for transmission protects information from unauthorized disclosure and modification. Cryptographic mechanisms implemented to protect information integrity include, for example, cryptographic hash functions which have common application in digital signatures, checksums, and message authentication codes. 
 
By specifying a cipher list with the order of ciphers being in a "strongest to weakest" orientation, the system will automatically attempt to use the strongest cipher for securing SSH connections.



```
---
SV-238218:
Old:
```
Failure to restrict system access to authenticated users negatively impacts Ubuntu
operating system security.

```
New:
```
Failure to restrict system access to authenticated users negatively impacts Ubuntu operating system security.

```
---
SV-238219:
Old:
```
The security risk of using X11 forwarding is that the client's X11 display server may be
exposed to attack when the SSH client requests forwarding.  A System Administrator may have a
stance in which they want to protect clients that may expose themselves to attack by
unwittingly requesting X11 forwarding, which can warrant a ''no'' setting.

X11
forwarding should be enabled with caution. Users with the ability to bypass file permissions
on the remote host (for the user's X11 authorization database) can access the local X11
display through the forwarded connection. An attacker may then be able to perform activities
such as keystroke monitoring if the ForwardX11Trusted option is also enabled.

If X11
services are not required for the system's intended function, they should be disabled or
restricted as appropriate to the system’s needs.

```
New:
```
The security risk of using X11 forwarding is that the client's X11 display server may be exposed to attack when the SSH client requests forwarding.  A System Administrator may have a stance in which they want to protect clients that may expose themselves to attack by unwittingly requesting X11 forwarding, which can warrant a ''no'' setting. 
 
X11 forwarding should be enabled with caution. Users with the ability to bypass file permissions on the remote host (for the user's X11 authorization database) can access the local X11 display through the forwarded connection. An attacker may then be able to perform activities such as keystroke monitoring if the ForwardX11Trusted option is also enabled. 
 
If X11 services are not required for the system's intended function, they should be disabled or restricted as appropriate to the system’s needs.

```
---
SV-238220:
Old:
```
When X11 forwarding is enabled, there may be additional exposure to the server and client
displays if the sshd proxy display is configured to listen on the wildcard address.  By
default, sshd binds the forwarding server to the loopback address and sets the hostname part
of the DISPLAY environment variable to localhost. This prevents remote hosts from
connecting to the proxy display.

```
New:
```
When X11 forwarding is enabled, there may be additional exposure to the server and client displays if the sshd proxy display is configured to listen on the wildcard address.  By default, sshd binds the forwarding server to the loopback address and sets the hostname part of the DISPLAY environment variable to localhost. This prevents remote hosts from connecting to the proxy display.

```
---
SV-238221:
Old:
```
Use of a complex password helps to increase the time and resources required to compromise the
password. Password complexity, or strength, is a measure of the effectiveness of a password
in resisting attempts at guessing and brute-force attacks.

Password complexity is one
factor of several that determines how long it takes to crack a password. The more complex the
password, the greater the number of possible combinations that need to be tested before the
password is compromised.

```
New:
```
Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. 
 
Password complexity is one factor of several that determines how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.

```
---
SV-238222:
Old:
```
Use of a complex password helps to increase the time and resources required to compromise the
password. Password complexity, or strength, is a measure of the effectiveness of a password
in resisting attempts at guessing and brute-force attacks.

Password complexity is one
factor of several that determines how long it takes to crack a password. The more complex the
password, the greater the number of possible combinations that need to be tested before the
password is compromised.

```
New:
```
Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. 
 
Password complexity is one factor of several that determines how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.

```
---
SV-238223:
Old:
```
Use of a complex password helps to increase the time and resources required to compromise the
password. Password complexity, or strength, is a measure of the effectiveness of a password
in resisting attempts at guessing and brute-force attacks.

Password complexity is one
factor of several that determines how long it takes to crack a password. The more complex the
password, the greater the number of possible combinations that need to be tested before the
password is compromised.

```
New:
```
Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. 
 
Password complexity is one factor of several that determines how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.

```
---
SV-238224:
Old:
```
If the operating system allows the user to consecutively reuse extensive portions of
passwords, this increases the chances of password compromise by increasing the window of
opportunity for attempts at guessing and brute-force attacks.

The number of changed
characters refers to the number of changes required with respect to the total number of
positions in the current password. In other words, characters may be the same within the two
passwords; however, the positions of the like characters must be different.

If the
password length is an odd number then number of changed characters must be rounded up.  For
example, a password length of 15 characters must require the change of at least 8 characters.

```
New:
```
If the operating system allows the user to consecutively reuse extensive portions of passwords, this increases the chances of password compromise by increasing the window of opportunity for attempts at guessing and brute-force attacks. 
 
The number of changed characters refers to the number of changes required with respect to the total number of positions in the current password. In other words, characters may be the same within the two passwords; however, the positions of the like characters must be different. 
 
If the password length is an odd number then number of changed characters must be rounded up.  For example, a password length of 15 characters must require the change of at least 8 characters.

```
---
SV-238225:
Old:
```
The shorter the password, the lower the number of possible combinations that need to be tested
before the password is compromised.

Password complexity, or strength, is a measure of the
effectiveness of a password in resisting attempts at guessing and brute-force attacks.
Password length is one factor of several that helps to determine strength and how long it takes
to crack a password. Use of more characters in a password helps to exponentially increase the
time and/or resources required to compromise the password.

```
New:
```
The shorter the password, the lower the number of possible combinations that need to be tested before the password is compromised. 
 
Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. Password length is one factor of several that helps to determine strength and how long it takes to crack a password. Use of more characters in a password helps to exponentially increase the time and/or resources required to compromise the password.

```
---
SV-238226:
Old:
```
Use of a complex password helps to increase the time and resources required to compromise the
password. Password complexity or strength is a measure of the effectiveness of a password in
resisting attempts at guessing and brute-force attacks.

Password complexity is one
factor in determining how long it takes to crack a password. The more complex the password, the
greater the number of possible combinations that need to be tested before the password is
compromised.

Special characters are those characters that are not alphanumeric.
Examples include: ~ ! @ # $ % ^ *.

```
New:
```
Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity or strength is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. 
 
Password complexity is one factor in determining how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised. 
 
Special characters are those characters that are not alphanumeric. Examples include: ~ ! @ # $ % ^ *.

```
---
SV-238227:
Old:
```
If the Ubuntu operating system allows the user to select passwords based on dictionary words,
then this increases the chances of password compromise by increasing the opportunity for
successful guesses and brute-force attacks.

```
New:
```
If the Ubuntu operating system allows the user to select passwords based on dictionary words, then this increases the chances of password compromise by increasing the opportunity for successful guesses and brute-force attacks.

```
---
SV-238228:
Old:
```
Use of a complex password helps to increase the time and resources required to compromise the
password. Password complexity, or strength, is a measure of the effectiveness of a password
in resisting attempts at guessing and brute-force attacks. "pwquality" enforces complex
password construction configuration and has the ability to limit brute-force attacks on the
system.

```
New:
```
Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. "pwquality" enforces complex password construction configuration and has the ability to limit brute-force attacks on the system.

```
---
SV-238229:
Old:
```
Without path validation, an informed trust decision by the relying party cannot be made when
presented with any certificate not already explicitly trusted.

A trust anchor is an
authoritative entity represented via a public key and associated data. It is used in the
context of public key infrastructures, X.509 digital certificates, and DNSSEC.

When
there is a chain of trust, usually the top entity to be trusted becomes the trust anchor; it can
be, for example, a Certification Authority (CA). A certification path starts with the
subject certificate and proceeds through a number of intermediate certificates up to a
trusted root certificate, typically issued by a trusted CA.

This requirement verifies
that a certification path to an accepted trust anchor is used for certificate validation and
that the path includes status information. Path validation is necessary for a relying party
to make an informed trust decision when presented with any certificate not already
explicitly trusted. Status information for certification paths includes certificate
revocation lists or online certificate status protocol responses. Validation of the
certificate status information is out of scope for this requirement.

```
New:
```
Without path validation, an informed trust decision by the relying party cannot be made when presented with any certificate not already explicitly trusted. 
 
A trust anchor is an authoritative entity represented via a public key and associated data. It is used in the context of public key infrastructures, X.509 digital certificates, and DNSSEC. 
 
When there is a chain of trust, usually the top entity to be trusted becomes the trust anchor; it can be, for example, a Certification Authority (CA). A certification path starts with the subject certificate and proceeds through a number of intermediate certificates up to a trusted root certificate, typically issued by a trusted CA. 
 
This requirement verifies that a certification path to an accepted trust anchor is used for certificate validation and that the path includes status information. Path validation is necessary for a relying party to make an informed trust decision when presented with any certificate not already explicitly trusted. Status information for certification paths includes certificate revocation lists or online certificate status protocol responses. Validation of the certificate status information is out of scope for this requirement.

```
---
SV-238230:
Old:
```
Using an authentication device, such as a CAC or token that is separate from the information
system, ensures that even if the information system is compromised, that compromise will not
affect credentials stored on the authentication device.

Multifactor solutions that
require devices separate from information systems gaining access include, for example,
hardware tokens providing time-based or challenge-response authenticators and smart
cards such as the U.S. Government Personal Identity Verification card and the DoD Common
Access Card.

A privileged account is defined as an information system account with
authorizations of a privileged user.

Remote access is access to DoD nonpublic information
systems by an authorized user (or an information system) communicating through an external,
non-organization-controlled network. Remote access methods include, for example,
dial-up, broadband, and wireless.

This requirement only applies to components where this
is specific to the function of the device or has the concept of an organizational user (e.g.,
VPN, proxy capability). This does not apply to authentication for the purpose of configuring
the device itself (management).

```
New:
```
Using an authentication device, such as a CAC or token that is separate from the information system, ensures that even if the information system is compromised, that compromise will not affect credentials stored on the authentication device. 
 
Multifactor solutions that require devices separate from information systems gaining access include, for example, hardware tokens providing time-based or challenge-response authenticators and smart cards such as the U.S. Government Personal Identity Verification card and the DoD Common Access Card. 
 
A privileged account is defined as an information system account with authorizations of a privileged user. 
 
Remote access is access to DoD nonpublic information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless. 
 
This requirement only applies to components where this is specific to the function of the device or has the concept of an organizational user (e.g., VPN, proxy capability). This does not apply to authentication for the purpose of configuring the device itself (management).

```
---
SV-238231:
Old:
```
The use of PIV credentials facilitates standardization and reduces the risk of unauthorized
access.

DoD has mandated the use of the CAC to support identity management and personal
authentication for systems covered under Homeland Security Presidential Directive (HSPD)
12, as well as making the CAC a primary component of layered protection for national security
systems.

```
New:
```
The use of PIV credentials facilitates standardization and reduces the risk of unauthorized access. 
 
DoD has mandated the use of the CAC to support identity management and personal authentication for systems covered under Homeland Security Presidential Directive (HSPD) 12, as well as making the CAC a primary component of layered protection for national security systems.

```
---
SV-238232:
Old:
```
The use of PIV credentials facilitates standardization and reduces the risk of unauthorized
access.

DoD has mandated the use of the CAC to support identity management and personal
authentication for systems covered under Homeland Security Presidential Directive (HSPD)
12, as well as making the CAC a primary component of layered protection for national security
systems.

```
New:
```
The use of PIV credentials facilitates standardization and reduces the risk of unauthorized access. 
 
DoD has mandated the use of the CAC to support identity management and personal authentication for systems covered under Homeland Security Presidential Directive (HSPD) 12, as well as making the CAC a primary component of layered protection for national security systems.

```
---
SV-238233:
Old:
```
Without configuring a local cache of revocation data, there is the potential to allow access
to users who are no longer authorized (users with revoked certificates).

```
New:
```
Without configuring a local cache of revocation data, there is the potential to allow access to users who are no longer authorized (users with revoked certificates).

```
---
SV-238234:
Old:
```
Password complexity, or strength, is a measure of the effectiveness of a password in
resisting attempts at guessing and brute-force attacks. If the information system or
application allows the user to consecutively reuse their password when that password has
exceeded its defined lifetime, the end result is a password that is not changed as per policy
requirements.

```
New:
```
Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. If the information system or application allows the user to consecutively reuse their password when that password has exceeded its defined lifetime, the end result is a password that is not changed as per policy requirements.



```
---
SV-238235:
Old:
```
By limiting the number of failed logon attempts, the risk of unauthorized system access via
user password guessing, otherwise known as brute-forcing, is reduced. Limits are imposed by
locking the account.

```
New:
```
By limiting the number of failed logon attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute-forcing, is reduced. Limits are imposed by locking the account.



```
---
SV-238236:
Old:
```
Without verification of the security functions, security functions may not operate
correctly and the failure may go unnoticed. Security function is defined as the hardware,
software, and/or firmware of the information system responsible for enforcing the system
security policy and supporting the isolation of code and data on which the protection is
based. Security functionality includes, but is not limited to, establishing system
accounts, configuring access authorizations (i.e., permissions, privileges), setting
events to be audited, and setting intrusion detection parameters.

Notifications
provided by information systems include, for example, electronic alerts to System
Administrators, messages to local computer consoles, and/or hardware indications, such as
lights.

This requirement applies to the Ubuntu operating system performing security
function verification/testing and/or systems and environments that require this
functionality.

```
New:
```
Without verification of the security functions, security functions may not operate correctly and the failure may go unnoticed. Security function is defined as the hardware, software, and/or firmware of the information system responsible for enforcing the system security policy and supporting the isolation of code and data on which the protection is based. Security functionality includes, but is not limited to, establishing system accounts, configuring access authorizations (i.e., permissions, privileges), setting events to be audited, and setting intrusion detection parameters. 
 
Notifications provided by information systems include, for example, electronic alerts to System Administrators, messages to local computer consoles, and/or hardware indications, such as lights. 
 
This requirement applies to the Ubuntu operating system performing security function verification/testing and/or systems and environments that require this functionality.

```
---
SV-238237:
Old:
```
Limiting the number of logon attempts over a certain time interval reduces the chances that an
unauthorized user may gain access to an account.

```
New:
```
Limiting the number of logon attempts over a certain time interval reduces the chances that an unauthorized user may gain access to an account.

```
---
SV-238238:
Old:
```
Once an attacker establishes access to a system, the attacker often attempts to create a
persistent method of reestablishing access. One way to accomplish this is for the attacker to
create an account. Auditing account creation actions provides logging that can be used for
forensic purposes.

To address access requirements, many operating systems may be
integrated with enterprise level authentication/access/auditing mechanisms that meet or
exceed access control policy requirements.

```
New:
```
Once an attacker establishes access to a system, the attacker often attempts to create a persistent method of reestablishing access. One way to accomplish this is for the attacker to create an account. Auditing account creation actions provides logging that can be used for forensic purposes. 
 
To address access requirements, many operating systems may be integrated with enterprise level authentication/access/auditing mechanisms that meet or exceed access control policy requirements.



```
---
SV-238239:
Old:
```
Once an attacker establishes access to a system, the attacker often attempts to create a
persistent method of reestablishing access. One way to accomplish this is for the attacker to
create an account. Auditing account creation actions provides logging that can be used for
forensic purposes.

To address access requirements, many operating systems may be
integrated with enterprise level authentication/access/auditing mechanisms that meet or
exceed access control policy requirements.

```
New:
```
Once an attacker establishes access to a system, the attacker often attempts to create a persistent method of reestablishing access. One way to accomplish this is for the attacker to create an account. Auditing account creation actions provides logging that can be used for forensic purposes. 
 
To address access requirements, many operating systems may be integrated with enterprise level authentication/access/auditing mechanisms that meet or exceed access control policy requirements.



```
---
SV-238240:
Old:
```
Once an attacker establishes access to a system, the attacker often attempts to create a
persistent method of reestablishing access. One way to accomplish this is for the attacker to
create an account. Auditing account creation actions provides logging that can be used for
forensic purposes.

To address access requirements, many operating systems may be
integrated with enterprise level authentication/access/auditing mechanisms that meet or
exceed access control policy requirements.

```
New:
```
Once an attacker establishes access to a system, the attacker often attempts to create a persistent method of reestablishing access. One way to accomplish this is for the attacker to create an account. Auditing account creation actions provides logging that can be used for forensic purposes. 
 
To address access requirements, many operating systems may be integrated with enterprise level authentication/access/auditing mechanisms that meet or exceed access control policy requirements.



```
---
SV-238241:
Old:
```
Once an attacker establishes access to a system, the attacker often attempts to create a
persistent method of reestablishing access. One way to accomplish this is for the attacker to
create an account. Auditing account creation actions provides logging that can be used for
forensic purposes.

To address access requirements, many operating systems may be
integrated with enterprise level authentication/access/auditing mechanisms that meet or
exceed access control policy requirements.

```
New:
```
Once an attacker establishes access to a system, the attacker often attempts to create a persistent method of reestablishing access. One way to accomplish this is for the attacker to create an account. Auditing account creation actions provides logging that can be used for forensic purposes. 
 
To address access requirements, many operating systems may be integrated with enterprise level authentication/access/auditing mechanisms that meet or exceed access control policy requirements.



```
---
SV-238242:
Old:
```
Once an attacker establishes access to a system, the attacker often attempts to create a
persistent method of reestablishing access. One way to accomplish this is for the attacker to
create an account. Auditing account creation actions provides logging that can be used for
forensic purposes.

To address access requirements, many operating systems may be
integrated with enterprise level authentication/access/auditing mechanisms that meet or
exceed access control policy requirements.

```
New:
```
Once an attacker establishes access to a system, the attacker often attempts to create a persistent method of reestablishing access. One way to accomplish this is for the attacker to create an account. Auditing account creation actions provides logging that can be used for forensic purposes. 
 
To address access requirements, many operating systems may be integrated with enterprise level authentication/access/auditing mechanisms that meet or exceed access control policy requirements. 



```
---
SV-238243:
Old:
```
It is critical for the appropriate personnel to be aware if a system is at risk of failing to
process audit logs as required. Without this notification, the security personnel may be
unaware of an impending failure of the audit capability, and system operation may be
adversely affected.

Audit processing failures include software/hardware errors,
failures in the audit capturing mechanisms, and audit storage capacity being reached or
exceeded.

This requirement applies to each audit data storage repository (i.e., distinct
information system component where audit records are stored), the centralized audit
storage capacity of organizations (i.e., all audit data storage repositories combined), or
both.

```
New:
```
It is critical for the appropriate personnel to be aware if a system is at risk of failing to process audit logs as required. Without this notification, the security personnel may be unaware of an impending failure of the audit capability, and system operation may be adversely affected. 
 
Audit processing failures include software/hardware errors, failures in the audit capturing mechanisms, and audit storage capacity being reached or exceeded. 
 
This requirement applies to each audit data storage repository (i.e., distinct information system component where audit records are stored), the centralized audit storage capacity of organizations (i.e., all audit data storage repositories combined), or both.

```
---
SV-238244:
Old:
```
It is critical that when the operating system is at risk of failing to process audit logs as
required, it takes action to mitigate the failure. Audit processing failures include:
software/hardware errors; failures in the audit capturing mechanisms; and audit storage
capacity being reached or exceeded. Responses to audit failure depend upon the nature of the
failure mode.

When availability is an overriding concern, other approved actions in
response to an audit failure are as follows:

1) If the failure was caused by the lack of audit
record storage capacity, the operating system must continue generating audit records if
possible (automatically restarting the audit service if necessary), overwriting the
oldest audit records in a first-in-first-out manner.

2) If audit records are sent to a
centralized collection server and communication with this server is lost or the server
fails, the operating system must queue audit records locally until communication is
restored or until the audit records are retrieved manually. Upon restoration of the
connection to the centralized collection server, action should be taken to synchronize the
local audit data with the collection server.

```
New:
```
It is critical that when the operating system is at risk of failing to process audit logs as required, it takes action to mitigate the failure. Audit processing failures include: software/hardware errors; failures in the audit capturing mechanisms; and audit storage capacity being reached or exceeded. Responses to audit failure depend upon the nature of the failure mode. 
 
When availability is an overriding concern, other approved actions in response to an audit failure are as follows:  
 
1) If the failure was caused by the lack of audit record storage capacity, the operating system must continue generating audit records if possible (automatically restarting the audit service if necessary), overwriting the oldest audit records in a first-in-first-out manner. 
 
2) If audit records are sent to a centralized collection server and communication with this server is lost or the server fails, the operating system must queue audit records locally until communication is restored or until the audit records are retrieved manually. Upon restoration of the connection to the centralized collection server, action should be taken to synchronize the local audit data with the collection server.

```
---
SV-238245:
Old:
```
Unauthorized disclosure of audit records can reveal system and configuration data to
attackers, thus compromising its confidentiality.

Audit information includes all
information (e.g., audit records, audit settings, audit reports) needed to successfully
audit operating system activity.

```
New:
```
Unauthorized disclosure of audit records can reveal system and configuration data to attackers, thus compromising its confidentiality. 
 
Audit information includes all information (e.g., audit records, audit settings, audit reports) needed to successfully audit operating system activity.



```
---
SV-238246:
Old:
```
Unauthorized disclosure of audit records can reveal system and configuration data to
attackers, thus compromising its confidentiality.

Audit information includes all
information (e.g., audit records, audit settings, audit reports) needed to successfully
audit operating system activity.

```
New:
```
Unauthorized disclosure of audit records can reveal system and configuration data to attackers, thus compromising its confidentiality. 
 
Audit information includes all information (e.g., audit records, audit settings, audit reports) needed to successfully audit operating system activity.



```
---
SV-238247:
Old:
```
Unauthorized disclosure of audit records can reveal system and configuration data to
attackers, thus compromising its confidentiality.

Audit information includes all
information (e.g., audit records, audit settings, audit reports) needed to successfully
audit operating system activity.

```
New:
```
Unauthorized disclosure of audit records can reveal system and configuration data to attackers, thus compromising its confidentiality. 
 
Audit information includes all information (e.g., audit records, audit settings, audit reports) needed to successfully audit operating system activity.



```
---
SV-238248:
Old:
```
If audit information were to become compromised, then forensic analysis and discovery of the
true source of potentially malicious system activity is impossible to achieve.

To ensure
the veracity of audit information, the operating system must protect audit information from
unauthorized deletion. This requirement can be achieved through multiple methods, which
will depend upon system architecture and design.

Audit information includes all
information (e.g., audit records, audit settings, audit reports) needed to successfully
audit information system activity.

```
New:
```
If audit information were to become compromised, then forensic analysis and discovery of the true source of potentially malicious system activity is impossible to achieve. 
 
To ensure the veracity of audit information, the operating system must protect audit information from unauthorized deletion. This requirement can be achieved through multiple methods, which will depend upon system architecture and design. 
 
Audit information includes all information (e.g., audit records, audit settings, audit reports) needed to successfully audit information system activity.

```
---
SV-238249:
Old:
```
Without the capability to restrict which roles and individuals can select which events are
audited, unauthorized personnel may be able to prevent the auditing of critical events.


Misconfigured audits may degrade the system's performance by overwhelming the audit log.
Misconfigured audits may also make it more difficult to establish, correlate, and
investigate the events relating to an incident or identify those responsible for one.

```
New:
```
Without the capability to restrict which roles and individuals can select which events are audited, unauthorized personnel may be able to prevent the auditing of critical events. 
 
Misconfigured audits may degrade the system's performance by overwhelming the audit log. Misconfigured audits may also make it more difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

```
---
SV-238250:
Old:
```
Without the capability to restrict which roles and individuals can select which events are
audited, unauthorized personnel may be able to prevent the auditing of critical events.


Misconfigured audits may degrade the system's performance by overwhelming the audit log.
Misconfigured audits may also make it more difficult to establish, correlate, and
investigate the events relating to an incident or identify those responsible for one.

```
New:
```
Without the capability to restrict which roles and individuals can select which events are audited, unauthorized personnel may be able to prevent the auditing of critical events.  
 
Misconfigured audits may degrade the system's performance by overwhelming the audit log. Misconfigured audits may also make it more difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

```
---
SV-238251:
Old:
```
Without the capability to restrict which roles and individuals can select which events are
audited, unauthorized personnel may be able to prevent the auditing of critical events.


Misconfigured audits may degrade the system's performance by overwhelming the audit log.
Misconfigured audits may also make it more difficult to establish, correlate, and
investigate the events relating to an incident or identify those responsible for one.

```
New:
```
Without the capability to restrict which roles and individuals can select which events are audited, unauthorized personnel may be able to prevent the auditing of critical events.  
 
Misconfigured audits may degrade the system's performance by overwhelming the audit log. Misconfigured audits may also make it more difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

```
---
SV-238252:
Old:
```
Without generating audit records that are specific to the security and mission needs of the
organization, it would be difficult to establish, correlate, and investigate the events
relating to an incident or identify those responsible for one.

Audit records can be
generated from various components within the information system (e.g., module or policy
filter).

```
New:
```
Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. 
 
Audit records can be generated from various components within the information system (e.g., module or policy filter).

```
---
SV-238253:
Old:
```
Without generating audit records that are specific to the security and mission needs of the
organization, it would be difficult to establish, correlate, and investigate the events
relating to an incident or identify those responsible for one.

Audit records can be
generated from various components within the information system (e.g., module or policy
filter).

```
New:
```
Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. 
 
Audit records can be generated from various components within the information system (e.g., module or policy filter).

```
---
SV-238254:
Old:
```
Without generating audit records that are specific to the security and mission needs of the
organization, it would be difficult to establish, correlate, and investigate the events
relating to an incident or identify those responsible for one.

Audit records can be
generated from various components within the information system (e.g., module or policy
filter).

```
New:
```
Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. 
 
Audit records can be generated from various components within the information system (e.g., module or policy filter).

```
---
SV-238255:
Old:
```
Without generating audit records that are specific to the security and mission needs of the
organization, it would be difficult to establish, correlate, and investigate the events
relating to an incident or identify those responsible for one.

Audit records can be
generated from various components within the information system (e.g., module or policy
filter).

```
New:
```
Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. 
 
Audit records can be generated from various components within the information system (e.g., module or policy filter).

```
---
SV-238256:
Old:
```
Without generating audit records that are specific to the security and mission needs of the
organization, it would be difficult to establish, correlate, and investigate the events
relating to an incident or identify those responsible for one.

Audit records can be
generated from various components within the information system (e.g., module or policy
filter).

```
New:
```
Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. 
 
Audit records can be generated from various components within the information system (e.g., module or policy filter).

```
---
SV-238257:
Old:
```
Without generating audit records that are specific to the security and mission needs of the
organization, it would be difficult to establish, correlate, and investigate the events
relating to an incident or identify those responsible for one.

Audit records can be
generated from various components within the information system (e.g., module or policy
filter).

```
New:
```
Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. 
 
Audit records can be generated from various components within the information system (e.g., module or policy filter).

```
---
SV-238258:
Old:
```
Without generating audit records that are specific to the security and mission needs of the
organization, it would be difficult to establish, correlate, and investigate the events
relating to an incident or identify those responsible for one.

Audit records can be
generated from various components within the information system (e.g., module or policy
filter).

The system call rules are loaded into a matching engine that intercepts each
syscall that all programs on the system makes. Therefore, it is very important to only use
syscall rules when absolutely necessary since these affect performance. The more rules, the
bigger the performance hit. The performance is helped, though, by combining syscalls into
one rule whenever possible.

```
New:
```
Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. 
 
Audit records can be generated from various components within the information system (e.g., module or policy filter).

The system call rules are loaded into a matching engine that intercepts each syscall that all programs on the system makes. Therefore, it is very important to only use syscall rules when absolutely necessary since these affect performance. The more rules, the bigger the performance hit. The performance is helped, though, by combining syscalls into one rule whenever possible.



```
---
SV-238264:
Old:
```
Without generating audit records that are specific to the security and mission needs of the
organization, it would be difficult to establish, correlate, and investigate the events
relating to an incident or identify those responsible for one.

Audit records can be
generated from various components within the information system (e.g., module or policy
filter).

The system call rules are loaded into a matching engine that intercepts each
syscall that all programs on the system makes. Therefore, it is very important to only use
syscall rules when absolutely necessary since these affect performance. The more rules, the
bigger the performance hit. The performance is helped, though, by combining syscalls into
one rule whenever possible.

```
New:
```
Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. 
 
Audit records can be generated from various components within the information system (e.g., module or policy filter).

The system call rules are loaded into a matching engine that intercepts each syscall that all programs on the system makes. Therefore, it is very important to only use syscall rules when absolutely necessary since these affect performance. The more rules, the bigger the performance hit. The performance is helped, though, by combining syscalls into one rule whenever possible.



```
---
SV-238268:
Old:
```
Without generating audit records that are specific to the security and mission needs of the
organization, it would be difficult to establish, correlate, and investigate the events
relating to an incident or identify those responsible for one.

Audit records can be
generated from various components within the information system (e.g., module or policy
filter).

The system call rules are loaded into a matching engine that intercepts each
syscall that all programs on the system makes. Therefore, it is very important to only use
syscall rules when absolutely necessary since these affect performance. The more rules, the
bigger the performance hit. The performance is helped, though, by combining syscalls into
one rule whenever possible.

```
New:
```
Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. 
 
Audit records can be generated from various components within the information system (e.g., module or policy filter).

The system call rules are loaded into a matching engine that intercepts each syscall that all programs on the system makes. Therefore, it is very important to only use syscall rules when absolutely necessary since these affect performance. The more rules, the bigger the performance hit. The performance is helped, though, by combining syscalls into one rule whenever possible.



```
---
SV-238271:
Old:
```
Without generating audit records that are specific to the security and mission needs of the
organization, it would be difficult to establish, correlate, and investigate the events
relating to an incident or identify those responsible for one.

Audit records can be
generated from various components within the information system (e.g., module or policy
filter).

The system call rules are loaded into a matching engine that intercepts each
syscall that all programs on the system makes. Therefore, it is very important to only use
syscall rules when absolutely necessary since these affect performance. The more rules, the
bigger the performance hit. The performance is helped, though, by combining syscalls into
one rule whenever possible.

```
New:
```
Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. 
 
Audit records can be generated from various components within the information system (e.g., module or policy filter).

The system call rules are loaded into a matching engine that intercepts each syscall that all programs on the system makes. Therefore, it is very important to only use syscall rules when absolutely necessary since these affect performance. The more rules, the bigger the performance hit. The performance is helped, though, by combining syscalls into one rule whenever possible.



```
---
SV-238277:
Old:
```
Without generating audit records that are specific to the security and mission needs of the
organization, it would be difficult to establish, correlate, and investigate the events
relating to an incident or identify those responsible for one.

Audit records can be
generated from various components within the information system (e.g., module or policy
filter).

```
New:
```
Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. 
 
Audit records can be generated from various components within the information system (e.g., module or policy filter).

```
---
SV-238278:
Old:
```
Without generating audit records that are specific to the security and mission needs of the
organization, it would be difficult to establish, correlate, and investigate the events
relating to an incident or identify those responsible for one.

Audit records can be
generated from various components within the information system (e.g., module or policy
filter).

```
New:
```
Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. 
 
Audit records can be generated from various components within the information system (e.g., module or policy filter).

```
---
SV-238279:
Old:
```
Without generating audit records that are specific to the security and mission needs of the
organization, it would be difficult to establish, correlate, and investigate the events
relating to an incident or identify those responsible for one.

Audit records can be
generated from various components within the information system (e.g., module or policy
filter).

```
New:
```
Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. 
 
Audit records can be generated from various components within the information system (e.g., module or policy filter).

```
---
SV-238280:
Old:
```
Without generating audit records that are specific to the security and mission needs of the
organization, it would be difficult to establish, correlate, and investigate the events
relating to an incident or identify those responsible for one.

Audit records can be
generated from various components within the information system (e.g., module or policy
filter).

```
New:
```
Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. 
 
Audit records can be generated from various components within the information system (e.g., module or policy filter).

```
---
SV-238281:
Old:
```
Without generating audit records that are specific to the security and mission needs of the
organization, it would be difficult to establish, correlate, and investigate the events
relating to an incident or identify those responsible for one.

Audit records can be
generated from various components within the information system (e.g., module or policy
filter).

```
New:
```
Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. 
 
Audit records can be generated from various components within the information system (e.g., module or policy filter).

```
---
SV-238282:
Old:
```
Without generating audit records that are specific to the security and mission needs of the
organization, it would be difficult to establish, correlate, and investigate the events
relating to an incident or identify those responsible for one.

Audit records can be
generated from various components within the information system (e.g., module or policy
filter).

```
New:
```
Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. 
 
Audit records can be generated from various components within the information system (e.g., module or policy filter).

```
---
SV-238283:
Old:
```
Without generating audit records that are specific to the security and mission needs of the
organization, it would be difficult to establish, correlate, and investigate the events
relating to an incident or identify those responsible for one.

Audit records can be
generated from various components within the information system (e.g., module or policy
filter).

```
New:
```
Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. 
 
Audit records can be generated from various components within the information system (e.g., module or policy filter).

```
---
SV-238284:
Old:
```
Without generating audit records that are specific to the security and mission needs of the
organization, it would be difficult to establish, correlate, and investigate the events
relating to an incident or identify those responsible for one.

Audit records can be
generated from various components within the information system (e.g., module or policy
filter).

```
New:
```
Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. 
 
Audit records can be generated from various components within the information system (e.g., module or policy filter).

```
---
SV-238285:
Old:
```
Without generating audit records that are specific to the security and mission needs of the
organization, it would be difficult to establish, correlate, and investigate the events
relating to an incident or identify those responsible for one.

Audit records can be
generated from various components within the information system (e.g., module or policy
filter).

```
New:
```
Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. 
 
Audit records can be generated from various components within the information system (e.g., module or policy filter).



```
---
SV-238286:
Old:
```
Without generating audit records that are specific to the security and mission needs of the
organization, it would be difficult to establish, correlate, and investigate the events
relating to an incident or identify those responsible for one.

Audit records can be
generated from various components within the information system (e.g., module or policy
filter).

```
New:
```
Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. 
 
Audit records can be generated from various components within the information system (e.g., module or policy filter).



```
---
SV-238287:
Old:
```
Without generating audit records that are specific to the security and mission needs of the
organization, it would be difficult to establish, correlate, and investigate the events
relating to an incident or identify those responsible for one.

Audit records can be
generated from various components within the information system (e.g., module or policy
filter).

```
New:
```
Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. 
 
Audit records can be generated from various components within the information system (e.g., module or policy filter).



```
---
SV-238288:
Old:
```
Without generating audit records that are specific to the security and mission needs of the
organization, it would be difficult to establish, correlate, and investigate the events
relating to an incident or identify those responsible for one.

Audit records can be
generated from various components within the information system (e.g., module or policy
filter).

```
New:
```
Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. 
 
Audit records can be generated from various components within the information system (e.g., module or policy filter).

```
---
SV-238289:
Old:
```
Without generating audit records that are specific to the security and mission needs of the
organization, it would be difficult to establish, correlate, and investigate the events
relating to an incident or identify those responsible for one.

Audit records can be
generated from various components within the information system (e.g., module or policy
filter).

```
New:
```
Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. 
 
Audit records can be generated from various components within the information system (e.g., module or policy filter).

```
---
SV-238290:
Old:
```
Without generating audit records that are specific to the security and mission needs of the
organization, it would be difficult to establish, correlate, and investigate the events
relating to an incident or identify those responsible for one.

Audit records can be
generated from various components within the information system (e.g., module or policy
filter).

```
New:
```
Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. 
 
Audit records can be generated from various components within the information system (e.g., module or policy filter).

```
---
SV-238291:
Old:
```
Without generating audit records that are specific to the security and mission needs of the
organization, it would be difficult to establish, correlate, and investigate the events
relating to an incident or identify those responsible for one.

Audit records can be
generated from various components within the information system (e.g., module or policy
filter).

```
New:
```
Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. 
 
Audit records can be generated from various components within the information system (e.g., module or policy filter).

```
---
SV-238292:
Old:
```
Without generating audit records that are specific to the security and mission needs of the
organization, it would be difficult to establish, correlate, and investigate the events
relating to an incident or identify those responsible for one.

Audit records can be
generated from various components within the information system (e.g., module or policy
filter).

```
New:
```
Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. 
 
Audit records can be generated from various components within the information system (e.g., module or policy filter).

```
---
SV-238293:
Old:
```
Without generating audit records that are specific to the security and mission needs of the
organization, it would be difficult to establish, correlate, and investigate the events
relating to an incident or identify those responsible for one.

Audit records can be
generated from various components within the information system (e.g., module or policy
filter).

```
New:
```
Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. 
 
Audit records can be generated from various components within the information system (e.g., module or policy filter).

```
---
SV-238294:
Old:
```
Without generating audit records that are specific to the security and mission needs of the
organization, it would be difficult to establish, correlate, and investigate the events
relating to an incident or identify those responsible for one.

Audit records can be
generated from various components within the information system (e.g., module or policy
filter).

```
New:
```
Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. 
 
Audit records can be generated from various components within the information system (e.g., module or policy filter).

```
---
SV-238295:
Old:
```
Without generating audit records that are specific to the security and mission needs of the
organization, it would be difficult to establish, correlate, and investigate the events
relating to an incident or identify those responsible for one.

Audit records can be
generated from various components within the information system (e.g., module or policy
filter).

The system call rules are loaded into a matching engine that intercepts each
syscall that all programs on the system makes. Therefore, it is very important to only use
syscall rules when absolutely necessary since these affect performance. The more rules, the
bigger the performance hit. The performance is helped, though, by combining syscalls into
one rule whenever possible.

```
New:
```
Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. 
 
Audit records can be generated from various components within the information system (e.g., module or policy filter).

The system call rules are loaded into a matching engine that intercepts each syscall that all programs on the system makes. Therefore, it is very important to only use syscall rules when absolutely necessary since these affect performance. The more rules, the bigger the performance hit. The performance is helped, though, by combining syscalls into one rule whenever possible.



```
---
SV-238297:
Old:
```
Without generating audit records that are specific to the security and mission needs of the
organization, it would be difficult to establish, correlate, and investigate the events
relating to an incident or identify those responsible for one.

Audit records can be
generated from various components within the information system (e.g., module or policy
filter).

```
New:
```
Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. 

Audit records can be generated from various components within the information system (e.g., module or policy filter).



```
---
SV-238298:
Old:
```
Without establishing the when, where, type, source, and outcome of events that occurred, it
would be difficult to establish, correlate, and investigate the events leading up to an
outage or attack.

Without the capability to generate audit records, it would be difficult
to establish, correlate, and investigate the events relating to an incident or identify
those responsible for one.

Audit record content that may be necessary to satisfy this
requirement includes, for example, time stamps, source and destination addresses,
user/process identifiers, event descriptions, success/fail indications, filenames
involved, and access control or flow control rules invoked.

Reconstruction of harmful
events or forensic analysis is not possible if audit records do not contain enough
information.

Successful incident response and auditing relies on timely, accurate
system information and analysis in order to allow the organization to identify and respond to
potential incidents in a proficient manner. If the operating system does not provide the
ability to centrally review the operating system logs, forensic analysis is negatively
impacted.

Associating event types with detected events in the Ubuntu operating system
audit logs provides a means of investigating an attack; recognizing resource utilization or
capacity thresholds; or identifying an improperly configured operating system.

```
New:
```
Without establishing the when, where, type, source, and outcome of events that occurred, it would be difficult to establish, correlate, and investigate the events leading up to an outage or attack. 
 
Without the capability to generate audit records, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. 
 
Audit record content that may be necessary to satisfy this requirement includes, for example, time stamps, source and destination addresses, user/process identifiers, event descriptions, success/fail indications, filenames involved, and access control or flow control rules invoked. 
 
Reconstruction of harmful events or forensic analysis is not possible if audit records do not contain enough information. 
 
Successful incident response and auditing relies on timely, accurate system information and analysis in order to allow the organization to identify and respond to potential incidents in a proficient manner. If the operating system does not provide the ability to centrally review the operating system logs, forensic analysis is negatively impacted. 
 
Associating event types with detected events in the Ubuntu operating system audit logs provides a means of investigating an attack; recognizing resource utilization or capacity thresholds; or identifying an improperly configured operating system.



```
---
SV-238299:
Old:
```
If auditing is enabled late in the start-up process, the actions of some start-up processes
may not be audited. Some audit systems also maintain state information only available if
auditing is enabled before a given process is created.

```
New:
```
If auditing is enabled late in the start-up process, the actions of some start-up processes may not be audited. Some audit systems also maintain state information only available if auditing is enabled before a given process is created.

```
---
SV-238300:
Old:
```
Protecting audit information also includes identifying and protecting the tools used to
view and manipulate log data. Therefore, protecting audit tools is necessary to prevent
unauthorized operation on audit information.

Operating systems providing tools to
interface with audit information will leverage user permissions and roles identifying the
user accessing the tools and the corresponding rights the user enjoys in order to make access
decisions regarding the access to audit tools.

Audit tools include, but are not limited to,
vendor-provided and open source audit tools needed to successfully view and manipulate
audit information system activity and records. Audit tools include custom queries and
report generators.

```
New:
```
Protecting audit information also includes identifying and protecting the tools used to view and manipulate log data. Therefore, protecting audit tools is necessary to prevent unauthorized operation on audit information. 
 
Operating systems providing tools to interface with audit information will leverage user permissions and roles identifying the user accessing the tools and the corresponding rights the user enjoys in order to make access decisions regarding the access to audit tools. 
 
Audit tools include, but are not limited to, vendor-provided and open source audit tools needed to successfully view and manipulate audit information system activity and records. Audit tools include custom queries and report generators.



```
---
SV-238301:
Old:
```
Protecting audit information also includes identifying and protecting the tools used to
view and manipulate log data. Therefore, protecting audit tools is necessary to prevent
unauthorized operation on audit information.

Operating systems providing tools to
interface with audit information will leverage user permissions and roles identifying the
user accessing the tools and the corresponding rights the user enjoys in order to make access
decisions regarding the access to audit tools.

Audit tools include, but are not limited to,
vendor-provided and open source audit tools needed to successfully view and manipulate
audit information system activity and records. Audit tools include custom queries and
report generators.

```
New:
```
Protecting audit information also includes identifying and protecting the tools used to view and manipulate log data. Therefore, protecting audit tools is necessary to prevent unauthorized operation on audit information. 
 
Operating systems providing tools to interface with audit information will leverage user permissions and roles identifying the user accessing the tools and the corresponding rights the user enjoys in order to make access decisions regarding the access to audit tools. 
 
Audit tools include, but are not limited to, vendor-provided and open source audit tools needed to successfully view and manipulate audit information system activity and records. Audit tools include custom queries and report generators.



```
---
SV-238302:
Old:
```
Protecting audit information also includes identifying and protecting the tools used to
view and manipulate log data. Therefore, protecting audit tools is necessary to prevent
unauthorized operation on audit information.

Operating systems providing tools to
interface with audit information will leverage user permissions and roles identifying the
user accessing the tools and the corresponding rights the user enjoys in order to make access
decisions regarding the access to audit tools.

Audit tools include, but are not limited to,
vendor-provided and open source audit tools needed to successfully view and manipulate
audit information system activity and records. Audit tools include custom queries and
report generators.

```
New:
```
Protecting audit information also includes identifying and protecting the tools used to view and manipulate log data. Therefore, protecting audit tools is necessary to prevent unauthorized operation on audit information. 
 
Operating systems providing tools to interface with audit information will leverage user permissions and roles identifying the user accessing the tools and the corresponding rights the user enjoys in order to make access decisions regarding the access to audit tools. 
 
Audit tools include, but are not limited to, vendor-provided and open source audit tools needed to successfully view and manipulate audit information system activity and records. Audit tools include custom queries and report generators.



```
---
SV-238303:
Old:
```
Protecting the integrity of the tools used for auditing purposes is a critical step toward
ensuring the integrity of audit information. Audit information includes all information
(e.g., audit records, audit settings, and audit reports) needed to successfully audit
information system activity.

Audit tools include, but are not limited to,
vendor-provided and open source audit tools needed to successfully view and manipulate
audit information system activity and records. Audit tools include custom queries and
report generators.

It is not uncommon for attackers to replace the audit tools or inject
code into the existing tools with the purpose of providing the capability to hide or erase
system activity from the audit logs.

To address this risk, audit tools must be
cryptographically signed in order to provide the capability to identify when the audit tools
have been modified, manipulated, or replaced. An example is a checksum hash of the file or
files.

```
New:
```
Protecting the integrity of the tools used for auditing purposes is a critical step toward ensuring the integrity of audit information. Audit information includes all information (e.g., audit records, audit settings, and audit reports) needed to successfully audit information system activity. 
 
Audit tools include, but are not limited to, vendor-provided and open source audit tools needed to successfully view and manipulate audit information system activity and records. Audit tools include custom queries and report generators. 
 
It is not uncommon for attackers to replace the audit tools or inject code into the existing tools with the purpose of providing the capability to hide or erase system activity from the audit logs. 
 
To address this risk, audit tools must be cryptographically signed in order to provide the capability to identify when the audit tools have been modified, manipulated, or replaced. An example is a checksum hash of the file or files.

```
---
SV-238304:
Old:
```
In certain situations, software applications/programs need to execute with elevated
privileges to perform required functions. However, if the privileges required for
execution are at a higher level than the privileges assigned to organizational users
invoking such applications/programs, those users are indirectly provided with greater
privileges than assigned by the organizations.

Some programs and processes are required
to operate at a higher privilege level and therefore should be excluded from the
organization-defined software list after review.

```
New:
```
In certain situations, software applications/programs need to execute with elevated privileges to perform required functions. However, if the privileges required for execution are at a higher level than the privileges assigned to organizational users invoking such applications/programs, those users are indirectly provided with greater privileges than assigned by the organizations. 
 
Some programs and processes are required to operate at a higher privilege level and therefore should be excluded from the organization-defined software list after review.



```
---
SV-238305:
Old:
```
In order to ensure operating systems have a sufficient storage capacity in which to write the
audit logs, operating systems need to be able to allocate audit record storage capacity.


The task of allocating audit record storage capacity is usually performed during initial
installation of the operating system.

```
New:
```
In order to ensure operating systems have a sufficient storage capacity in which to write the audit logs, operating systems need to be able to allocate audit record storage capacity. 
 
The task of allocating audit record storage capacity is usually performed during initial installation of the operating system.

```
---
SV-238306:
Old:
```
Information stored in one location is vulnerable to accidental or incidental deletion or
alteration.

Off-loading is a common process in information systems with limited audit
storage capacity.

```
New:
```
Information stored in one location is vulnerable to accidental or incidental deletion or alteration. 
 
Off-loading is a common process in information systems with limited audit storage capacity.



```
---
SV-238307:
Old:
```
If security personnel are not notified immediately when storage volume reaches 75%
utilization, they are unable to plan for audit record storage capacity expansion.

```
New:
```
If security personnel are not notified immediately when storage volume reaches 75% utilization, they are unable to plan for audit record storage capacity expansion.

```
---
SV-238308:
Old:
```
If time stamps are not consistently applied and there is no common time reference, it is
difficult to perform forensic analysis.

Time stamps generated by the operating system
include date and time. Time is commonly expressed in Coordinated Universal Time (UTC), a
modern continuation of Greenwich Mean Time (GMT), or local time with an offset from UTC.

```
New:
```
If time stamps are not consistently applied and there is no common time reference, it is difficult to perform forensic analysis. 
 
Time stamps generated by the operating system include date and time. Time is commonly expressed in Coordinated Universal Time (UTC), a modern continuation of Greenwich Mean Time (GMT), or local time with an offset from UTC.

```
---
SV-238309:
Old:
```
If events associated with nonlocal administrative access or diagnostic sessions are not
logged, a major tool for assessing and investigating attacks would not be available.

This
requirement addresses auditing-related issues associated with maintenance tools used
specifically for diagnostic and repair actions on organizational information systems.


Nonlocal maintenance and diagnostic activities are those activities conducted by
individuals communicating through a network, either an external network (e.g., the
internet) or an internal network. Local maintenance and diagnostic activities are those
activities carried out by individuals physically present at the information system or
information system component and not communicating across a network connection.

This
requirement applies to hardware/software diagnostic test equipment or tools. This
requirement does not cover hardware/software components that may support information
system maintenance, yet are a part of the system, for example, the software implementing
"ping," "ls," "ipconfig," or the hardware and software implementing the monitoring port of
an Ethernet switch.

```
New:
```
If events associated with nonlocal administrative access or diagnostic sessions are not logged, a major tool for assessing and investigating attacks would not be available. 
 
This requirement addresses auditing-related issues associated with maintenance tools used specifically for diagnostic and repair actions on organizational information systems. 
 
Nonlocal maintenance and diagnostic activities are those activities conducted by individuals communicating through a network, either an external network (e.g., the internet) or an internal network. Local maintenance and diagnostic activities are those activities carried out by individuals physically present at the information system or information system component and not communicating across a network connection. 
 
This requirement applies to hardware/software diagnostic test equipment or tools. This requirement does not cover hardware/software components that may support information system maintenance, yet are a part of the system, for example, the software implementing "ping," "ls," "ipconfig," or the hardware and software implementing the monitoring port of an Ethernet switch.



```
---
SV-238310:
Old:
```
Without generating audit records that are specific to the security and mission needs of the
organization, it would be difficult to establish, correlate, and investigate the events
relating to an incident or identify those responsible for one.

Audit records can be
generated from various components within the information system (e.g., module or policy
filter).

The system call rules are loaded into a matching engine that intercepts each
syscall that all programs on the system makes. Therefore, it is very important to only use
syscall rules when absolutely necessary since these affect performance. The more rules, the
bigger the performance hit. The performance is helped, though, by combining syscalls into
one rule whenever possible.

```
New:
```
Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. 
 
Audit records can be generated from various components within the information system (e.g., module or policy filter).

The system call rules are loaded into a matching engine that intercepts each syscall that all programs on the system makes. Therefore, it is very important to only use syscall rules when absolutely necessary since these affect performance. The more rules, the bigger the performance hit. The performance is helped, though, by combining syscalls into one rule whenever possible.

```
---
SV-238315:
Old:
```
Without generating audit records that are specific to the security and mission needs of the
organization, it would be difficult to establish, correlate, and investigate the events
relating to an incident or identify those responsible for one.

Audit records can be
generated from various components within the information system (e.g., module or policy
filter).

```
New:
```
Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. 
 
Audit records can be generated from various components within the information system (e.g., module or policy filter).

```
---
SV-238316:
Old:
```
Without generating audit records that are specific to the security and mission needs of the
organization, it would be difficult to establish, correlate, and investigate the events
relating to an incident or identify those responsible for one.

Audit records can be
generated from various components within the information system (e.g., module or policy
filter).

```
New:
```
Without generating audit records specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. 
 
Audit records can be generated from various components within the information system (e.g., module or policy filter).

```
---
SV-238317:
Old:
```
Without generating audit records that are specific to the security and mission needs of the
organization, it would be difficult to establish, correlate, and investigate the events
relating to an incident or identify those responsible for one.

Audit records can be
generated from various components within the information system (e.g., module or policy
filter).

```
New:
```
Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. 
 
Audit records can be generated from various components within the information system (e.g., module or policy filter).

```
---
SV-238318:
Old:
```
Without generating audit records that are specific to the security and mission needs of the
organization, it would be difficult to establish, correlate, and investigate the events
relating to an incident or identify those responsible for one.

Audit records can be
generated from various components within the information system (e.g., module or policy
filter).

```
New:
```
Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. 
 
Audit records can be generated from various components within the information system (e.g., module or policy filter).

```
---
SV-238319:
Old:
```
Without generating audit records that are specific to the security and mission needs of the
organization, it would be difficult to establish, correlate, and investigate the events
relating to an incident or identify those responsible for one.

Audit records can be
generated from various components within the information system (e.g., module or policy
filter).

```
New:
```
Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. 
 
Audit records can be generated from various components within the information system (e.g., module or policy filter).

```
---
SV-238320:
Old:
```
Without generating audit records that are specific to the security and mission needs of the
organization, it would be difficult to establish, correlate, and investigate the events
relating to an incident or identify those responsible for one.

Audit records can be
generated from various components within the information system (e.g., module or policy
filter).

```
New:
```
Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. 
 
Audit records can be generated from various components within the information system (e.g., module or policy filter).

```
---
SV-238321:
Old:
```
Information stored in one location is vulnerable to accidental or incidental deletion or
alteration.

Offloading is a common process in information systems with limited audit
storage capacity.

```
New:
```
Information stored in one location is vulnerable to accidental or incidental deletion or alteration. 
 
Offloading is a common process in information systems with limited audit storage capacity.

```
---
SV-238323:
Old:
```
The Ubuntu operating system management includes the ability to control the number of users
and user sessions that utilize an operating system. Limiting the number of allowed users and
sessions per user is helpful in reducing the risks related to DoS attacks.

This requirement
addresses concurrent sessions for information system accounts and does not address
concurrent sessions by single users via multiple system accounts. The maximum number of
concurrent sessions should be defined based upon mission needs and the operational
environment for each system.

```
New:
```
The Ubuntu operating system management includes the ability to control the number of users and user sessions that utilize an operating system. Limiting the number of allowed users and sessions per user is helpful in reducing the risks related to DoS attacks. 
 
This requirement addresses concurrent sessions for information system accounts and does not address concurrent sessions by single users via multiple system accounts. The maximum number of concurrent sessions should be defined based upon mission needs and the operational environment for each system.

```
---
SV-238324:
Old:
```
Remote access services, such as those providing remote access to network devices and
information systems, which lack automated monitoring capabilities, increase risk and make
remote user access management difficult at best.

Remote access is access to DoD nonpublic
information systems by an authorized user (or an information system) communicating through
an external, non-organization-controlled network. Remote access methods include, for
example, dial-up, broadband, and wireless.

Automated monitoring of remote access
sessions allows organizations to detect cyber attacks and also ensure ongoing compliance
with remote access policies by auditing connection activities of remote access
capabilities, such as Remote Desktop Protocol (RDP), on a variety of information system
components (e.g., servers, workstations, notebook computers, smartphones, and tablets).

```
New:
```
Remote access services, such as those providing remote access to network devices and information systems, which lack automated monitoring capabilities, increase risk and make remote user access management difficult at best. 
 
Remote access is access to DoD nonpublic information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless. 
 
Automated monitoring of remote access sessions allows organizations to detect cyber attacks and also ensure ongoing compliance with remote access policies by auditing connection activities of remote access capabilities, such as Remote Desktop Protocol (RDP), on a variety of information system components (e.g., servers, workstations, notebook computers, smartphones, and tablets).

```
---
SV-238325:
Old:
```
Passwords need to be protected at all times, and encryption is the standard method for
protecting passwords. If passwords are not encrypted, they can be plainly read (i.e., clear
text) and easily compromised.

```
New:
```
Passwords need to be protected at all times, and encryption is the standard method for protecting passwords. If passwords are not encrypted, they can be plainly read (i.e., clear text) and easily compromised.

```
---
SV-238326:
Old:
```
Passwords need to be protected at all times, and encryption is the standard method for
protecting passwords. If passwords are not encrypted, they can be plainly read (i.e., clear
text) and easily compromised.

```
New:
```
Passwords need to be protected at all times, and encryption is the standard method for protecting passwords. If passwords are not encrypted, they can be plainly read (i.e., clear text) and easily compromised.

```
---
SV-238327:
Old:
```
It is detrimental for operating systems to provide, or install by default, functionality
exceeding requirements or mission objectives. These unnecessary capabilities or services
are often overlooked and therefore may remain unsecured. They increase the risk to the
platform by providing additional attack vectors.

Operating systems are capable of
providing a wide variety of functions and services. Some of the functions and services,
provided by default, may not be necessary to support essential organizational operations
(e.g., key missions, functions).

Examples of non-essential capabilities include, but
are not limited to, games, software packages, tools, and demonstration software, not
related to requirements or providing a wide array of functionality not required for every
mission, but which cannot be disabled.

```
New:
```
It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors. 
 
Operating systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions). 
 
Examples of non-essential capabilities include, but are not limited to, games, software packages, tools, and demonstration software, not related to requirements or providing a wide array of functionality not required for every mission, but which cannot be disabled.

```
---
SV-238328:
Old:
```
In order to prevent unauthorized connection of devices, unauthorized transfer of
information, or unauthorized tunneling (i.e., embedding of data types within data types),
organizations must disable or restrict unused or unnecessary physical and logical
ports/protocols on information systems.

Operating systems are capable of providing a
wide variety of functions and services. Some of the functions and services provided by
default may not be necessary to support essential organizational operations.
Additionally, it is sometimes convenient to provide multiple services from a single
component (e.g., VPN and IPS); however, doing so increases risk over limiting the services
provided by any one component.

To support the requirements and principles of least
functionality, the operating system must support the organizational requirements,
providing only essential capabilities and limiting the use of ports, protocols, and/or
services to only those required, authorized, and approved to conduct official business or to
address authorized quality of life issues.

```
New:
```
In order to prevent unauthorized connection of devices, unauthorized transfer of information, or unauthorized tunneling (i.e., embedding of data types within data types), organizations must disable or restrict unused or unnecessary physical and logical ports/protocols on information systems. 
 
Operating systems are capable of providing a wide variety of functions and services. Some of the functions and services provided by default may not be necessary to support essential organizational operations. Additionally, it is sometimes convenient to provide multiple services from a single component (e.g., VPN and IPS); however, doing so increases risk over limiting the services provided by any one component. 
 
To support the requirements and principles of least functionality, the operating system must support the organizational requirements, providing only essential capabilities and limiting the use of ports, protocols, and/or services to only those required, authorized, and approved to conduct official business or to address authorized quality of life issues.

```
---
SV-238329:
Old:
```
To assure individual accountability and prevent unauthorized access, organizational
users must be individually identified and authenticated.

A group authenticator is a
generic account used by multiple individuals. Use of a group authenticator alone does not
uniquely identify individual users. Examples of the group authenticator is the UNIX OS
"root" user account, the Windows "Administrator" account, the "sa" account, or a "helpdesk"
account.

For example, the UNIX and Windows operating systems offer a 'switch user'
capability allowing users to authenticate with their individual credentials and, when
needed, 'switch' to the administrator role. This method provides for unique individual
authentication prior to using a group authenticator.

Users (and any processes acting on
behalf of users) need to be uniquely identified and authenticated for all accesses other than
those accesses explicitly identified and documented by the organization, which outlines
specific user actions that can be performed on the operating system without identification
or authentication.

Requiring individuals to be authenticated with an individual
authenticator prior to using a group authenticator allows for traceability of actions, as
well as adding an additional level of protection of the actions that can be taken with group
account knowledge.

```
New:
```
To assure individual accountability and prevent unauthorized access, organizational users must be individually identified and authenticated. 
 
A group authenticator is a generic account used by multiple individuals. Use of a group authenticator alone does not uniquely identify individual users. Examples of the group authenticator is the UNIX OS "root" user account, the Windows "Administrator" account, the "sa" account, or a "helpdesk" account. 
 
For example, the UNIX and Windows operating systems offer a 'switch user' capability allowing users to authenticate with their individual credentials and, when needed, 'switch' to the administrator role. This method provides for unique individual authentication prior to using a group authenticator. 
 
Users (and any processes acting on behalf of users) need to be uniquely identified and authenticated for all accesses other than those accesses explicitly identified and documented by the organization, which outlines specific user actions that can be performed on the operating system without identification or authentication. 
 
Requiring individuals to be authenticated with an individual authenticator prior to using a group authenticator allows for traceability of actions, as well as adding an additional level of protection of the actions that can be taken with group account knowledge.

```
---
SV-238330:
Old:
```
Inactive identifiers pose a risk to systems and applications because attackers may exploit
an inactive identifier and potentially obtain undetected access to the system. Owners of
inactive accounts will not notice if unauthorized access to their user account has been
obtained.

Operating systems need to track periods of inactivity and disable application
identifiers after 35 days of inactivity.

```
New:
```
Inactive identifiers pose a risk to systems and applications because attackers may exploit an inactive identifier and potentially obtain undetected access to the system. Owners of inactive accounts will not notice if unauthorized access to their user account has been obtained. 
 
Operating systems need to track periods of inactivity and disable application identifiers after 35 days of inactivity.

```
---
SV-238331:
Old:
```
Emergency accounts are different from infrequently used accounts (i.e., local logon
accounts used by the organization's System Administrator
s when network or normal
logon/access is not available). Infrequently used accounts are not subject to automatic
termination dates.  Emergency accounts are accounts created in response to crisis
situations, usually for use by maintenance personnel. The automatic expiration or
disabling time period may be extended as needed until the crisis is resolved; however, it must
not be extended indefinitely. A permanent account should be established for privileged
users who need long-term maintenance accounts.

```
New:
```
Temporary accounts are privileged or nonprivileged accounts that are established during pressing circumstances, such as new software or hardware configuration or an incident response, where the need for prompt account activation requires bypassing normal account authorization procedures. If any inactive temporary accounts are left enabled on the system and are not either manually removed or automatically expired within 72 hours, the security posture of the system will be degraded and exposed to exploitation by unauthorized users or insider threat actors.

Temporary accounts are different from emergency accounts. Emergency accounts, also known as "last resort" or "break glass" accounts, are local logon accounts enabled on the system for emergency use by authorized system administrators to manage a system when standard logon methods are failing or not available. Emergency accounts are not subject to manual removal or scheduled expiration requirements.

The automatic expiration of temporary accounts may be extended as needed by the circumstances but it must not be extended indefinitely. A documented permanent account should be established for privileged users who need long-term maintenance accounts.

```
---
SV-238332:
Old:
```
Preventing unauthorized information transfers mitigates the risk of information,
including encrypted representations of information, produced by the actions of prior
users/roles (or the actions of processes acting on behalf of prior users/roles) from being
available to any current users/roles (or current processes) that obtain access to shared
system resources (e.g., registers, main memory, hard disks) after those resources have been
released back to information systems. The control of information in shared resources is also
commonly referred to as object reuse and residual information protection.

This
requirement generally applies to the design of an information technology product, but it can
also apply to the configuration of particular information system components that are, or
use, such products. This can be verified by acceptance/validation processes in DoD or other
government agencies.

There may be shared resources with configurable protections (e.g.,
files in storage) that may be assessed on specific information system components.

```
New:
```
Preventing unauthorized information transfers mitigates the risk of information, including encrypted representations of information, produced by the actions of prior users/roles (or the actions of processes acting on behalf of prior users/roles) from being available to any current users/roles (or current processes) that obtain access to shared system resources (e.g., registers, main memory, hard disks) after those resources have been released back to information systems. The control of information in shared resources is also commonly referred to as object reuse and residual information protection. 
 
This requirement generally applies to the design of an information technology product, but it can also apply to the configuration of particular information system components that are, or use, such products. This can be verified by acceptance/validation processes in DoD or other government agencies. 
 
There may be shared resources with configurable protections (e.g., files in storage) that may be assessed on specific information system components.

```
---
SV-238333:
Old:
```
DoS is a condition when a resource is not available for legitimate users. When this occurs, the
organization either cannot accomplish its mission or must operate at degraded capacity.


Managing excess capacity ensures that sufficient capacity is available to counter
flooding attacks. Employing increased capacity and service redundancy may reduce the
susceptibility to some DoS attacks. Managing excess capacity may include, for example,
establishing selected usage priorities, quotas, or partitioning.

```
New:
```
DoS is a condition when a resource is not available for legitimate users. When this occurs, the organization either cannot accomplish its mission or must operate at degraded capacity.  
 
Managing excess capacity ensures that sufficient capacity is available to counter flooding attacks. Employing increased capacity and service redundancy may reduce the susceptibility to some DoS attacks. Managing excess capacity may include, for example, establishing selected usage priorities, quotas, or partitioning.

```
---
SV-238334:
Old:
```
Kernel core dumps may contain the full contents of system memory at the time of the crash.
Kernel core dumps may consume a considerable amount of disk space and may result in denial of
service by exhausting the available space on the target file system partition.

```
New:
```
Kernel core dumps may contain the full contents of system memory at the time of the crash. Kernel core dumps may consume a considerable amount of disk space and may result in denial of service by exhausting the available space on the target file system partition.

```
---
SV-238335:
Old:
```
Information at rest refers to the state of information when it is located on a secondary
storage device (e.g., disk drive and tape drive, when used for backups) within an operating
system.

This requirement addresses protection of user-generated data, as well as
operating system-specific configuration data. Organizations may choose to employ
different mechanisms to achieve confidentiality and integrity protections, as
appropriate, in accordance with the security category and/or classification of the
information.

```
New:
```
Information at rest refers to the state of information when it is located on a secondary storage device (e.g., disk drive and tape drive, when used for backups) within an operating system. 
 
This requirement addresses protection of user-generated data, as well as operating system-specific configuration data. Organizations may choose to employ different mechanisms to achieve confidentiality and integrity protections, as appropriate, in accordance with the security category and/or classification of the information.

```
---
SV-238336:
Old:
```
Without the use of automated mechanisms to scan for security flaws on a continuous and/or
periodic basis, the operating system or other system components may remain vulnerable to the
exploits presented by undetected software flaws.

To support this requirement, the
operating system may have an integrated solution incorporating continuous scanning using
HBSS and periodic scanning using other tools, as specified in the requirement.

```
New:
```
Without the use of automated mechanisms to scan for security flaws on a continuous and/or periodic basis, the operating system or other system components may remain vulnerable to the exploits presented by undetected software flaws. 
 
To support this requirement, the operating system may have an integrated solution incorporating continuous scanning using HBSS and periodic scanning using other tools, as specified in the requirement.

```
---
SV-238337:
Old:
```
Any operating system providing too much information in error messages risks compromising
the data and security of the structure, and content of error messages needs to be carefully
considered by the organization.

Organizations carefully consider the
structure/content of error messages. The extent to which information systems are able to
identify and handle error conditions is guided by organizational policy and operational
requirements. Information that could be exploited by adversaries includes, for example,
erroneous logon attempts with passwords entered by mistake as the username,
mission/business information that can be derived from (if not stated explicitly by)
information recorded, and personal information, such as account numbers, social security
numbers, and credit card numbers.

```
New:
```
Any operating system providing too much information in error messages risks compromising the data and security of the structure, and content of error messages needs to be carefully considered by the organization. 
 
Organizations carefully consider the structure/content of error messages. The extent to which information systems are able to identify and handle error conditions is guided by organizational policy and operational requirements. Information that could be exploited by adversaries includes, for example, erroneous logon attempts with passwords entered by mistake as the username, mission/business information that can be derived from (if not stated explicitly by) information recorded, and personal information, such as account numbers, social security numbers, and credit card numbers.

The /var/log/btmp, /var/log/wtmp, and /var/log/lastlog files have group write and global read permissions to allow for the lastlog function to perform. Limiting the permissions beyond this configuration will result in the failure of functions that rely on the lastlog database.

```
---
SV-238338:
Old:
```
Only authorized personnel should be aware of errors and the details of the errors. Error
messages are an indicator of an organization's operational state or can identify the
operating system or platform. Additionally, Personally Identifiable Information (PII)
and operational information must not be revealed through error messages to unauthorized
personnel or their designated representatives.

The structure and content of error
messages must be carefully considered by the organization and development team. The extent
to which the information system is able to identify and handle error conditions is guided by
organizational policy and operational requirements.

```
New:
```
Only authorized personnel should be aware of errors and the details of the errors. Error messages are an indicator of an organization's operational state or can identify the operating system or platform. Additionally, Personally Identifiable Information (PII) and operational information must not be revealed through error messages to unauthorized personnel or their designated representatives. 
 
The structure and content of error messages must be carefully considered by the organization and development team. The extent to which the information system is able to identify and handle error conditions is guided by organizational policy and operational requirements.

```
---
SV-238339:
Old:
```
Only authorized personnel should be aware of errors and the details of the errors. Error
messages are an indicator of an organization's operational state or can identify the
operating system or platform. Additionally, Personally Identifiable Information (PII)
and operational information must not be revealed through error messages to unauthorized
personnel or their designated representatives.

The structure and content of error
messages must be carefully considered by the organization and development team. The extent
to which the information system is able to identify and handle error conditions is guided by
organizational policy and operational requirements.

```
New:
```
Only authorized personnel should be aware of errors and the details of the errors. Error messages are an indicator of an organization's operational state or can identify the operating system or platform. Additionally, Personally Identifiable Information (PII) and operational information must not be revealed through error messages to unauthorized personnel or their designated representatives. 
 
The structure and content of error messages must be carefully considered by the organization and development team. The extent to which the information system is able to identify and handle error conditions is guided by organizational policy and operational requirements.

```
---
SV-238340:
Old:
```
Only authorized personnel should be aware of errors and the details of the errors. Error
messages are an indicator of an organization's operational state or can identify the
operating system or platform. Additionally, Personally Identifiable Information (PII)
and operational information must not be revealed through error messages to unauthorized
personnel or their designated representatives.

The structure and content of error
messages must be carefully considered by the organization and development team. The extent
to which the information system is able to identify and handle error conditions is guided by
organizational policy and operational requirements.

```
New:
```
Only authorized personnel should be aware of errors and the details of the errors. Error messages are an indicator of an organization's operational state or can identify the operating system or platform. Additionally, personally identifiable information (PII) and operational information must not be revealed through error messages to unauthorized personnel or their designated representatives. 
 
The structure and content of error messages must be carefully considered by the organization and development team. The extent to which the information system is able to identify and handle error conditions is guided by organizational policy and operational requirements.

```
---
SV-238341:
Old:
```
Only authorized personnel should be aware of errors and the details of the errors. Error
messages are an indicator of an organization's operational state or can identify the
operating system or platform. Additionally, Personally Identifiable Information (PII)
and operational information must not be revealed through error messages to unauthorized
personnel or their designated representatives.

The structure and content of error
messages must be carefully considered by the organization and development team. The extent
to which the information system is able to identify and handle error conditions is guided by
organizational policy and operational requirements.

```
New:
```
Only authorized personnel should be aware of errors and the details of the errors. Error messages are an indicator of an organization's operational state or can identify the operating system or platform. Additionally, Personally Identifiable Information (PII) and operational information must not be revealed through error messages to unauthorized personnel or their designated representatives. 
 
The structure and content of error messages must be carefully considered by the organization and development team. The extent to which the information system is able to identify and handle error conditions is guided by organizational policy and operational requirements.

```
---
SV-238342:
Old:
```
Only authorized personnel should be aware of errors and the details of the errors. Error
messages are an indicator of an organization's operational state or can identify the
operating system or platform. Additionally, Personally Identifiable Information (PII)
and operational information must not be revealed through error messages to unauthorized
personnel or their designated representatives.

The structure and content of error
messages must be carefully considered by the organization and development team. The extent
to which the information system is able to identify and handle error conditions is guided by
organizational policy and operational requirements.

```
New:
```
Only authorized personnel should be aware of errors and the details of the errors. Error messages are an indicator of an organization's operational state or can identify the operating system or platform. Additionally, Personally Identifiable Information (PII) and operational information must not be revealed through error messages to unauthorized personnel or their designated representatives. 
 
The structure and content of error messages must be carefully considered by the organization and development team. The extent to which the information system is able to identify and handle error conditions is guided by organizational policy and operational requirements.

```
---
SV-238343:
Old:
```
Only authorized personnel should be aware of errors and the details of the errors. Error
messages are an indicator of an organization's operational state or can identify the
operating system or platform. Additionally, Personally Identifiable Information (PII)
and operational information must not be revealed through error messages to unauthorized
personnel or their designated representatives.

The structure and content of error
messages must be carefully considered by the organization and development team. The extent
to which the information system is able to identify and handle error conditions is guided by
organizational policy and operational requirements.

```
New:
```
Only authorized personnel should be aware of errors and the details of the errors. Error messages are an indicator of an organization's operational state or can identify the operating system or platform. Additionally, Personally Identifiable Information (PII) and operational information must not be revealed through error messages to unauthorized personnel or their designated representatives. 
 
The structure and content of error messages must be carefully considered by the organization and development team. The extent to which the information system is able to identify and handle error conditions is guided by organizational policy and operational requirements.

```
---
SV-238344:
Old:
```
Protecting audit information also includes identifying and protecting the tools used to
view and manipulate log data. Therefore, protecting audit tools is necessary to prevent
unauthorized operation on audit information.

Operating systems providing tools to
interface with audit information will leverage user permissions and roles identifying the
user accessing the tools and the corresponding rights the user has in order to make access
decisions regarding the deletion of audit tools.

Audit tools include, but are not limited
to, vendor-provided and open source audit tools needed to successfully view and manipulate
audit information system activity and records. Audit tools include custom queries and
report generators.

```
New:
```
Protecting audit information also includes identifying and protecting the tools used to view and manipulate log data. Therefore, protecting audit tools is necessary to prevent unauthorized operation on audit information. 
 
Operating systems providing tools to interface with audit information will leverage user permissions and roles identifying the user accessing the tools and the corresponding rights the user has in order to make access decisions regarding the deletion of audit tools. 
 
Audit tools include, but are not limited to, vendor-provided and open source audit tools needed to successfully view and manipulate audit information system activity and records. Audit tools include custom queries and report generators.

```
---
SV-238345:
Old:
```
Protecting audit information also includes identifying and protecting the tools used to
view and manipulate log data. Therefore, protecting audit tools is necessary to prevent
unauthorized operation on audit information.

Operating systems providing tools to
interface with audit information will leverage user permissions and roles identifying the
user accessing the tools and the corresponding rights the user has in order to make access
decisions regarding the deletion of audit tools.

Audit tools include, but are not limited
to, vendor-provided and open source audit tools needed to successfully view and manipulate
audit information system activity and records. Audit tools include custom queries and
report generators.

```
New:
```
Protecting audit information also includes identifying and protecting the tools used to view and manipulate log data. Therefore, protecting audit tools is necessary to prevent unauthorized operation on audit information. 
 
Operating systems providing tools to interface with audit information will leverage user permissions and roles identifying the user accessing the tools and the corresponding rights the user has in order to make access decisions regarding the deletion of audit tools. 
 
Audit tools include, but are not limited to, vendor-provided and open source audit tools needed to successfully view and manipulate audit information system activity and records. Audit tools include custom queries and report generators.

```
---
SV-238346:
Old:
```
Protecting audit information also includes identifying and protecting the tools used to
view and manipulate log data. Therefore, protecting audit tools is necessary to prevent
unauthorized operation on audit information.

Operating systems providing tools to
interface with audit information will leverage user permissions and roles identifying the
user accessing the tools and the corresponding rights the user has in order to make access
decisions regarding the deletion of audit tools.

Audit tools include, but are not limited
to, vendor-provided and open source audit tools needed to successfully view and manipulate
audit information system activity and records. Audit tools include custom queries and
report generators.

```
New:
```
Protecting audit information also includes identifying and protecting the tools used to view and manipulate log data. Therefore, protecting audit tools is necessary to prevent unauthorized operation on audit information. 
 
Operating systems providing tools to interface with audit information will leverage user permissions and roles identifying the user accessing the tools and the corresponding rights the user has in order to make access decisions regarding the deletion of audit tools. 
 
Audit tools include, but are not limited to, vendor-provided and open source audit tools needed to successfully view and manipulate audit information system activity and records. Audit tools include custom queries and report generators.

```
---
SV-238347:
Old:
```
If the operating system were to allow any user to make changes to software libraries, then
those changes might be implemented without undergoing the appropriate testing and
approvals that are part of a robust change management process.

This requirement applies to
operating systems with software libraries that are accessible and configurable, as in the
case of interpreted languages. Software libraries also include privileged programs which
execute with escalated privileges. Only qualified and authorized individuals must be
allowed to obtain access to information system components for purposes of initiating
changes, including upgrades and modifications.

```
New:
```
If the operating system were to allow any user to make changes to software libraries, then those changes might be implemented without undergoing the appropriate testing and approvals that are part of a robust change management process. 
 
This requirement applies to operating systems with software libraries that are accessible and configurable, as in the case of interpreted languages. Software libraries also include privileged programs which execute with escalated privileges. Only qualified and authorized individuals must be allowed to obtain access to information system components for purposes of initiating changes, including upgrades and modifications.

```
---
SV-238348:
Old:
```
If the operating system were to allow any user to make changes to software libraries, then
those changes might be implemented without undergoing the appropriate testing and
approvals that are part of a robust change management process.

This requirement applies to
operating systems with software libraries that are accessible and configurable, as in the
case of interpreted languages. Software libraries also include privileged programs which
execute with escalated privileges. Only qualified and authorized individuals must be
allowed to obtain access to information system components for purposes of initiating
changes, including upgrades and modifications.

```
New:
```
If the operating system were to allow any user to make changes to software libraries, then those changes might be implemented without undergoing the appropriate testing and approvals that are part of a robust change management process. 
 
This requirement applies to operating systems with software libraries that are accessible and configurable, as in the case of interpreted languages. Software libraries also include privileged programs which execute with escalated privileges. Only qualified and authorized individuals must be allowed to obtain access to information system components for purposes of initiating changes, including upgrades and modifications.

```
---
SV-238349:
Old:
```
If the operating system were to allow any user to make changes to software libraries, then
those changes might be implemented without undergoing the appropriate testing and
approvals that are part of a robust change management process.

This requirement applies to
operating systems with software libraries that are accessible and configurable, as in the
case of interpreted languages. Software libraries also include privileged programs which
execute with escalated privileges. Only qualified and authorized individuals must be
allowed to obtain access to information system components for purposes of initiating
changes, including upgrades and modifications.

```
New:
```
If the operating system were to allow any user to make changes to software libraries, then those changes might be implemented without undergoing the appropriate testing and approvals that are part of a robust change management process. 
 
This requirement applies to operating systems with software libraries that are accessible and configurable, as in the case of interpreted languages. Software libraries also include privileged programs which execute with escalated privileges. Only qualified and authorized individuals must be allowed to obtain access to information system components for purposes of initiating changes, including upgrades and modifications.

```
---
SV-238350:
Old:
```
If the operating system were to allow any user to make changes to software libraries, then
those changes might be implemented without undergoing the appropriate testing and
approvals that are part of a robust change management process.

This requirement applies to
operating systems with software libraries that are accessible and configurable, as in the
case of interpreted languages. Software libraries also include privileged programs which
execute with escalated privileges. Only qualified and authorized individuals must be
allowed to obtain access to information system components for purposes of initiating
changes, including upgrades and modifications.

```
New:
```
If the operating system were to allow any user to make changes to software libraries, then those changes might be implemented without undergoing the appropriate testing and approvals that are part of a robust change management process. 
 
This requirement applies to operating systems with software libraries that are accessible and configurable, as in the case of interpreted languages. Software libraries also include privileged programs which execute with escalated privileges. Only qualified and authorized individuals must be allowed to obtain access to information system components for purposes of initiating changes, including upgrades and modifications.

```
---
SV-238351:
Old:
```
If the operating system were to allow any user to make changes to software libraries, then
those changes might be implemented without undergoing the appropriate testing and
approvals that are part of a robust change management process.

This requirement applies to
operating systems with software libraries that are accessible and configurable, as in the
case of interpreted languages. Software libraries also include privileged programs which
execute with escalated privileges. Only qualified and authorized individuals must be
allowed to obtain access to information system components for purposes of initiating
changes, including upgrades and modifications.

```
New:
```
If the operating system were to allow any user to make changes to software libraries, then those changes might be implemented without undergoing the appropriate testing and approvals that are part of a robust change management process. 
 
This requirement applies to operating systems with software libraries that are accessible and configurable, as in the case of interpreted languages. Software libraries also include privileged programs which execute with escalated privileges. Only qualified and authorized individuals must be allowed to obtain access to information system components for purposes of initiating changes, including upgrades and modifications.

```
---
SV-238352:
Old:
```
If the operating system were to allow any user to make changes to software libraries, then
those changes might be implemented without undergoing the appropriate testing and
approvals that are part of a robust change management process.

This requirement applies to
operating systems with software libraries that are accessible and configurable, as in the
case of interpreted languages. Software libraries also include privileged programs which
execute with escalated privileges. Only qualified and authorized individuals must be
allowed to obtain access to information system components for purposes of initiating
changes, including upgrades and modifications.

```
New:
```
If the operating system were to allow any user to make changes to software libraries, then those changes might be implemented without undergoing the appropriate testing and approvals that are part of a robust change management process. 
 
This requirement applies to operating systems with software libraries that are accessible and configurable, as in the case of interpreted languages. Software libraries also include privileged programs which execute with escalated privileges. Only qualified and authorized individuals must be allowed to obtain access to information system components for purposes of initiating changes, including upgrades and modifications.

```
---
SV-238353:
Old:
```
Failure to a known state can address safety or security in accordance with the
mission/business needs of the organization. Failure to a known secure state helps prevent a
loss of confidentiality, integrity, or availability in the event of a failure of the
information system or a component of the system.

Preserving operating system state
information helps to facilitate operating system restart and return to the operational mode
of the organization with least disruption to mission/business processes.

```
New:
```
Failure to a known state can address safety or security in accordance with the mission/business needs of the organization. Failure to a known secure state helps prevent a loss of confidentiality, integrity, or availability in the event of a failure of the information system or a component of the system.  
 
Preserving operating system state information helps to facilitate operating system restart and return to the operational mode of the organization with least disruption to mission/business processes.

```
---
SV-238354:
Old:
```
Remote access services, such as those providing remote access to network devices and
information systems, which lack automated control capabilities, increase risk and make
remote user access management difficult at best.

Remote access is access to DoD nonpublic
information systems by an authorized user (or an information system) communicating through
an external, non-organization-controlled network. Remote access methods include, for
example, dial-up, broadband, and wireless.

Ubuntu operating system functionality
(e.g., RDP) must be capable of taking enforcement action if the audit reveals unauthorized
activity. Automated control of remote access sessions allows organizations to ensure
ongoing compliance with remote access policies by enforcing connection rules of remote
access applications on a variety of information system components (e.g., servers,
workstations, notebook computers, smartphones, and tablets).

```
New:
```
Remote access services, such as those providing remote access to network devices and information systems, which lack automated control capabilities, increase risk and make remote user access management difficult at best. 
 
Remote access is access to DoD nonpublic information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless. 
 
Ubuntu operating system functionality (e.g., RDP) must be capable of taking enforcement action if the audit reveals unauthorized activity. Automated control of remote access sessions allows organizations to ensure ongoing compliance with remote access policies by enforcing connection rules of remote access applications on a variety of information system components (e.g., servers, workstations, notebook computers, smartphones, and tablets).

```
---
SV-238355:
Old:
```
Remote access services, such as those providing remote access to network devices and
information systems, which lack automated control capabilities, increase risk and make
remote user access management difficult at best.

Remote access is access to DoD nonpublic
information systems by an authorized user (or an information system) communicating through
an external, non-organization-controlled network. Remote access methods include, for
example, dial-up, broadband, and wireless.

Ubuntu operating system functionality
(e.g., RDP) must be capable of taking enforcement action if the audit reveals unauthorized
activity. Automated control of remote access sessions allows organizations to ensure
ongoing compliance with remote access policies by enforcing connection rules of remote
access applications on a variety of information system components (e.g., servers,
workstations, notebook computers, smartphones, and tablets).

```
New:
```
Remote access services, such as those providing remote access to network devices and information systems, which lack automated control capabilities, increase risk and make remote user access management difficult at best. 
 
Remote access is access to DoD nonpublic information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless. 
 
Ubuntu operating system functionality (e.g., RDP) must be capable of taking enforcement action if the audit reveals unauthorized activity. Automated control of remote access sessions allows organizations to ensure ongoing compliance with remote access policies by enforcing connection rules of remote access applications on a variety of information system components (e.g., servers, workstations, notebook computers, smartphones, and tablets).

```
---
SV-238356:
Old:
```
Inaccurate time stamps make it more difficult to correlate events and can lead to an
inaccurate analysis. Determining the correct time a particular event occurred on a system is
critical when conducting forensic analysis and investigating system events. Sources
outside the configured acceptable allowance (drift) may be inaccurate.

Synchronizing
internal information system clocks provides uniformity of time stamps for information
systems with multiple system clocks and systems connected over a network.

Organizations
should consider endpoints that may not have regular access to the authoritative time server
(e.g., mobile, teleworking, and tactical endpoints).

```
New:
```
Inaccurate time stamps make it more difficult to correlate events and can lead to an inaccurate analysis. Determining the correct time a particular event occurred on a system is critical when conducting forensic analysis and investigating system events. Sources outside the configured acceptable allowance (drift) may be inaccurate. 
 
Synchronizing internal information system clocks provides uniformity of time stamps for information systems with multiple system clocks and systems connected over a network. 
 
Organizations should consider endpoints that may not have regular access to the authoritative time server (e.g., mobile, teleworking, and tactical endpoints).

```
---
SV-238357:
Old:
```
Inaccurate time stamps make it more difficult to correlate events and can lead to an
inaccurate analysis. Determining the correct time a particular event occurred on a system is
critical when conducting forensic analysis and investigating system events.


Synchronizing internal information system clocks provides uniformity of time stamps for
information systems with multiple system clocks and systems connected over a network.
Organizations should consider setting time periods for different types of systems (e.g.,
financial, legal, or mission-critical systems).

Organizations should also consider
endpoints that may not have regular access to the authoritative time server (e.g., mobile,
teleworking, and tactical endpoints). This requirement is related to the comparison done
every 24 hours in SRG-OS-000355 because a comparison must be done in order to determine the
time difference.

```
New:
```
Inaccurate time stamps make it more difficult to correlate events and can lead to an inaccurate analysis. Determining the correct time a particular event occurred on a system is critical when conducting forensic analysis and investigating system events. 
 
Synchronizing internal information system clocks provides uniformity of time stamps for information systems with multiple system clocks and systems connected over a network. Organizations should consider setting time periods for different types of systems (e.g., financial, legal, or mission-critical systems). 
 
Organizations should also consider endpoints that may not have regular access to the authoritative time server (e.g., mobile, teleworking, and tactical endpoints). This requirement is related to the comparison done every 24 hours in SRG-OS-000355 because a comparison must be done in order to determine the time difference.

```
---
SV-238358:
Old:
```
Unauthorized changes to the baseline configuration could make the system vulnerable to
various attacks or allow unauthorized access to the operating system. Changes to operating
system configurations can have unintended side effects, some of which may be relevant to
security.

Detecting such changes and providing an automated response can help avoid
unintended, negative consequences that could ultimately affect the security state of the
operating system. The operating system's IMO/ISSO and SAs must be notified via email and/or
monitoring system trap when there is an unauthorized modification of a configuration item.

```
New:
```
Unauthorized changes to the baseline configuration could make the system vulnerable to various attacks or allow unauthorized access to the operating system. Changes to operating system configurations can have unintended side effects, some of which may be relevant to security. 
 
Detecting such changes and providing an automated response can help avoid unintended, negative consequences that could ultimately affect the security state of the operating system. The operating system's IMO/ISSO and SAs must be notified via email and/or monitoring system trap when there is an unauthorized modification of a configuration item.

```
---
SV-238359:
Old:
```
Changes to any software components can have significant effects on the overall security of
the operating system. This requirement ensures the software has not been tampered with and
that it has been provided by a trusted vendor.

Accordingly, patches, service packs, device
drivers, or operating system components must be signed with a certificate recognized and
approved by the organization.

Verifying the authenticity of the software prior to
installation validates the integrity of the patch or upgrade received from a vendor. This
ensures the software has not been tampered with and that it has been provided by a trusted
vendor. Self-signed certificates are disallowed by this requirement. The operating system
should not have to verify the software again. This requirement does not mandate DoD
certificates for this purpose; however, the certificate used to verify the software must be
from an approved CA.

```
New:
```
Changes to any software components can have significant effects on the overall security of the operating system. This requirement ensures the software has not been tampered with and that it has been provided by a trusted vendor. 
 
Accordingly, patches, service packs, device drivers, or operating system components must be signed with a certificate recognized and approved by the organization. 
 
Verifying the authenticity of the software prior to installation validates the integrity of the patch or upgrade received from a vendor. This ensures the software has not been tampered with and that it has been provided by a trusted vendor. Self-signed certificates are disallowed by this requirement. The operating system should not have to verify the software again. This requirement does not mandate DoD certificates for this purpose; however, the certificate used to verify the software must be from an approved CA.

```
---
SV-238360:
Old:
```
Control of program execution is a mechanism used to prevent execution of unauthorized
programs. Some operating systems may provide a capability that runs counter to the mission or
provides users with functionality that exceeds mission requirements. This includes
functions and services installed at the operating system-level.

Some of the programs,
installed by default, may be harmful or may not be necessary to support essential
organizational operations (e.g., key missions, functions). Removal of executable
programs is not always possible; therefore, establishing a method of preventing program
execution is critical to maintaining a secure system baseline.

Methods for complying with
this requirement include restricting execution of programs in certain environments, while
preventing execution in other environments; or limiting execution of certain program
functionality based on organization-defined criteria (e.g., privileges, subnets,
sandboxed environments, or roles).

```
New:
```
Control of program execution is a mechanism used to prevent execution of unauthorized programs. Some operating systems may provide a capability that runs counter to the mission or provides users with functionality that exceeds mission requirements. This includes functions and services installed at the operating system-level. 
 
Some of the programs, installed by default, may be harmful or may not be necessary to support essential organizational operations (e.g., key missions, functions). Removal of executable programs is not always possible; therefore, establishing a method of preventing program execution is critical to maintaining a secure system baseline. 
 
Methods for complying with this requirement include restricting execution of programs in certain environments, while preventing execution in other environments; or limiting execution of certain program functionality based on organization-defined criteria (e.g., privileges, subnets, sandboxed environments, or roles).



```
---
SV-238361:
Old:
```
Without providing this capability, an account may be created without a password.
Non-repudiation cannot be guaranteed once an account is created if a user is not forced to
change the temporary password upon initial logon.

Temporary passwords are typically used
to allow access when new accounts are created or passwords are changed. It is common practice
for administrators to create temporary passwords for user accounts which allow the users to
log on, yet force them to change the password once they have successfully authenticated.

```
New:
```
Without providing this capability, an account may be created without a password. Non-repudiation cannot be guaranteed once an account is created if a user is not forced to change the temporary password upon initial logon. 
 
Temporary passwords are typically used to allow access when new accounts are created or passwords are changed. It is common practice for administrators to create temporary passwords for user accounts which allow the users to log on, yet force them to change the password once they have successfully authenticated.

```
---
SV-238362:
Old:
```
If cached authentication information is out-of-date, the validity of the authentication
information may be questionable.

```
New:
```
If cached authentication information is out-of-date, the validity of the authentication information may be questionable.

```
---
SV-238363:
Old:
```
Use of weak or untested encryption algorithms undermines the purposes of utilizing
encryption to protect data. The operating system must implement cryptographic modules
adhering to the higher standards approved by the federal government since this provides
assurance they have been tested and validated.

```
New:
```
Use of weak or untested encryption algorithms undermines the purposes of utilizing encryption to protect data. The operating system must implement cryptographic modules adhering to the higher standards approved by the federal government since this provides assurance they have been tested and validated.



```
---
SV-238364:
Old:
```
Untrusted Certificate Authorities (CA) can issue certificates, but they may be issued by
organizations or individuals that seek to compromise DoD systems or by organizations with
insufficient security controls. If the CA used for verifying the certificate is not a
DoD-approved CA, trust of this CA has not been established.

The DoD will only accept
PKI-certificates obtained from a DoD-approved internal or external certificate
authority. Reliance on CAs for the establishment of secure sessions includes, for example,
the use of SSL/TLS certificates.

```
New:
```
Untrusted Certificate Authorities (CA) can issue certificates, but they may be issued by organizations or individuals that seek to compromise DoD systems or by organizations with insufficient security controls. If the CA used for verifying the certificate is not a DoD-approved CA, trust of this CA has not been established. 
 
The DoD will only accept PKI-certificates obtained from a DoD-approved internal or external certificate authority. Reliance on CAs for the establishment of secure sessions includes, for example, the use of SSL/TLS certificates.

```
---
SV-238365:
Old:
```
Operating systems handling data requiring "data at rest" protections must employ
cryptographic mechanisms to prevent unauthorized disclosure and modification of the
information at rest.

Selection of a cryptographic mechanism is based on the need to protect
the integrity of organizational information. The strength of the mechanism is commensurate
with the security category and/or classification of the information. Organizations have
the flexibility to either encrypt all information on storage devices (i.e., full disk
encryption) or encrypt specific data structures (e.g., files, records, or fields).

```
New:
```
Operating systems handling data requiring "data at rest" protections must employ cryptographic mechanisms to prevent unauthorized disclosure and modification of the information at rest. 
 
Selection of a cryptographic mechanism is based on the need to protect the integrity of organizational information. The strength of the mechanism is commensurate with the security category and/or classification of the information. Organizations have the flexibility to either encrypt all information on storage devices (i.e., full disk encryption) or encrypt specific data structures (e.g., files, records, or fields).

```
---
SV-238366:
Old:
```
Operating systems handling data requiring "data at rest" protections must employ
cryptographic mechanisms to prevent unauthorized disclosure and modification of the
information at rest.

Selection of a cryptographic mechanism is based on the need to protect
the integrity of organizational information. The strength of the mechanism is commensurate
with the security category and/or classification of the information. Organizations have
the flexibility to either encrypt all information on storage devices (i.e., full disk
encryption) or encrypt specific data structures (e.g., files, records, or fields).

```
New:
```
Operating systems handling data requiring "data at rest" protections must employ cryptographic mechanisms to prevent unauthorized disclosure and modification of the information at rest. 
 
Selection of a cryptographic mechanism is based on the need to protect the integrity of organizational information. The strength of the mechanism is commensurate with the security category and/or classification of the information. Organizations have the flexibility to either encrypt all information on storage devices (i.e., full disk encryption) or encrypt specific data structures (e.g., files, records, or fields).

```
---
SV-238367:
Old:
```
Denial of service (DoS) is a condition when a resource is not available for legitimate users.
When this occurs, the organization either cannot accomplish its mission or must operate at
degraded capacity.

This requirement addresses the configuration of the operating system
to mitigate the impact of DoS attacks that have occurred or are ongoing on system
availability. For each system, known and potential DoS attacks must be identified and
solutions for each type implemented. A variety of technologies exist to limit or, in some
cases, eliminate the effects of DoS attacks (e.g., limiting processes or establishing
memory partitions). Employing increased capacity and bandwidth, combined with service
redundancy, may reduce the susceptibility to some DoS attacks.

```
New:
```
Denial of service (DoS) is a condition when a resource is not available for legitimate users. When this occurs, the organization either cannot accomplish its mission or must operate at degraded capacity. 
 
This requirement addresses the configuration of the operating system to mitigate the impact of DoS attacks that have occurred or are ongoing on system availability. For each system, known and potential DoS attacks must be identified and solutions for each type implemented. A variety of technologies exist to limit or, in some cases, eliminate the effects of DoS attacks (e.g., limiting processes or establishing memory partitions). Employing increased capacity and bandwidth, combined with service redundancy, may reduce the susceptibility to some DoS attacks.

```
---
SV-238368:
Old:
```
Some adversaries launch attacks with the intent of executing code in non-executable regions
of memory or in memory locations that are prohibited. Security safeguards employed to
protect memory include, for example, data execution prevention and address space layout
randomization. Data execution prevention safeguards can either be hardware-enforced or
software-enforced with hardware providing the greater strength of mechanism.

Examples
of attacks are buffer overflow attacks.

```
New:
```
Some adversaries launch attacks with the intent of executing code in nonexecutable regions of memory or in memory locations that are prohibited. Security safeguards employed to protect memory include, for example, data execution prevention and address space layout randomization. Data execution prevention safeguards can either be hardware-enforced or software-enforced with hardware providing the greater strength of mechanism. 
 
Examples of attacks are buffer overflow attacks.

```
---
SV-238369:
Old:
```
Some adversaries launch attacks with the intent of executing code in non-executable regions
of memory or in memory locations that are prohibited. Security safeguards employed to
protect memory include, for example, data execution prevention and address space layout
randomization. Data execution prevention safeguards can either be hardware-enforced or
software-enforced with hardware providing the greater strength of mechanism.

Examples
of attacks are buffer overflow attacks.

```
New:
```
Some adversaries launch attacks with the intent of executing code in non-executable regions of memory or in memory locations that are prohibited. Security safeguards employed to protect memory include, for example, data execution prevention and address space layout randomization. Data execution prevention safeguards can either be hardware-enforced or software-enforced with hardware providing the greater strength of mechanism. 
 
Examples of attacks are buffer overflow attacks.

```
---
SV-238370:
Old:
```
Previous versions of software components that are not removed from the information system
after updates have been installed may be exploited by adversaries. Some information
technology products may remove older versions of software automatically from the
information system.

```
New:
```
Previous versions of software components that are not removed from the information system after updates have been installed may be exploited by adversaries. Some information technology products may remove older versions of software automatically from the information system.

```
---
SV-238371:
Old:
```
Without verification of the security functions, security functions may not operate
correctly and the failure may go unnoticed. Security function is defined as the hardware,
software, and/or firmware of the information system responsible for enforcing the system
security policy and supporting the isolation of code and data on which the protection is
based. Security functionality includes, but is not limited to, establishing system
accounts, configuring access authorizations (i.e., permissions, privileges), setting
events to be audited, and setting intrusion detection parameters.

This requirement
applies to the Ubuntu operating system performing security function verification/testing
and/or systems and environments that require this functionality.

```
New:
```
Without verification of the security functions, security functions may not operate correctly and the failure may go unnoticed. Security function is defined as the hardware, software, and/or firmware of the information system responsible for enforcing the system security policy and supporting the isolation of code and data on which the protection is based. Security functionality includes, but is not limited to, establishing system accounts, configuring access authorizations (i.e., permissions, privileges), setting events to be audited, and setting intrusion detection parameters. 
 
This requirement applies to the Ubuntu operating system performing security function verification/testing and/or systems and environments that require this functionality.

```
---
SV-238372:
Old:
```
Unauthorized changes to the baseline configuration could make the system vulnerable to
various attacks or allow unauthorized access to the Ubuntu operating system. Changes to
Ubuntu operating system configurations can have unintended side effects, some of which may
be relevant to security.

Detecting such changes and providing an automated response can
help avoid unintended, negative consequences that could ultimately affect the security
state of the Ubuntu operating system. The Ubuntu operating system's IMO/ISSO and SAs must be
notified via email and/or monitoring system trap when there is an unauthorized modification
of a configuration item.

```
New:
```
Unauthorized changes to the baseline configuration could make the system vulnerable to various attacks or allow unauthorized access to the Ubuntu operating system. Changes to Ubuntu operating system configurations can have unintended side effects, some of which may be relevant to security. 
 
Detecting such changes and providing an automated response can help avoid unintended, negative consequences that could ultimately affect the security state of the Ubuntu operating system. The Ubuntu operating system's IMO/ISSO and SAs must be notified via email and/or monitoring system trap when there is an unauthorized modification of a configuration item.

```
---
SV-238373:
Old:
```
Configuration settings are the set of parameters that can be changed in hardware, software,
or firmware components of the system that affect the security posture and/or functionality
of the system. Security-related parameters are those parameters impacting the security
state of the system, including the parameters required to satisfy other security control
requirements. Security-related parameters include, for example: registry settings;
account, file, directory permission settings; and settings for functions, ports,
protocols, services, and remote connections.

```
New:
```
Configuration settings are the set of parameters that can be changed in hardware, software, or firmware components of the system that affect the security posture and/or functionality of the system. Security-related parameters are those parameters impacting the security state of the system, including the parameters required to satisfy other security control requirements. Security-related parameters include, for example: registry settings; account, file, directory permission settings; and settings for functions, ports, protocols, services, and remote connections.

```
---
SV-238374:
Old:
```
Firewalls protect computers from network attacks by blocking or limiting access to open
network ports. Application firewalls limit which applications are allowed to communicate
over the network.

```
New:
```
Firewalls protect computers from network attacks by blocking or limiting access to open network ports. Application firewalls limit which applications are allowed to communicate over the network.

```
---
SV-238376:
Old:
```
If the Ubuntu operating system were to allow any user to make changes to software libraries,
then those changes might be implemented without undergoing the appropriate testing and
approvals that are part of a robust change management process.

This requirement applies to
Ubuntu operating systems with software libraries that are accessible and configurable, as
in the case of interpreted languages. Software libraries also include privileged programs
which execute with escalated privileges. Only qualified and authorized individuals must be
allowed to obtain access to information system components for purposes of initiating
changes, including upgrades and modifications.

```
New:
```
If the Ubuntu operating system were to allow any user to make changes to software libraries, then those changes might be implemented without undergoing the appropriate testing and approvals that are part of a robust change management process. 
 
This requirement applies to Ubuntu operating systems with software libraries that are accessible and configurable, as in the case of interpreted languages. Software libraries also include privileged programs which execute with escalated privileges. Only qualified and authorized individuals must be allowed to obtain access to information system components for purposes of initiating changes, including upgrades and modifications.

```
---
SV-238377:
Old:
```
If the Ubuntu operating system were to allow any user to make changes to software libraries,
then those changes might be implemented without undergoing the appropriate testing and
approvals that are part of a robust change management process.

This requirement applies to
Ubuntu operating systems with software libraries that are accessible and configurable, as
in the case of interpreted languages. Software libraries also include privileged programs
which execute with escalated privileges. Only qualified and authorized individuals must be
allowed to obtain access to information system components for purposes of initiating
changes, including upgrades and modifications.

```
New:
```
If the Ubuntu operating system were to allow any user to make changes to software libraries, then those changes might be implemented without undergoing the appropriate testing and approvals that are part of a robust change management process. 
 
This requirement applies to Ubuntu operating systems with software libraries that are accessible and configurable, as in the case of interpreted languages. Software libraries also include privileged programs which execute with escalated privileges. Only qualified and authorized individuals must be allowed to obtain access to information system components for purposes of initiating changes, including upgrades and modifications.

```
---
SV-238378:
Old:
```
If the Ubuntu operating system were to allow any user to make changes to software libraries,
then those changes might be implemented without undergoing the appropriate testing and
approvals that are part of a robust change management process.

This requirement applies to
Ubuntu operating systems with software libraries that are accessible and configurable, as
in the case of interpreted languages. Software libraries also include privileged programs
which execute with escalated privileges. Only qualified and authorized individuals must be
allowed to obtain access to information system components for purposes of initiating
changes, including upgrades and modifications.

```
New:
```
If the Ubuntu operating system were to allow any user to make changes to software libraries, then those changes might be implemented without undergoing the appropriate testing and approvals that are part of a robust change management process. 
 
This requirement applies to Ubuntu operating systems with software libraries that are accessible and configurable, as in the case of interpreted languages. Software libraries also include privileged programs which execute with escalated privileges. Only qualified and authorized individuals must be allowed to obtain access to information system components for purposes of initiating changes, including upgrades and modifications.

```
---
SV-238379:
Old:
```
A locally logged-on user who presses Ctrl-Alt-Delete, when at the console, can reboot the
system. If accidentally pressed, as could happen in the case of a mixed OS environment, this
can create the risk of short-term loss of availability of systems due to unintentional
reboot. In the graphical environment, risk of unintentional reboot from the
Ctrl-Alt-Delete sequence is reduced because the user will be prompted before any action is
taken.

```
New:
```
A locally logged-on user who presses Ctrl-Alt-Delete, when at the console, can reboot the system. If accidentally pressed, as could happen in the case of a mixed OS environment, this can create the risk of short-term loss of availability of systems due to unintentional reboot. In the graphical environment, risk of unintentional reboot from the Ctrl-Alt-Delete sequence is reduced because the user will be prompted before any action is taken.

```
---
SV-238380:
Old:
```
A locally logged-on user who presses Ctrl-Alt-Delete, when at the console, can reboot the
system. If accidentally pressed, as could happen in the case of a mixed OS environment, this
can create the risk of short-term loss of availability of systems due to unintentional
reboot.

```
New:
```
A locally logged-on user who presses Ctrl-Alt-Delete, when at the console, can reboot the system. If accidentally pressed, as could happen in the case of a mixed OS environment, this can create the risk of short-term loss of availability of systems due to unintentional reboot.

```
---
SV-251503:
Old:
```
If an account has an empty password, anyone could log on and run commands with the privileges of
that account. Accounts with empty passwords should never be used in operational
environments.

```
New:
```
If an account has an empty password, anyone could log on and run commands with the privileges of that account. Accounts with empty passwords should never be used in operational environments.

```
---
SV-251504:
Old:
```
If an account has an empty password, anyone could log on and run commands with the privileges of
that account. Accounts with empty passwords should never be used in operational
environments.

```
New:
```
If an account has an empty password, anyone could log on and run commands with the privileges of that account. Accounts with empty passwords should never be used in operational environments.

```
---
SV-251505:
Old:
```
Without authenticating devices, unidentified or unknown devices may be introduced,
thereby facilitating malicious activity.

Peripherals include, but are not limited to,
such devices as flash drives, external storage, and printers.

```
New:
```
Without authenticating devices, unidentified or unknown devices may be introduced, thereby facilitating malicious activity.

Peripherals include, but are not limited to, such devices as flash drives, external storage, and printers.

```
---
SV-252704:
Old:
```
Without protection of communications with wireless peripherals, confidentiality and
integrity may be compromised because unprotected communications can be intercepted and
either read, altered, or used to compromise the operating system.

This requirement
applies to wireless peripheral technologies (e.g., wireless mice, keyboards, displays,
etc.) used with an operating system. Wireless peripherals (e.g., Wi-Fi/Bluetooth/IR
Keyboards, Mice, and Pointing Devices and Near Field Communications [NFC]) present a unique
challenge by creating an open, unsecured port on a computer. Wireless peripherals must meet
DoD requirements for wireless data transmission and be approved for use by the AO. Even though
some wireless peripherals, such as mice and pointing devices, do not ordinarily carry
information that need to be protected, modification of communications with these wireless
peripherals may be used to compromise the operating system. Communication paths outside the
physical protection of a controlled boundary are exposed to the possibility of interception
and modification.

Protecting the confidentiality and integrity of communications with
wireless peripherals can be accomplished by physical means (e.g., employing physical
barriers to wireless radio frequencies) or by logical means (e.g., employing cryptographic
techniques). If physical means of protection are employed, then logical means
(cryptography) do not have to be employed, and vice versa. If the wireless peripheral is only
passing telemetry data, encryption of the data may not be required.

```
New:
```
Without protection of communications with wireless peripherals, confidentiality and integrity may be compromised because unprotected communications can be intercepted and either read, altered, or used to compromise the operating system. 
 
This requirement applies to wireless peripheral technologies (e.g., wireless mice, keyboards, displays, etc.) used with an operating system. Wireless peripherals (e.g., Wi-Fi/Bluetooth/IR Keyboards, Mice, and Pointing Devices and Near Field Communications [NFC]) present a unique challenge by creating an open, unsecured port on a computer. Wireless peripherals must meet DoD requirements for wireless data transmission and be approved for use by the AO. Even though some wireless peripherals, such as mice and pointing devices, do not ordinarily carry information that need to be protected, modification of communications with these wireless peripherals may be used to compromise the operating system. Communication paths outside the physical protection of a controlled boundary are exposed to the possibility of interception and modification. 
 
Protecting the confidentiality and integrity of communications with wireless peripherals can be accomplished by physical means (e.g., employing physical barriers to wireless radio frequencies) or by logical means (e.g., employing cryptographic techniques). If physical means of protection are employed, then logical means (cryptography) do not have to be employed, and vice versa. If the wireless peripheral is only passing telemetry data, encryption of the data may not be required.

```
---
</details>