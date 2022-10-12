control "V-238257" do
  title "The Ubuntu operating system must generate audit records for successful/unsuccessful uses 
of the ssh-keysign command. "
  desc "Without generating audit records that are specific to the security and mission needs of the 
organization, it would be difficult to establish, correlate, and investigate the events 
relating to an incident or identify those responsible for one. 
 
Audit records can be 
generated from various components within the information system (e.g., module or policy 
filter). "
  desc "check", "Verify the Ubuntu operating system generates an audit record upon successful/unsuccessful 
attempts to use the \"ssh-keysign\" command. 
 
Check the configured audit rules with the 
following commands: 
 
$ sudo auditctl -l | grep ssh-keysign 
 
-a always,exit -F 
path=/usr/lib/openssh/ssh-keysign -F perm=x -F auid&gt;=1000 -F auid!=-1 -k 
privileged-ssh 
 
If the command does not return lines that match the example or the lines are 
commented out, this is a finding. 
 
Note: The \"-k\" allows for specifying an arbitrary 
identifier, and the string after it does not need to match the example output above. "
  desc "fix", "Configure the audit system to generate an audit event for any successful/unsuccessful use of 
the \"ssh-keysign\" command.  
 
Add or update the following rules in the 
\"/etc/audit/rules.d/stig.rules\" file: 
 
-a always,exit -F 
path=/usr/lib/openssh/ssh-keysign -F perm=x -F auid&gt;=1000 -F auid!=4294967295 -k 
privileged-ssh 
 
To reload the rules file, issue the following command: 
 
$ sudo augenrules 
--load "
  impact 0.5
  tag severity: "medium "
  tag gtitle: "SRG-OS-000064-GPOS-00033 "
  tag gid: "V-238257 "
  tag rid: "SV-238257r653946_rule "
  tag stig_id: "UBTU-20-010141 "
  tag fix_id: "F-41426r653945_fix "
  tag cci: ["CCI-000172"]
  tag nist: ["AU-12 c"]
end