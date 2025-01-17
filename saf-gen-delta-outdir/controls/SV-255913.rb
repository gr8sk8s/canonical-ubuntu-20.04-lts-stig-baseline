control 'SV-255913' do
  title 'The Ubuntu operating system must restrict access to the kernel message buffer.'
  desc 'Restricting access to the kernel message buffer limits access only to root. This prevents attackers from gaining additional system information as a nonprivileged user.'
  desc 'check', 'Verify the operating system is configured to restrict access to the kernel message buffer with the following commands:

     $ sudo sysctl kernel.dmesg_restrict
     kernel.dmesg_restrict = 1

If "kernel.dmesg_restrict" is not set to "1" or is missing, this is a finding.

Check that the configuration files are present to enable this kernel parameter:

     $ sudo grep -r kernel.dmesg_restrict /run/sysctl.d/* /etc/sysctl.d/* /usr/local/lib/sysctl.d/* /usr/lib/sysctl.d/* /lib/sysctl.d/* /etc/sysctl.conf 2> /dev/null
     /etc/sysctl.conf:kernel.dmesg_restrict = 1
     /etc/sysctl.d/99-sysctl.conf:kernel.dmesg_restrict = 1

If "kernel.dmesg_restrict" is not set to "1", is missing or commented out, this is a finding.

If conflicting results are returned, this is a finding.'
  desc 'fix', 'Configure the operating system to restrict access to the kernel message buffer.

Set the system to the required kernel parameter by adding or modifying the following line in /etc/sysctl.conf or a config file in the /etc/sysctl.d/ directory:

     kernel.dmesg_restrict = 1

Remove any configurations that conflict with the above from the following locations: 
     /run/sysctl.d/
     /etc/sysctl.d/
     /usr/local/lib/sysctl.d/
     /usr/lib/sysctl.d/
     /lib/sysctl.d/
     /etc/sysctl.conf

Reload settings from all system configuration files with the following command:

     $ sudo sysctl --system'
  impact 0.3
  ref 'DPMS Target Canonical Ubuntu 20.04 LTS'
  tag check_id: 'C-59590r880906_chk'
  tag severity: 'low'
  tag gid: 'V-255913'
  tag rid: 'SV-255913r880908_rule'
  tag stig_id: 'UBTU-20-010401'
  tag gtitle: 'SRG-OS-000138-GPOS-00069'
  tag fix_id: 'F-59533r880907_fix'
  tag 'documentable'
  tag cci: ['CCI-001090']
  tag nist: ['SC-4']
end
