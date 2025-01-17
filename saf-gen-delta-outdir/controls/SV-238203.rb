control 'SV-238203' do
  title 'The Ubuntu operating system must enforce a 60-day maximum password lifetime restriction.
Passwords for new users must have a 60-day maximum password lifetime restriction. '
  desc 'Any password, no matter how complex, can eventually be cracked. Therefore, passwords need to
be changed periodically. If the operating system does not limit the lifetime of passwords and
force users to change their passwords, there is the risk that the operating system passwords
could be compromised.'
  desc 'check', 'Verify the Ubuntu operating system enforces a 60-day maximum password lifetime for new user
accounts by running the following command:

$ grep -i ^pass_max_days /etc/login.defs

PASS_MAX_DAYS    60

If the "PASS_MAX_DAYS" parameter value is less than "60" or is commented
out, this is a finding.'
  desc 'fix', 'Configure the Ubuntu operating system to enforce a 60-day maximum password lifetime.

Add
or modify the following line in the "/etc/login.defs" file:

PASS_MAX_DAYS    60'
  impact 0.3
  ref 'DPMS Target Canonical Ubuntu 20.04 LTS'
  tag severity: 'low '
  tag gtitle: 'SRG-OS-000076-GPOS-00044 '
  tag gid: 'V-238203 '
  tag rid: 'SV-238203r653784_rule '
  tag stig_id: 'UBTU-20-010008 '
  tag fix_id: 'F-41372r653783_fix '
  tag cci: ['CCI-000199']
  tag nist: ['IA-5 (1) (d)']
  tag 'host'
  tag 'container'

  describe login_defs do
    its('PASS_MAX_DAYS') { should cmp <= 60 }
  end
end
