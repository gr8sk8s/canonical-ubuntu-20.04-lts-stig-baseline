control 'SV-238222' do
  title 'The Ubuntu operating system must enforce password complexity by requiring that at least one
lower-case character be used. '
  desc 'Use of a complex password helps to increase the time and resources required to compromise the
password. Password complexity, or strength, is a measure of the effectiveness of a password
in resisting attempts at guessing and brute-force attacks.

Password complexity is one
factor of several that determines how long it takes to crack a password. The more complex the
password, the greater the number of possible combinations that need to be tested before the
password is compromised.'
  desc 'check', 'Verify the Ubuntu operating system enforces password complexity by requiring that at least
one lower-case character be used.

Determine if the field "lcredit" is set in the
"/etc/security/pwquality.conf" file with the following command:

$ grep -i "lcredit"
/etc/security/pwquality.conf
lcredit=-1

If the "lcredit" parameter is greater than
"-1" or is commented out, this is a finding.'
  desc 'fix', 'Add or update the "/etc/security/pwquality.conf" file to contain the "lcredit" parameter:


lcredit=-1'
  impact 0.3
  ref 'DPMS Target Canonical Ubuntu 20.04 LTS'
  tag severity: 'low '
  tag gtitle: 'SRG-OS-000070-GPOS-00038 '
  tag gid: 'V-238222 '
  tag rid: 'SV-238222r653841_rule '
  tag stig_id: 'UBTU-20-010051 '
  tag fix_id: 'F-41391r653840_fix '
  tag cci: ['CCI-000193']
  tag nist: ['IA-5 (1) (a)']
  tag 'host'
  tag 'container'

  config_file = '/etc/security/pwquality.conf'
  config_file_exists = file(config_file).exist?

  if config_file_exists
    describe parse_config_file(config_file) do
      its('lcredit') { should cmp '-1' }
    end
  else
    describe(config_file + ' exists') do
      subject { config_file_exists }
      it { should be true }
    end
  end
end
