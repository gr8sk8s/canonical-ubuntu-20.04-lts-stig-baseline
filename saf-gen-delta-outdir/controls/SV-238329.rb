control 'SV-238329' do
  title 'The Ubuntu operating system must prevent direct login into the root account. '
  desc %q(To assure individual accountability and prevent unauthorized access, organizational
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
account knowledge.)
  desc 'check', 'Verify the Ubuntu operating system prevents direct logins to the root account with the
following command:

$ sudo passwd -S root

root L 04/23/2020 0 99999 7 -1

If the output does
not contain "L" in the second field to indicate the account is locked, this is a finding.'
  desc 'fix', 'Configure the Ubuntu operating system to prevent direct logins to the root account by
performing the following operations:

$ sudo passwd -l root'
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 20.04 LTS'
  tag severity: 'medium '
  tag gtitle: 'SRG-OS-000109-GPOS-00056 '
  tag gid: 'V-238329 '
  tag rid: 'SV-238329r654162_rule '
  tag stig_id: 'UBTU-20-010408 '
  tag fix_id: 'F-41498r654161_fix '
  tag cci: ['CCI-000770']
  tag nist: ['IA-2 (5)']
  tag 'host'
  tag 'container'

  describe.one do
    describe shadow.where(user: 'root') do
      its('passwords.uniq.first') { should eq '!*' }
    end
  end
  describe command('passwd -S root').stdout.strip do
    it { should match(/^root\s+L\s+.*$/) }
  end
end
