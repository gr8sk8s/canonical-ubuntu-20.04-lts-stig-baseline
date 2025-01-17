control 'SV-238204' do
  title "Ubuntu operating systems when booted must require authentication upon booting into
single-user and maintenance modes. "
  desc "To mitigate the risk of unauthorized access to sensitive information by entities that have
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
information system. "
  desc 'check', "Run the following command to verify the encrypted password is set:

$ sudo grep -i password
/boot/grub/grub.cfg

password_pbkdf2 root
grub.pbkdf2.sha512.10000.MFU48934NJA87HF8NSD34493GDHF84NG

If the root password
entry does not begin with \"password_pbkdf2\", this is a finding. "
  desc 'fix', "Configure the system to require a password for authentication upon booting into single-user
and maintenance modes.

Generate an encrypted (grub) password for root with the following
command:

$ grub-mkpasswd-pbkdf2
Enter Password:
Reenter Password:
PBKDF2 hash of
your password is grub.pbkdf2.sha512.10000.MFU48934NJD84NF8NSD39993JDHF84NG

Using
the hash from the output, modify the \"/etc/grub.d/40_custom\" file with the following
command to add a boot password:

$ sudo sed -i '$i set
superusers=\\\"root\\\"\\npassword_pbkdf2 root &lt;hash&gt;' /etc/grub.d/40_custom


where &lt;hash&gt; is the hash generated by grub-mkpasswd-pbkdf2 command.

Generate an
updated \"grub.conf\" file with the new password by using the following command:

$ sudo
update-grub "
  impact 0.7
  tag severity: 'high '
  tag gtitle: 'SRG-OS-000080-GPOS-00048 '
  tag gid: 'V-238204 '
  tag rid: 'SV-238204r832936_rule '
  tag stig_id: 'UBTU-20-010009 '
  tag fix_id: 'F-41373r832935_fix '
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
  tag 'host', 'container'

  describe grub_conf('/boot/grub/grub.cfg') do
    its('password') { should match '^password_pbkdf2' }
  end
end
