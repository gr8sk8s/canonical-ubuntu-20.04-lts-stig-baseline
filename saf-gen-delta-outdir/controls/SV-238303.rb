control 'SV-238303' do
  title 'The Ubuntu operating system must use cryptographic mechanisms to protect the integrity of
audit tools. '
  desc 'Protecting the integrity of the tools used for auditing purposes is a critical step toward
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
files.'
  desc 'check', "Verify that Advanced Intrusion Detection Environment (AIDE) is properly configured to use
cryptographic mechanisms to protect the integrity of audit tools.

Check the selection
lines that AIDE is configured to add/check with the following command:

$ egrep
'(\\/sbin\\/(audit|au))' /etc/aide/aide.conf

/sbin/auditctl
p+i+n+u+g+s+b+acl+xattrs+sha512
/sbin/auditd p+i+n+u+g+s+b+acl+xattrs+sha512

/sbin/ausearch p+i+n+u+g+s+b+acl+xattrs+sha512
/sbin/aureport
p+i+n+u+g+s+b+acl+xattrs+sha512
/sbin/autrace p+i+n+u+g+s+b+acl+xattrs+sha512

/sbin/audispd p+i+n+u+g+s+b+acl+xattrs+sha512
/sbin/augenrules
p+i+n+u+g+s+b+acl+xattrs+sha512

If any of the seven audit tools do not have appropriate
selection lines, this is a finding."
  desc 'fix', 'Add or update the following selection lines for "/etc/aide/aide.conf" to protect the
integrity of the audit tools:

# Audit Tools
/sbin/auditctl
p+i+n+u+g+s+b+acl+xattrs+sha512
/sbin/auditd p+i+n+u+g+s+b+acl+xattrs+sha512

/sbin/ausearch p+i+n+u+g+s+b+acl+xattrs+sha512
/sbin/aureport
p+i+n+u+g+s+b+acl+xattrs+sha512
/sbin/autrace p+i+n+u+g+s+b+acl+xattrs+sha512

/sbin/audispd p+i+n+u+g+s+b+acl+xattrs+sha512
/sbin/augenrules
p+i+n+u+g+s+b+acl+xattrs+sha512'
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 20.04 LTS'
  tag severity: 'medium '
  tag gtitle: 'SRG-OS-000278-GPOS-00108 '
  tag gid: 'V-238303 '
  tag rid: 'SV-238303r877393_rule'
  tag stig_id: 'UBTU-20-010205 '
  tag fix_id: 'F-41472r654083_fix '
  tag cci: ['CCI-001496']
  tag nist: ['AU-9 (3)']
  tag 'host'

  if virtualization.system.eql?('docker')
    impact 0.0
    describe 'Control not applicable to a container' do
      skip 'Control not applicable to a container'
    end
  else
    aide_conf = aide_conf input('aide_conf_path')

    aide_conf_exists = aide_conf.exist?

    if aide_conf_exists
      describe aide_conf.where { selection_line == '/sbin/auditctl' } do
        its('rules') { should include %w(p i n u g s b acl xattrs sha512) }
      end

      describe aide_conf.where { selection_line == '/sbin/auditd' } do
        its('rules') { should include %w(p i n u g s b acl xattrs sha512) }
      end

      describe aide_conf.where { selection_line == '/sbin/ausearch' } do
        its('rules') { should include %w(p i n u g s b acl xattrs sha512) }
      end

      describe aide_conf.where { selection_line == '/sbin/aureport' } do
        its('rules') { should include %w(p i n u g s b acl xattrs sha512) }
      end

      describe aide_conf.where { selection_line == '/sbin/autrace' } do
        its('rules') { should include %w(p i n u g s b acl xattrs sha512) }
      end

      describe aide_conf.where { selection_line == '/sbin/audispd' } do
        its('rules') { should include %w(p i n u g s b acl xattrs sha512) }
      end

      describe aide_conf.where { selection_line == '/sbin/augenrules' } do
        its('rules') { should include %w(p i n u g s b acl xattrs sha512) }
      end
    else
      describe 'aide.conf file exists' do
        subject { aide_conf_exists }
        it { should be true }
      end
    end
  end
end
