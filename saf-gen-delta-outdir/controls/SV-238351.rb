control 'SV-238351' do
  title 'The Ubuntu operating system library files must be group-owned by root or a system account. '
  desc 'If the operating system were to allow any user to make changes to software libraries, then
those changes might be implemented without undergoing the appropriate testing and
approvals that are part of a robust change management process.

This requirement applies to
operating systems with software libraries that are accessible and configurable, as in the
case of interpreted languages. Software libraries also include privileged programs which
execute with escalated privileges. Only qualified and authorized individuals must be
allowed to obtain access to information system components for purposes of initiating
changes, including upgrades and modifications.'
  desc 'check', %q(Verify the system-wide library files contained in the directories "/lib", "/lib64", and
"/usr/lib" are group-owned by root, or a required system account, with the following
command:

$ sudo find /lib /usr/lib /lib64 ! -group root -type f -exec stat -c "%n %G" '{}' \;


If any system-wide shared library file is returned and is not group-owned by a required
system account, this is a finding.)
  desc 'fix', 'Configure the system library files to be protected from unauthorized access. Run the
following command, replacing "[FILE]" with any system command file not group-owned by
"root" or a required system account:

$ sudo chgrp root [FILE]'
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 20.04 LTS'
  tag severity: 'medium '
  tag gtitle: 'SRG-OS-000259-GPOS-00100 '
  tag gid: 'V-238351 '
  tag rid: 'SV-238351r832962_rule '
  tag stig_id: 'UBTU-20-010430 '
  tag fix_id: 'F-41520r832961_fix '
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
  tag 'host'
  tag 'container'

  library_files = if os.arch == 'x86_64'
                    command('find /lib /usr/lib /usr/lib32 /lib32 /lib64 ! \-group root \-type f').stdout.strip.split("\n").entries
                  else
                    command('find /lib /usr/lib /usr/lib32 /lib32 ! \-group root \-type f').stdout.strip.split("\n").entries
                  end

  if library_files.count > 0
    library_files.each do |lib_file|
      describe file(lib_file) do
        its('group') { should cmp 'root' }
      end
    end
  else
    describe 'Number of system-wide shared library files found that are NOT group-owned by root' do
      subject { library_files }
      its('count') { should eq 0 }
    end
  end
end
