control 'SV-238348' do
  title 'The Ubuntu operating system library directories must have mode 0755 or less permissive. '
  desc 'If the operating system were to allow any user to make changes to software libraries, then
those changes might be implemented without undergoing the appropriate testing and
approvals that are part of a robust change management process.

This requirement applies to
operating systems with software libraries that are accessible and configurable, as in the
case of interpreted languages. Software libraries also include privileged programs which
execute with escalated privileges. Only qualified and authorized individuals must be
allowed to obtain access to information system components for purposes of initiating
changes, including upgrades and modifications.'
  desc 'check', %q(Verify the system-wide shared library directories "/lib", "/lib64", and "/usr/lib have
mode 0755 or less permissive with the following command:

$ sudo find /lib /lib64 /usr/lib
-perm /022 -type d -exec stat -c "%n %a" '{}' \;

If any of the aforementioned directories are
found to be group-writable or world-writable, this is a finding.)
  desc 'fix', "Configure the shared library directories to be protected from unauthorized access. Run the
following command:

$ sudo find /lib /lib64 /usr/lib -perm /022 -type d -exec chmod 755 '{}'
\\;"
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 20.04 LTS'
  tag severity: 'medium '
  tag gtitle: 'SRG-OS-000259-GPOS-00100 '
  tag gid: 'V-238348 '
  tag rid: 'SV-238348r654219_rule '
  tag stig_id: 'UBTU-20-010427 '
  tag fix_id: 'F-41517r654218_fix '
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
  tag 'host'
  tag 'container'

  library_dirs = if os.arch == 'x86_64'
                   command('find /lib /lib32 lib64 /usr/lib /usr/lib32 -perm /022 -type d').stdout.strip.split("\n").entries
                 else
                   command('find /lib /usr/lib /usr/lib32 /lib32 -perm /022 -type d').stdout.strip.split("\n").entries
                 end

  if library_dirs.count > 0
    library_dirs.each do |lib_file|
      describe file(lib_file) do
        it { should_not be_more_permissive_than('0755') }
      end
    end
  else
    describe 'Number of system-wide shared library directories found that are less permissive than 0755' do
      subject { library_dirs }
      its('count') { should eq 0 }
    end
  end
end
