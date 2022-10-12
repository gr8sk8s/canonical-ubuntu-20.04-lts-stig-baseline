control "V-238336" do
  title "The Ubuntu operating system must deploy Endpoint Security for Linux Threat Prevention 
(ENSLTP). "
  desc "Without the use of automated mechanisms to scan for security flaws on a continuous and/or 
periodic basis, the operating system or other system components may remain vulnerable to the 
exploits presented by undetected software flaws. 
 
To support this requirement, the 
operating system may have an integrated solution incorporating continuous scanning using 
HBSS and periodic scanning using other tools, as specified in the requirement. "
  desc "check", "The Ubuntu operating system is not compliant with this requirement; hence, it is a finding. 
However, the severity level can be mitigated to a CAT III if the ENSLTP module is installed and 
running. 
 
Check that the \"mfetp\" package has been installed: 
 
# dpkg -l | grep mfetp 
 
If the 
\"mfetp\" package is not installed, this finding will remain as a CAT II. 
 
Check that the daemon 
is running: 
 
# /opt/McAfee/ens/tp/init/mfetpd-control.sh status 
 
If the daemon is not 
running, this finding will remain as a CAT II. "
  desc "fix", "The Ubuntu operating system is not compliant with this requirement; however, the severity 
level can be mitigated to a CAT III if the ENSLTP module is installed and running. 
 
Configure 
the Ubuntu operating system to use ENSLTP. 
 
Install the \"mfetp\" package: 
 
# sudo apt-get 
install mfetp "
  impact 0.3
  tag severity: "low "
  tag gtitle: "SRG-OS-000191-GPOS-00080 "
  tag gid: "V-238336 "
  tag rid: "SV-238336r654183_rule "
  tag stig_id: "UBTU-20-010415 "
  tag fix_id: "F-41505r654182_fix "
  tag cci: ["CCI-001233"]
  tag nist: ["SI-2 (2)"]
end