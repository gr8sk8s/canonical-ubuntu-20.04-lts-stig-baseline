control 'SV-252704' do
  title 'The Ubuntu operating system must disable all wireless network adapters. '
  desc 'Without protection of communications with wireless peripherals, confidentiality and
integrity may be compromised because unprotected communications can be intercepted and
either read, altered, or used to compromise the operating system.

This requirement
applies to wireless peripheral technologies (e.g., wireless mice, keyboards, displays,
etc.) used with an operating system. Wireless peripherals (e.g., Wi-Fi/Bluetooth/IR
Keyboards, Mice, and Pointing Devices and Near Field Communications [NFC]) present a unique
challenge by creating an open, unsecured port on a computer. Wireless peripherals must meet
DoD requirements for wireless data transmission and be approved for use by the AO. Even though
some wireless peripherals, such as mice and pointing devices, do not ordinarily carry
information that need to be protected, modification of communications with these wireless
peripherals may be used to compromise the operating system. Communication paths outside the
physical protection of a controlled boundary are exposed to the possibility of interception
and modification.

Protecting the confidentiality and integrity of communications with
wireless peripherals can be accomplished by physical means (e.g., employing physical
barriers to wireless radio frequencies) or by logical means (e.g., employing cryptographic
techniques). If physical means of protection are employed, then logical means
(cryptography) do not have to be employed, and vice versa. If the wireless peripheral is only
passing telemetry data, encryption of the data may not be required.'
  desc 'check', 'Note: This requirement is Not Applicable for systems that do not have physical wireless
network radios.

Verify that there are no wireless interfaces configured on the system with
the following command:

$ ls -L -d /sys/class/net/*/wireless | xargs dirname | xargs
basename

If a wireless interface is configured and has not been documented and approved by
the ISSO, this is a finding.'
  desc 'fix', 'List all the wireless interfaces with the following command: 
 
$ ls -L -d /sys/class/net/*/wireless | xargs dirname | xargs basename 
 
For each interface, configure the system to disable wireless network interfaces with the following command: 
 
$ sudo ifdown <interface name> 
 
For each interface listed, find their respective module with the following command: 
 
$ basename $(readlink -f /sys/class/net/<interface name>/device/driver) 
 
where <interface name> must be substituted by the actual interface name. 
 
Create a file in the "/etc/modprobe.d" directory and for each module, add the following line: 
 
install <module name> /bin/true 
 
For each module from the system, execute the  following command to remove it: 
 
$ sudo modprobe -r <module name>'
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 20.04 LTS'
  tag severity: 'medium '
  tag gtitle: 'SRG-OS-000481-GPOS-00481 '
  tag gid: 'V-252704 '
  tag rid: 'SV-252704r916433_rule'
  tag stig_id: 'UBTU-20-010455 '
  tag fix_id: 'F-56110r819056_fix '
  tag cci: ['CCI-002418']
  tag nist: ['SC-8']
  tag 'host'
  tag 'container'

  describe command('ls -L -d /sys/class/net/*/wireless | xargs dirname | xargs basename') do
    its('stdout.lines') { should be_in input('approved_wireless_interfaces') }
  end
end
