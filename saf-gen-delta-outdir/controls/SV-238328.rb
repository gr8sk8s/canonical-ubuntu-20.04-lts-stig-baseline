control 'SV-238328' do
  title 'The Ubuntu operating system must be configured to prohibit or restrict the use of functions,
ports, protocols, and/or services, as defined in the PPSM CAL and vulnerability
assessments. '
  desc 'In order to prevent unauthorized connection of devices, unauthorized transfer of
information, or unauthorized tunneling (i.e., embedding of data types within data types),
organizations must disable or restrict unused or unnecessary physical and logical
ports/protocols on information systems.

Operating systems are capable of providing a
wide variety of functions and services. Some of the functions and services provided by
default may not be necessary to support essential organizational operations.
Additionally, it is sometimes convenient to provide multiple services from a single
component (e.g., VPN and IPS); however, doing so increases risk over limiting the services
provided by any one component.

To support the requirements and principles of least
functionality, the operating system must support the organizational requirements,
providing only essential capabilities and limiting the use of ports, protocols, and/or
services to only those required, authorized, and approved to conduct official business or to
address authorized quality of life issues.'
  desc 'check', 'Verify the Ubuntu operating system is configured to prohibit or restrict the use of
functions, ports, protocols, and/or services as defined in the Ports, Protocols, and
Services Management (PPSM) Category Assignments List (CAL) and vulnerability
assessments.

Check the firewall configuration for any unnecessary or prohibited
functions, ports, protocols, and/or services by running the following command:

$ sudo ufw
show raw

Chain OUTPUT (policy ACCEPT)
target  prot opt sources    destination
Chain INPUT
(policy ACCEPT 1 packets, 40 bytes)
    pkts      bytes target     prot opt in     out     source               destination


Chain FORWARD (policy ACCEPT 0 packets, 0 bytes)
    pkts      bytes target     prot opt in     out     source
destination

Chain OUTPUT (policy ACCEPT 0 packets, 0 bytes)
    pkts      bytes target     prot opt in
out     source               destination

Ask the System Administrator
 for the site or program PPSM CLSA.
Verify the services allowed by the firewall match the PPSM CLSA.

If there are any additional
ports, protocols, or services that are not included in the PPSM CLSA, this is a finding.

If
there are any ports, protocols, or services that are prohibited by the PPSM CAL, this is a
finding.'
  desc 'fix', 'Add all ports, protocols, or services allowed by the PPSM CLSA by using the following command: 
 
$ sudo ufw allow <direction> <port/protocol/service> 
 
where the direction is "in" or "out" and the port is the one corresponding to the protocol  or service allowed. 
 
To deny access to ports, protocols, or services, use: 
 
$ sudo ufw deny <direction> <port/protocol/service>'
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 20.04 LTS'
  tag severity: 'medium '
  tag gtitle: 'SRG-OS-000096-GPOS-00050 '
  tag gid: 'V-238328 '
  tag rid: 'SV-238328r654159_rule '
  tag stig_id: 'UBTU-20-010407 '
  tag fix_id: 'F-41497r654158_fix '
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
  tag 'host'

  if virtualization.system.eql?('docker')
    impact 0.0
    describe 'Control not applicable to a container' do
      skip 'Control not applicable to a container'
    end
  else
    ufw_status = command('ufw status').stdout.strip.lines.first
    value = ufw_status.split(':')[1].strip

    describe 'UFW status' do
      subject { value }
      it { should cmp 'active' }
    end
    describe 'Status listings for any allowed services, ports, or applications must be documented with the organization' do
      skip 'Status listings checks must be preformed manually'
    end
  end
end
