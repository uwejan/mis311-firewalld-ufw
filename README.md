![alt text](https://cdn.freelogovectors.net/wp-content/uploads/2017/04/ankara-yildirim-beyazit-universitesi_logo.png)

**ANKARA YILDIRIM BEYAZIT UNIVERSITY**

**MIS311 – INFORMATION SECURITY SYSTEMS DESIGN AND APPLICATIONS**

**Instructor: Dr. SAFA BURAK GÜRLEYEN**

**Student: Saddam UWEJAN**

![alt_text](https://icon2.cleanpng.com/20180519/ikr/kisspng-firewall-computer-icons-computer-network-clip-art-5b007791dd1517.0304465015267572659056.jpg)

**Introduction to Firewalls; firewalld && ufw**


**Repository contents;**

- Read me file. (general details, full report).
- Presentation. (basic introduction to firewalls, firewalld, ufw).
- Report. (useful links to manual pages, and other resources).

**Demo cmd;**

**Install firewalls;**

Centos; yum/dnf

```dnf install firewalld -y

systemctl status firewalld

systemctl enable firewalld

Allow http:

firewall-cmd --zone=public --add-service=http –permanent

systemctl restart firewalld
```

Ubuntu; apt/apt-get

```apt install ufw -y

systemctl status ufw

systemctl enable ufw

Allow http:

ufw allow http

systemctl restart ufw
```

**Contents;**

- Definitions.
- firewalld
- ufw
- Features.
- firewalld
- ufw

**Firewalld** ;

Firewalld provides a dynamically managed firewall with support for network/firewall zones that define the trust level of network connections or interfaces. It has support for IPv4, IPv6 firewall settings, ethernet bridges and IP sets. There is a separation of runtime and permanent configuration options. It also provides an interface for services or applications to add firewall rules directly.

## Benefits of using firewalld

Changes can be done immediately in the runtime environment. No restart of the service or daemon is needed.

With the firewalld D-Bus interface it is simple for services, applications and also users to adapt firewall settings. The interface is complete and is used for the firewall configuration tools firewall-cmd, firewall-config and firewall-applet.

The separation of the runtime and permanent configuration makes it possible to do evaulation and tests in runtime. The runtime configuration is only valid up to the next service reload and restart or to a system reboot. Then the permanent configuration will be loaded again. With the runtime environment it is possible to use runtime for settings that should only be active for a limited amount of time. If the runtime configuration has been used for evaluation, and it is complete and working, then it is possible to save this configuration to the permanent environment.

## Features

- Complete D-Bus API
- IPv4, IPv6, bridge and ipset support
- IPv4 and IPv6 NAT support
- Firewall zones
- Predefined list of zones, services and icmptypes
- Simple service, port, protocol, source port, masquerading, port forwarding, icmp filter, rich rule, interface and source address handlig in zones
- Simple service definition with ports, protocols, source ports, modules (netfilter helpers) and destination address handling
- Rich Language for more flexible and complex rules in zones
- Timed firewall rules in zones
- Simple log of denied packets
- Direct interface
- Lockdown: Whitelisting of applications that may modify the firewall
- Automatic loading of Linux kernel modules
- Integration with Puppet
- Command line clients for online and offline configuration
- Graphical configuration tool using gtk3
- Applet using Qt4

## Who is using it?

firewalld is used in the following Linux distributions as the default firewall management tool:

- RHEL 7 and newer
- CentOS 7 and newer
- Fedora 18 and newer
- SUSE 15 and newer
- OpenSUSE 15 and newer
- Available for several other distributions

Applications and libraries which support firewalld as a firewall management tool include:

- [NetworkManager](https://wiki.gnome.org/Projects/NetworkManager)
- [libvirt](http://libvirt.org/)
- [podman](https://podman.io/)
- [docker](http://docker.com/)(iptables backend only)
- [fail2ban](http://www.fail2ban.org/)

## Installing and Managing FirewallD

FirewallD is included by default with CentOS 7 but it&#39;s inactive. Controlling it is the same as with other systemd units.

1. To start the service and enable FirewallD on boot:

```
sudo systemctl start firewalldsudo systemctl enable firewalld
```

To stop and disable it:

```
sudo systemctl stop firewalldsudo systemctl disable firewalld
```

1. Check the firewall status. The output should say either `running` or `not running`.

```
sudo firewall-cmd --state
```

1. To view the status of the FirewallD daemon:

```
sudo systemctl status firewalld
```

Example output:

```
firewalld.service - firewalld - dynamic firewall daemonLoaded: loaded (/usr/lib/systemd/system/firewalld.service; enabled; vendor preset: enabled)Active: active (running) since Thu 2019-08-08 15:11:24 IST; 23h agoDocs: man:firewalld(1)Main PID: 2577 (firewalld)CGroup: /system.slice/firewalld.service└─2577 /usr/bin/python -Es /usr/sbin/firewalld --nofork --nopid
```

1. To reload a FirewallD configuration:

```
sudo firewall-cmd --reload
```

## Configuring FirewallD

Firewalld is configured with XML files. Except for very specific configurations, you won&#39;t have to deal with them and  **firewall-cmd**  should be used instead.

Configuration files are located in two directories:

- `/usr/lib/FirewallD` holds default configurations like default zones and common services. Avoid updating them because those files will be overwritten by each firewalld package update.
- `/etc/firewalld` holds system configuration files. These files will overwrite a default configuration.

### Configuration Sets

Firewalld uses two _configuration sets_: Runtime and Permanent. Runtime configuration changes are not retained on reboot or upon restarting FirewallD whereas permanent changes are not applied to a running system.

By default, `firewall-cmd` commands apply to runtime configuration but using the `--permanent` flag will establish a persistent configuration. To add and activate a permanent rule, you can use one of two methods.

1. Add the rule to both the permanent and runtime sets.

```
sudo firewall-cmd --zone=public --add-service=http --permanentsudo firewall-cmd --zone=public --add-service=http
```

1. Add the rule to the permanent set and reload FirewallD.

```
sudo firewall-cmd --zone=public --add-service=http --permanentsudo firewall-cmd --reload
```

&gt; **Note**

&gt; The reload command drops all runtime configurations and applies a permanent configuration. Because firewalld manages the ruleset dynamically, it won&#39;t break an existing connection and session.

### Firewall Zones

Zones are pre-constructed rulesets for various trust levels you would likely have for a given location or scenario (e.g. home, public, trusted, etc.). Different zones allow different network services and incoming traffic types while denying everything else. After enabling FirewallD for the first time, _Public_ will be the default zone.

Zones can also be applied to different network interfaces. For example, with separate interfaces for both an internal network and the Internet, you can allow DHCP on an internal zone but only HTTP and SSH on external zone. Any interface not explicitly set to a specific zone will be attached to the default zone.

To view the default zone:

```
sudo firewall-cmd --get-default-zone
```

To change the default zone:

```
sudo firewall-cmd --set-default-zone=internal
```

To see the zones used by your network interface(s):

```
sudo firewall-cmd --get-active-zones
```

Example output:

```
publicinterfaces: eth0
```

To get all configurations for a specific zone:

```
sudo firewall-cmd --zone=public --list-all
```

Example output:

```
public (active)target: defaulticmp-block-inversion: nointerfaces: eth0sources:services: ssh dhcpv6-client httpports: 12345/tcpprotocols:masquerade: noforward-ports:source-ports:icmp-blocks:rich rules:
```

To get all configurations for all zones:

```
sudo firewall-cmd --list-all-zones
```

Example output:

```
trustedtarget: ACCEPTicmp-block-inversion: nointerfaces:sources:services:ports:protocols:masquerade: noforward-ports:source-ports:icmp-blocks:rich rules:...worktarget: defaulticmp-block-inversion: nointerfaces:sources:services: ssh dhcpv6-clientports:protocols:masquerade: noforward-ports:source-ports:icmp-blocks:rich rules:
```

### Working with Services

FirewallD can allow traffic based on predefined rules for specific network services. You can create your own custom service rules and add them to any zone. The configuration files for the default supported services are located at `/usr/lib/firewalld/services` and user-created service files would be in `/etc/firewalld/services`.

To view the default available services:

```
sudo firewall-cmd --get-services
```

As an example, to enable or disable the HTTP service:

```
sudo firewall-cmd --zone=public --add-service=http --permanentsudo firewall-cmd --zone=public --remove-service=http --permanent
```

## Allowing or Denying an Arbitrary Port/Protocol

As an example: Allow or disable TCP traffic on port 12345.

```
sudo firewall-cmd --zone=public --add-port=12345/tcp --permanentsudo firewall-cmd --zone=public --remove-port=12345/tcp --permanent
```

### Port Forwarding

The example rule below forwards traffic from port 80 to port 12345 on  **the same server**.

```
sudo firewall-cmd --zone=&quot;public&quot; --add-forward-port=port=80:proto=tcp:toport=12345
```

To forward a port to  **a different server** :

1. Activate masquerade in the desired zone.

```
sudo firewall-cmd --zone=public --add-masquerade
```

1. Add the forward rule. This example forwards traffic from local port 80 to port 8080 on _a remote server_ located at the IP address: 198.51.100.0.

```
sudo firewall-cmd --zone=&quot;public&quot; --add-forward-port=port=80:proto=tcp:toport=8080:toaddr=198.51.100.0
```

To remove the rules, substitute `--add` with `--remove`. For example:

```
sudo firewall-cmd --zone=public --remove-masquerade
```

## Constructing a Ruleset with FirewallD

As an example, here is how you would use FirewallD to assign basic rules to your Linode if you were running a web server.

1. Assign the _dmz_ zone as the default zone to eth0. Of the default zones offered, dmz (demilitarized zone) is the most desirable to start with for this application because it allows only SSH and ICMP.

```
sudo firewall-cmd --set-default-zone=dmzsudo firewall-cmd --zone=dmz --add-interface=eth0
```

1. Add permanent service rules for HTTP and HTTPS to the dmz zone:

```
sudo firewall-cmd --zone=dmz --add-service=http --permanentsudo firewall-cmd --zone=dmz --add-service=https --permanent
```

1. Reload FirewallD so the rules take effect immediately:

```
sudo firewall-cmd --reload
```

If you now run `firewall-cmd --zone=dmz --list-all`, this should be the output:

```
dmz (default)interfaces: eth0sources:services: http https sshports:masquerade: noforward-ports:icmp-blocks:rich rules:
```

This tells us that the  **dmz**  zone is our  **default**  which applies to the  **eth0 interface** , all network  **sources**  and  **ports**. Incoming HTTP (port 80), HTTPS (port 443) and SSH (port 22) traffic is allowed and since there are no restrictions on IP versioning, this will apply to both IPv4 and IPv6.  **Masquerading**  and  **port forwarding**  are not allowed. We have no  **ICMP blocks** , so ICMP traffic is fully allowed, and no  **rich rules**. All outgoing traffic is allowed.

## Advanced Configuration

Services and ports are fine for basic configuration but may be too limiting for advanced scenarios. Rich Rules and Direct Interface allow you to add fully custom firewall rules to any zone for any port, protocol, address and action.

### Rich Rules

Rich rules syntax is extensive but fully documented in the [firewalld.richlanguage(5)](https://jpopelka.fedorapeople.org/firewalld/doc/firewalld.richlanguage.html) man page (or see `man firewalld.richlanguage` in your terminal). Use `--add-rich-rule`, `--list-rich-rules` and `--remove-rich-rule` with firewall-cmd command to manage them.

Here are some common examples:

Allow all IPv4 traffic from host 192.0.2.0.

```
sudo firewall-cmd --zone=public --add-rich-rule &#39;rule family=&quot;ipv4&quot; source address=192.0.2.0 accept&#39;
```

Deny IPv4 traffic over TCP from host 192.0.2.0 to port 22.

```
sudo firewall-cmd --zone=public --add-rich-rule &#39;rule family=&quot;ipv4&quot; source address=&quot;192.0.2.0&quot; port port=22 protocol=tcp reject&#39;
```

Allow IPv4 traffic over TCP from host 192.0.2.0 to port 80, and forward it locally to port 6532.

```
sudo firewall-cmd --zone=public --add-rich-rule &#39;rule family=ipv4 source address=192.0.2.0 forward-port port=80 protocol=tcp to-port=6532&#39;
```

Forward all IPv4 traffic on port 80 to port 8080 on host 198.51.100.0 (masquerade should be active on the zone).

```
sudo firewall-cmd --zone=public --add-rich-rule &#39;rule family=ipv4 forward-port port=80 protocol=tcp to-port=8080 to-addr=198.51.100.0&#39;
```

To list your current Rich Rules in the public zone:

```
sudo firewall-cmd --zone=public --list-rich-rules
```

### iptables Direct Interface

For the most advanced usage, or for iptables experts, FirewallD provides a direct interface that allows you to pass raw iptables commands to it. Direct Interface rules are not persistent unless the `--permanent` is used.

To see all custom chains or rules added to FirewallD:

```
firewall-cmd --direct --get-all-chainsfirewall-cmd --direct --get-all-rules
```

Discussing iptables syntax details goes beyond the scope of this guide. If you want to learn more, you can review our [iptables guide](https://www.linode.com/docs/security/firewalls/control-network-traffic-with-iptables/).

\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_

## UFW - Uncomplicated Firewall

The default firewall configuration tool for Ubuntu is ufw. Developed to ease _iptables_firewall configuration, ufw provides a user friendly way to create an IPv4 or IPv6 host-based firewall. By default UFW is disabled.

[Gufw](https://help.ubuntu.com/community/Gufw)is a GUI that is available as a frontend.

# Basic Syntax and Examples

## Default rules are fine for the average home user

When you turn UFW on, it uses a default set of rules (profile) that should be fine for the average home user. That&#39;s at least the goal of the Ubuntu developers. In short, all &#39;incoming&#39; is being denied, with some exceptions to make things easier for home users.

## Enable and Disable

### Enable UFW

To turn UFW on with the default set of rules:

```
sudo ufw enable
```

To check the status of UFW:

```
sudo ufw status verbose
```

The output should be like this:

```
youruser@yourcomputer:~$ sudo ufw status verbose[sudo] password for youruser:Status: activeLogging: on (low)Default: deny (incoming), allow (outgoing)New profiles: skipyouruser@yourcomputer:~$
```

Note that by default, deny is being applied to incoming. There are exceptions, which can be found in the output of this command:

```
sudo ufw show raw
```

You can also read the rules files in /etc/ufw (the files whose names end with .rules).

### Disable UFW

To disable ufw use:

```
sudo ufw disable
```

Allow and Deny (specific rules)

### Allow

```
sudo ufw allow \&lt;port\&gt;/\&lt;optional: protocol\&gt;
```

**example:**  To allow incoming tcp and udp packet on port 53

1.
```
sudo ufw allow 53
```

**example:**  To allow incoming tcp packets on port 53

1.
```
sudo ufw allow 53/tcp
```

**example:**  To allow incoming udp packets on port 53

1.
```
sudo ufw allow 53/udp
```

### Deny

```
sudo ufw deny \&lt;port\&gt;/\&lt;optional: protocol\&gt;
```

**example:**  To deny tcp and udp packets on port 53

1.
```
sudo ufw deny 53
```

**example:**  To deny incoming tcp packets on port 53

1.
```
sudo ufw deny 53/tcp
```

**example:**  To deny incoming udp packets on port 53

1.
```
sudo ufw deny 53/udp
```

## Delete Existing Rule

To delete a rule, simply prefix the original rule with delete. For example, if the original rule was:

```
ufw deny 80/tcp
```

Use this to delete it:

```
sudo ufw delete deny 80/tcp
```

## Services

You can also allow or deny by service name since ufw reads from /etc/services To see get a list of services:

```
less /etc/services
```

### Allow by Service Name

```
sudo ufw allow \&lt;service name\&gt;
```

**example:**  to allow ssh by name

1.
```
sudo ufw allow ssh
```

### Deny by Service Name

```
sudo ufw deny \&lt;service name\&gt;
```

**example:**  to deny ssh by name

1.
```
sudo ufw deny ssh
```

## Status

Checking the status of ufw will tell you if ufw is enabled or disabled and also list the current ufw rules that are applied to your iptables.

To check the status of ufw:

```
sudo ufw statusFirewall loadedTo Action From-- ------ ----22:tcp DENY 192.168.0.122:udp DENY 192.168.0.122:tcp DENY 192.168.0.722:udp DENY 192.168.0.722:tcp ALLOW 192.168.0.0/2422:udp ALLOW 192.168.0.0/24
```

if ufw was not enabled the output would be:

```
sudo ufw statusStatus: inactive
```

## Logging

To enable logging use:

```
sudo ufw logging on
```

To disable logging use:

```
sudo ufw logging off
```

# Advanced Syntax

You can also use a fuller syntax, specifying the source and destination addresses, ports and protocols.

## Allow Access

This section shows how to allow specific access.

### Allow by Specific IP

```
sudo ufw allow from \&lt;ip address\&gt;
```

**example:** To allow packets from 207.46.232.182:

1.
```
sudo ufw allow from 207.46.232.182
```

### Allow by Subnet

You may use a net mask :

```
sudo ufw allow from 192.168.1.0/24
```

### Allow by specific port and IP address

```
sudo ufw allow from \&lt;target\&gt; to \&lt;destination\&gt; port \&lt;port number\&gt;
```

**example:**  allow IP address 192.168.0.4 access to port 22 for all protocols

1.
```
sudo ufw allow from 192.168.0.4 to any port 22
```

### Allow by specific port, IP address and protocol

```
sudo ufw allow from \&lt;target\&gt; to \&lt;destination\&gt; port \&lt;port number\&gt; proto \&lt;protocol name\&gt;
```

**example:**  allow IP address 192.168.0.4 access to port 22 using TCP

1.
```
sudo ufw allow from 192.168.0.4 to any port 22 proto tcp
```

### Enable PING

Note: Security by obscurity may be of very little actual benefit with modern cracker scripts.  **By default, UFW allows ping requests**. You may find you wish to leave (icmp) ping requests enabled to diagnose networking problems.

In order to disable ping (icmp) requests, you need to edit  **/etc/ufw/before.rules**  and remove the following lines:

```
# ok icmp codes-A ufw-before-input -p icmp --icmp-type destination-unreachable -j ACCEPT-A ufw-before-input -p icmp --icmp-type source-quench -j ACCEPT-A ufw-before-input -p icmp --icmp-type time-exceeded -j ACCEPT-A ufw-before-input -p icmp --icmp-type parameter-problem -j ACCEPT-A ufw-before-input -p icmp --icmp-type echo-request -j ACCEPT
```

or change the &quot;ACCEPT&quot; to &quot;DROP&quot;

```
# ok icmp codes-A ufw-before-input -p icmp --icmp-type destination-unreachable -j DROP-A ufw-before-input -p icmp --icmp-type source-quench -j DROP-A ufw-before-input -p icmp --icmp-type time-exceeded -j DROP-A ufw-before-input -p icmp --icmp-type parameter-problem -j DROP-A ufw-before-input -p icmp --icmp-type echo-request -j DROP
```

## Deny Access

### Deny by specific IP

```
sudo ufw deny from \&lt;ip address\&gt;
```

**example:** To block packets from 207.46.232.182:

1.
```
sudo ufw deny from 207.46.232.182
```

### Deny by specific port and IP address

```
sudo ufw deny from \&lt;ip address\&gt; to \&lt;protocol\&gt; port \&lt;port number\&gt;
```

**example:**  deny ip address 192.168.0.1 access to port 22 for all protocols

1.
```
sudo ufw deny from 192.168.0.1 to any port 22
```

## Working with numbered rules

### Listing rules with a reference number

You may use status numbered to show the order and id number of rules:

```
sudo ufw status numbered
```

## Editing numbered rules

### Delete numbered rule

You may then delete rules using the number. This will delete the first rule and rules will shift up to fill in the list.

```
sudo ufw delete 1
```

### Insert numbered rule

```
sudo ufw insert 1 allow from \&lt;ip address\&gt;
```

## Advanced Example

**Scenario:**  You want to block access to port 22 from 192.168.0.1 and 192.168.0.7 but allow all other 192.168.0.x IPs to have access to port 22 using tcp

```
sudo ufw deny from 192.168.0.1 to any port 22sudo ufw deny from 192.168.0.7 to any port 22sudo ufw allow from 192.168.0.0/24 to any port 22 proto tcp
```

This puts the specific rules first and the generic second. Once a rule is matched the others will not be evaluated (see manual below) so you must put the specific rules first.  **As rules change you may need to delete old rules to ensure that new rules are put in the proper order.**

To check your rules orders you can check the status; for the scenario the output below is the desired output for the rules to work properly

```
sudo ufw statusFirewall loadedTo Action From-- ------ ----22:tcp DENY 192.168.0.122:udp DENY 192.168.0.122:tcp DENY 192.168.0.722:udp DENY 192.168.0.722:tcp ALLOW 192.168.0.0/24
```

**Scenario change:**  You want to block access to port 22 to 192.168.0.3 as well as 192.168.0.1 and 192.168.0.7.

```
sudo ufw delete allow from 192.168.0.0/24 to any port 22sudo ufw statusFirewall loadedTo Action From-- ------ ----22:tcp DENY 192.168.0.122:udp DENY 192.168.0.122:tcp DENY 192.168.0.722:udp DENY 192.168.0.7sudo ufw deny 192.168.0.3 to any port 22sudo ufw allow 192.168.0.0/24 to any port 22 proto tcpsudo ufw statusFirewall loadedTo Action From-- ------ ----22:tcp DENY 192.168.0.122:udp DENY 192.168.0.122:tcp DENY 192.168.0.722:udp DENY 192.168.0.722:tcp DENY 192.168.0.322:udp DENY 192.168.0.322:tcp ALLOW 192.168.0.0/24
```

If you simply add the deny rule the allow would have been above it and been applied instead of the deny

# Interpreting Log Entries

Based on the response to the post [UFW log guide/tutorial ?](http://ubuntuforums.org/showthread.php?t=2085110&amp;p=12361050#post12361050).

The SPT and DPT values, along with SRC and DST values, will typically be the values you&#39;ll focus on when analysing the firewall logs.

### Pseudo Log Entry

```
Feb 4 23:33:37 hostname kernel: [3529.289825] [UFW BLOCK] IN=eth0 OUT= MAC=00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd SRC=444.333.222.111 DST=111.222.333.444 LEN=103 TOS=0x00 PREC=0x00 TTL=52 ID=0 DF PROTO=UDP SPT=53 DPT=36427 LEN=83
```

### Date

It&#39;s good practice to watch the dates and times. If things are out of order or blocks of time are missing then an attacker probably messed with your logs.

### Hostname

The server&#39;s hostname

### Uptime

The time in seconds since boot.

### Logged Event

Short description of the logged event; e.g. [UFW BLOCK]

### IN

If set, then the event was an incoming event.

### OUT

If set, then the event was an outgoing event.

### MAC

This provides a 14-byte combination of the Destination MAC, Source MAC, and [EtherType](https://help.ubuntu.com/community/EtherType) fields, following the order found in the Ethernet II header. See [Ethernet frame](http://en.wikipedia.org/wiki/Ethernet_frame) and [EtherType](http://en.wikipedia.org/wiki/EtherType) for more information.

### SRC

This indicates the source IP, who sent the packet initially. Some IPs are routable over the internet, some will only communicate over a LAN, and some will only route back to the source computer. See [IP address](http://en.wikipedia.org/wiki/IP_address#Private_addresses) for more information.

### DST

This indicates the destination IP, who is meant to receive the packet. You can use [whois.net](https://whois.net/) or the cli whois to determine the owner of the IP address.

### LEN

This indicates the length of the packet.

### TOS

I believe this refers to the TOS field of the IPv4 header. See [TCP Processing of the IPv4 Precedence Field](http://tools.ietf.org/html/draft-xiao-tcp-prec-02) for more information.

### PREC

I believe this refers to the Precedence field of the IPv4 header.

### TTL

This indicates the &quot;Time to live&quot; for the packet. Basically each packet will only bounce through the given number of routers before it dies and disappears. If it hasn&#39;t found its destination before the TTL expires, then the packet will evaporate. This field keeps lost packets from clogging the internet forever. See [Time to live](http://en.wikipedia.org/wiki/Time_to_live) for more information.

### ID

Not sure what this one is, but it&#39;s not really important for reading logs. It might be ufw&#39;s internal ID system, it might be the operating system&#39;s ID.

### PROTO

This indicates the protocol of the packet - TCP or UDP. See [TCP and UDP Ports Explained](http://www.bleepingcomputer.com/tutorials/tcp-and-udp-ports-explained/) for more information.

### SPT

This indicates the source. I believe this is the port, which the SRC IP sent the IP packet over. See [List of TCP and UDP port numbers](http://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers) for more information.

### DPT

This indicates the destination port. I believe this is the port, which the SRC IP sent its IP packet to, expecting a service to be running on this port.

### WINDOW

This indicates the size of packet the sender is willing to receive.

### RES

This bit is reserved for future use &amp; is always set to 0. Basically it&#39;s irrelevant for log reading purposes.

### SYN URGP

SYN indicates that this connection requires a three-way handshake, which is typical of TCP connections. URGP indicates whether the urgent pointer field is relevant. 0 means it&#39;s not. Doesn&#39;t really matter for firewall log reading.

Resources;

- Manual Page; `man firewalld`
- [FirewallD Official Site](http://www.firewalld.org/); http://www.firewalld.org/
- [RHEL 7 Security Guide: Introduction to FirewallD](https://access.redhat.com/documentation/en-US/Red_Hat_Enterprise_Linux/7/html/Security_Guide/sec-Using_Firewalls.html#sec-Introduction_to_firewalld); https://access.redhat.com/documentation/en-US/Red\_Hat\_Enterprise\_Linux/7/html/Security\_Guide/sec-Using\_Firewalls.html#sec-Introduction\_to\_firewalld
- [Fedora Wiki: FirewallD](https://fedoraproject.org/wiki/FirewallD); [https://fedoraproject.org/wiki/FirewallD](https://fedoraproject.org/wiki/FirewallD)
- For instructions on using ufw first see the [official server guide](https://help.ubuntu.com/lts/serverguide/firewall.html); https://help.ubuntu.com/lts/serverguide/firewall.html
- The most recent syntax and manual can be retrieved by getting the [man page](http://manpages.ubuntu.com/manpages/man8/ufw.8.html). Otherwise open a terminal window and type:

```
man ufw
```

- [Firewall](https://help.ubuntu.com/community/Firewall)- wiki homepage for firewall related documentation; https://help.ubuntu.com/community/Firewall
- [Iptables](https://help.ubuntu.com/community/Iptables)- interface to the netfilter subsystem in the Linux kernel; https://help.ubuntu.com/community/Iptables
- [UncomplicatedFirewall](https://wiki.ubuntu.com/UncomplicatedFirewall)- UFW Project wiki page; https://wiki.ubuntu.com/UncomplicatedFirewall
- [Gufw](https://help.ubuntu.com/community/Gufw)- Graphic User Interface for UFW; https://help.ubuntu.com/community/Gufw
