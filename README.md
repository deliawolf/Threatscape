# Threatscape

Threats to the enterprise network can come in many forms and from many sources, external and internal. This multitude of types of threats and sources is referred to as the threatscape.

Here is some terminology that will help you as you learn about today's threatscape:

1. Vulnerability: A weakness that compromises either the security or the functionality of a system. Weak or easily guessed passwords are considered vulnerabilities.

2. Exploit: The mechanism that is used to leverage a vulnerability to compromise the security or functionality of a system. An example of an exploit is an exploit tool. When a vulnerability is disclosed to the public, attackers often create a tool that implements an exploit for the vulnerability. If they release this tool to the internet, other attackers with very little skill can effectively exploit the vulnerability.

3. Threat: Any circumstance or event with the potential to cause harm to an asset in the form of destruction, disclosure, adverse modification of data, or DoS. An example of a threat is malicious software that targets workstations.

4. Risk: The likelihood that a particular threat using a specific attack will exploit a particular vulnerability of an asset that results in an undesirable consequence.

## Threatscape Landscape

Threatscape is a very large concept that is constantly growing. There are many treat vectors that will impact the enterprise network, coming from many different types of attackers. To help understand the range of threats, here is a summary of some of the major types of attacks and threats that can be seen:

1. DOS and DDOS: DoS attacks attempt to consume all a critical computer or network resource to make it unavailable for valid use.

2. Spoofing: An attack can be considered a spoofing attack anytime an attacker injects traffic that appears to be sourced from a system other than the attacker's system itself. Spoofing is not specifically an attack, but spoofing can be incorporated into various types of attacks.

3. Reflection: A reflection attack is a type of DoS attack in which the attacker sends a flood of protocol request packets to various IP hosts. The attacker spoofs the source IP address of the packets such that each packet has as its source address the IP address of the intended target rather than the IP address of the attacker. The IP hosts that receive these packets become "reflectors." The reflectors respond by sending response packets to the spoofed address (the target), thus flooding the unsuspecting target.

4. Social Engineering: Social engineering is manipulating people and capitalizing on expected behaviors. Social engineering often involves utilizing social skills, relationships, or understanding of cultural norms to manipulate people inside a network to provide the information that is needed to access the network.

5. Phishing: Phishing is a common social engineering technique. Typically, a phishing email pretends to be from a large, legitimate organization, as illustrated in the figure below. Since the large organization is legitimate, the target may have a real account with the organization. The malicious website generally resembles that of the real organization. The goal is to get the victim to enter personal information such as account numbers, social security numbers, usernames, or passwords.

6. Password Attacks: Password attacks have been a problem since the beginning of network security, and they continue to be a dominant problem in current network security. The attacker will try to access protected resources by obtaining a user’s password. Methods for retrieving the user’s password include guessing, brute force, and dictionary attacks. Many authentication systems require a certain degree of password complexity. Specifying a minimum length of a password and forcing an enlarged character set (upper case, lower case, numeric, and special characters) can have an enormous influence on the feasibility of brute force attacks.

7. Reconnaissance Attacks: A reconnaissance attack is an attempt to learn more about the intended victim before attempting a more intrusive attack. Attackers can use standard networking tools such as dig, nslookup, and who is to gather public information about a target network from DNS registries. All three are command-line tools. The nslookup and who is tools are available on both Windows, UNIX and Linux platforms, and dig is available on UNIX and Linux systems.

8. Buffer Overflow Attacks: Attackers can analyze network server applications for flaws. A buffer overflow vulnerability is one type of flaw. If a service accepts input and expects the input to be within a certain size but does not verify the size of input upon reception, it may be vulnerable to a buffer overflow attack. This means that an attacker can provide input that is larger than expected, and the service will accept the input and write it to memory, filling up the associated buffer and overwriting adjacent memory. This overwrite may corrupt the system and cause it to crash, resulting in a DoS. In the worst cases, the attacker can inject malicious code in the buffer overflow, leading to a system compromise.

9. Man-in-the-Middle Attacks: A man-in-the-middle attack is more of a generalized concept that can be implemented in many different scenarios than a specific attack. Generally, in these attacks, a system that has the ability to view the communication between two systems imposes itself in the communication path between those other systems. Man-in-the-middle attacks are complex attacks that require successful attacks against IP routing or protocols (such as ARP, DNS, or DHCP), resulting in the misdirection of traffic.

10. Malware: Malware is malicious software that comes in several forms, including viruses, worms, and Trojan horses. The common thread of these attacks is that the attacker tries to install software on the victim’s system. Once the software is installed on the victim’s system the attacker can take control of that system, encrypt and lock the victim’s data, or escalate privileges to other parts of the victim’s network as part of an advanced persistent threat (APT).

11. Vectors of Data Loss and Exfiltration: The expression "vector of data loss and exfiltration" refers to the means by which data leaves the organization without authorization. While not a direct attack itself, it is a major security concern in the enterprise network. Many of the tools that make our jobs easier today are also ways that confidential data can be obtained by unauthorized persons. Some of the common data loss vectors include email attachments, unencrypted devices, cloud storage services, removable storage devices, and having improper access controls.

12. Hacking tools: The distinction between a security tool and an attack tool is in the intent of the user. A penetration tester legitimately uses tools to attempt to penetrate an organization’s security defenses, and the results of the penetration test are used by the organization to improve their security defenses. However, the same tools that the penetration tester uses can be used illegitimately by an attacker. Hacking tools can be easily found, including: sectools.org, Kali Linux, and Metasploit.

For more information about the threats facing the enterprise network, visit Cisco Talos at https://www.talosintelligence.com/
