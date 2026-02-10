# Cyber Kill Chain Lab

This is a lab is intended to show the cyber kill chain of an attack.
The lab internally uses a generated pcap -> Zeek -> Free version of Splunk

It also uses event logs from DFIRMuseum (particularly the APTSimulatorVM_EventLogs)

The goal is to show the flow of an attack at a very basic level.

Note this lab uses the attack_data sysmon log involving the agent telsa malware.
You should accept the splunk license in docker before doing stuff (uncomment line)