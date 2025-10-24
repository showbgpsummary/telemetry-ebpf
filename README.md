# Ebpf powered zero trust arthitecture firewall 
This repository contains a simple eBPF/XDP-based firewall. The purpose of this project is to create a high-performance firewall that operates on an "allow-list" basis, blocking all traffic except for sources explicitly permitted in a BPF map.
## About architecture
This project uses a standard Control Plane / Data Plane separation:

- Data Plane (Kernelspace): The firewall.c eBPF program, once loaded via XDP, acts as the high-speed data plane. It runs in the kernel and inspects every packet, enforcing policy by checking the allowed_ip_map for a match.

- Control Plane (Userspace): A (planned) Go application will act as the control plane. Its job is to manage the policy by adding or removing allowed IP addresses from the allowed_ip_map.
