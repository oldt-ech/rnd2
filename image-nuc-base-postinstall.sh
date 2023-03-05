#!/bin/bash

service ssh stop
iptables -t nat -F
iptables -t mangle -F
iptables -F
iptables -X
echo "y" | ufw reset
ufw default deny incoming
ufw default deny routed
ufw default allow outgoing
ufw allow in on enx0050b6bd37e7
ufw disable
sed -i 's/IPV6=yes/IPV6=no/g' /etc/default/ufw
sed -i 's/-A ufw-before-input -p udp -d 224.0.0.251 --dport 5353 -j ACCEPT/#-A ufw-before-input -p udp -d 224.0.0.251 --dport 5353 -j ACCEPT/g' /etc/ufw/before.rules
sed -i 's/-A ufw-before-input -p udp -d 239.255.255.250 --dport 1900 -j ACCEPT/#-A ufw-before-input -p udp -d 239.255.255.250 --dport 1900 -j ACCEPT/g' /etc/ufw/before.rules
sudo ufw enable
service ssh start
apt install -y update-notifier-common unattended-upgrade
dpkg-reconfigure -pmedium unattended-upgrades
sed -i 's/\/\/Unattended-Upgrade::Automatic-Reboot "false";/Unattended-Upgrade::Automatic-Reboot "true";/g' /etc/apt/apt.conf.d/50unattended-upgrades
sed -i 's/\/\/Unattended-Upgrade::Remove-Unused-Dependencies "false";/Unattended-Upgrade::Remove-Unused-Dependencies "true";/g' /etc/apt/apt.conf.d/50unattended-upgrades
sed -i 's/\/\/Unattended-Upgrade::Automatic-Reboot-WithUsers "true";/Unattended-Upgrade::Automatic-Reboot-WithUsers "true";/g' /etc/apt/apt.conf.d/50unattended-upgrades
sed -i 's/\/\/Acquire::http::Dl-Limit "70";/Acquire::http::Dl-Limit "8000";/g' /etc/apt/apt.conf.d/50unattended-upgrades
sed -i 's/\/\/Unattended-Upgrade::InstallOnShutdown "false";/Unattended-Upgrade::InstallOnShutdown "false";/g' /etc/apt/apt.conf.d/50unattended-upgrades
sed -i 's/\/\/Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";/Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";/g' /etc/apt/apt.conf.d/50unattended-upgrades
sed -i 's/\/\/Unattended-Upgrade::Remove-New-Unused-Dependencies "true";/Unattended-Upgrade::Remove-New-Unused-Dependencies "true";/g' /etc/apt/apt.conf.d/50unattended-upgrades
shutdown -r now