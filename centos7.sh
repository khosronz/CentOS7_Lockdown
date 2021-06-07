#!/bin/bash

### Change OS Header Name

#sudo sed -i 's/CentOS Linux release 7.9.2009 (Core)/Tahlilyar release 2021 (Core)/g' /etc/centos-release
#sudo sed -i 's/CentOS Linux/Tahlilyar/g' /etc/os-release
#sudo sed -i 's/VERSION="7 (Core)"/VERSION="2021 (Core)"/g' /etc/os-release
#sudo sed -i 's/ID="centos"/ID="tahlilyar"/g' /etc/os-release
#sudo sed -i 's/ID_LIKE="rhel fedora"/ID_LIKE="tahlilyar"/g' /etc/os-release
#sudo sed -i 's/VERSION_ID="7"/VERSION_ID="2021"/g' /etc/os-release
#sudo sed -i 's/PRETTY_NAME="CentOS Linux 7 (Core)"/PRETTY_NAME="Tahlilyar 2021 (Core)"/g' /etc/os-release
#sudo sed -i 's/centos:centos:7/tahlilyar:tahlilyar:2021/g' /etc/os-release
#sudo sed -i 's/centos.org/tahlilyar.com/g' /etc/os-release
#sudo sed -i 's/CENTOS_MANTISBT_PROJECT="CentOS-7"/CENTOS_MANTISBT_PROJECT="Tahlilyar-2021"/g' /etc/os-release
#sudo sed -i 's/CENTOS_MANTISBT_PROJECT_VERSION="7"/CENTOS_MANTISBT_PROJECT_VERSION="2021"/g' /etc/os-release
#sudo sed -i 's/REDHAT_SUPPORT_PRODUCT="centos"/REDHAT_SUPPORT_PRODUCT="tahlilyar"/g' /etc/os-release
#sudo sed -i 's/REDHAT_SUPPORT_PRODUCT_VERSION="7"/REDHAT_SUPPORT_PRODUCT_VERSION="2021"/g' /etc/os-release

## Rolebac

#sudo sed -i 's/Tahlilyar release 2021 (Core)/CentOS Linux release 7.9.2009 (Core)/g' /etc/centos-release
#sudo sed -i 's/Tahlilyar/CentOS Linux/g' /etc/os-release
#sudo sed -i 's/VERSION="2021 (Core)"/VERSION="7 (Core)"/g' /etc/os-release
#sudo sed -i 's/ID="tahlilyar"/ID="centos"/g' /etc/os-release
#sudo sed -i 's/ID_LIKE="tahlilyar"/ID_LIKE="rhel fedora"/g' /etc/os-release
#sudo sed -i 's/VERSION_ID="2021"/VERSION_ID="7"/g' /etc/os-release
#sudo sed -i 's/PRETTY_NAME="Tahlilyar 2021 (Core)"/PRETTY_NAME="CentOS Linux 7 (Core)"/g' /etc/os-release
#sudo sed -i 's/tahlilyar:tahlilyar:2021/centos:centos:7/g' /etc/os-release
#sudo sed -i 's/tahlilyar.com/centos.org/g' /etc/os-release
#sudo sed -i 's/CENTOS_MANTISBT_PROJECT="Tahlilyar-2021"/CENTOS_MANTISBT_PROJECT="CentOS-7"/g' /etc/os-release
#sudo sed -i 's/CENTOS_MANTISBT_PROJECT_VERSION="2021"/CENTOS_MANTISBT_PROJECT_VERSION="7"/g' /etc/os-release
#sudo sed -i 's/REDHAT_SUPPORT_PRODUCT="tahlilyar"/REDHAT_SUPPORT_PRODUCT="centos"/g' /etc/os-release
#sudo sed -i 's/REDHAT_SUPPORT_PRODUCT_VERSION="2021"/REDHAT_SUPPORT_PRODUCT_VERSION="7"/g' /etc/os-release

# Ensure /tmp is configured - enabled




yum install module-init-tools



### Hardening Script for CentOS7 Servers.
AUDITDIR="/tmp/$(hostname -s)_audit"
TIME="$(date +%F_%T)"

mkdir -p $AUDITDIR
# Ensure mounting of cramfs filesystems is disabled - modprobe
# Ensure mounting of squashfs filesystems is disabled - modprobe
# Ensure mounting of udf filesystems is disabled - modprobe
# Disable USB Storage - modprobe

ls -l /lib/modules/$(uname -r)/kernel/fs | grep cramfs 
ls -l /lib/modules/$(uname -r)/kernel/fs | grep freevxfs 
ls -l /lib/modules/$(uname -r)/kernel/fs | grep jffs2 
ls -l /lib/modules/$(uname -r)/kernel/fs | grep hfs 
ls -l /lib/modules/$(uname -r)/kernel/fs | grep hfsplus 
ls -l /lib/modules/$(uname -r)/kernel/fs | grep squahfs 
ls -l /lib/modules/$(uname -r)/kernel/fs | grep squashfs 
ls -l /lib/modules/$(uname -r)/kernel/fs | grep udf 
ls -l /lib/modules/$(uname -r)/kernel/fs | grep dccp 
ls -l /lib/modules/$(uname -r)/kernel/fs | grep sctp 
ls -l /lib/modules/$(uname -r)/kernel/fs | grep rds 
ls -l /lib/modules/$(uname -r)/kernel/fs | grep tipc 
ls -l /lib/modules/$(uname -r)/kernel/fs | grep usb-storage 


rmmod  cramfs 
rmmod  freevxfs 
rmmod  jffs2 
rmmod  hfs 
rmmod  hfsplus 
rmmod  squahfs 
rmmod  squashfs 
rmmod  udf 
rmmod  dccp 
rmmod  sctp 
rmmod  rds 
rmmod  tipc 
rmmod  usb-storage 

## Run

modprobe -v -r  cramfs 
modprobe -v -r  freevxfs 
modprobe -v -r  jffs2 
modprobe -v -r  hfs 
modprobe -v -r  hfsplus 
modprobe -v -r  squahfs 
modprobe -v -r  squashfs 
modprobe -v -r  udf 
modprobe -v -r  dccp 
modprobe -v -r  sctp 
modprobe -v -r  rds 
modprobe -v -r  tipc 
modprobe -v -r  usb-storage 



echo "Disabling Legacy Filesystems"
cat > /etc/modprobe.d/CIS.conf << "EOF"
install cramfs /bin/true
install freevxfs /bin/true
install jffs2 /bin/true
install hfs /bin/true
install hfsplus /bin/true
install squahfs /bin/true
install squashfs /bin/true
install udf /bin/true
install dccp /bin/true
install sctp /bin/true
install rds /bin/true
install tipc /bin/true
install usb-storage /bin/true
EOF


/usr/sbin/modprobe -n -v cramfs  | /usr/bin/awk '{print} END {if (NR == 0) print "fail"}'
/usr/sbin/modprobe -n -v freevxfs  | /usr/bin/awk '{print} END {if (NR == 0) print "fail"}'
/usr/sbin/modprobe -n -v jffs2  | /usr/bin/awk '{print} END {if (NR == 0) print "fail"}'
/usr/sbin/modprobe -n -v hfs  | /usr/bin/awk '{print} END {if (NR == 0) print "fail"}'
/usr/sbin/modprobe -n -v hfsplus  | /usr/bin/awk '{print} END {if (NR == 0) print "fail"}'
/usr/sbin/modprobe -n -v squahfs  | /usr/bin/awk '{print} END {if (NR == 0) print "fail"}'
/usr/sbin/modprobe -n -v udf  | /usr/bin/awk '{print} END {if (NR == 0) print "fail"}'
/usr/sbin/modprobe -n -v dccp  | /usr/bin/awk '{print} END {if (NR == 0) print "fail"}'
/usr/sbin/modprobe -n -v sctp  | /usr/bin/awk '{print} END {if (NR == 0) print "fail"}'
/usr/sbin/modprobe -n -v rds  | /usr/bin/awk '{print} END {if (NR == 0) print "fail"}'
/usr/sbin/modprobe -n -v tipc  | /usr/bin/awk '{print} END {if (NR == 0) print "fail"}'
/usr/sbin/modprobe -n -v usb-storage  | /usr/bin/awk '{print} END {if (NR == 0) print "fail"}'


# Ensure kernel module loading and unloading is collected - auditctl modprobe
# Ensure kernel module loading and unloading is collected - auditctl rmmod

## For 64 bit
cat >> /etc/audit/rules.d/modules.rules  << "EOF"
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=b64 -S init_module -S delete_module -k modules
EOF

cat >> /etc/audit/rules.d/MAC_policy.rules << "EOF"
-w /etc/selinux/ -p wa -k MAC-policy
-w /usr/share/selinux/ -p wa -k MAC-policy
EOF



cat >> /etc/audit/rules.d/logins.rules << "EOF"
-w /var/log/faillog -p wa -k logins
-w /var/log/lastlog -p wa -k logins
-w /var/log/tallylog -p wa -k logins
EOF


cat >> /etc/audit/rules.d/session.rules << "EOF"
-w /var/run/utmp -p wa -k session
-w /var/log/wtmp -p wa -k logins
-w /var/log/btmp -p wa -k logins
EOF


cat >> /etc/audit/rules.d/perm_mod.rules << "EOF"
-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod
EOF




cat >> /etc/audit/rules.d/access.rules << "EOF"
-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access
EOF


cat >> /etc/audit/rules.d/mounts.rules << "EOF"
-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts
-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts
EOF


cat >> /etc/audit/rules.d/deletion.rules << "EOF"
-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete
-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete
EOF


cat >> /etc/audit/rules.d/scope.rules << "EOF"
-w /etc/sudoers -p wa -k scope
-w /etc/sudoers.d/ -p wa -k scope
EOF


cat >> /etc/audit/rules.d/actions.rules << "EOF"
-w /var/log/sudo.log -p wa -k actions
EOF



cat >> /etc/audit/rules.d/99-finalize.rules << "EOF"
-e 2
EOF

cat >> /etc/rsyslog.d/file-create-mode.conf << "EOF"
$FileCreateMode 0640
EOF

cat >> /etc/rsyslog.d/loghost.example.com.conf << "EOF"
*.* @@loghost.example.com
EOF


# Run the following command to reload the rsyslogd configuration:


systemctl restart rsyslog


#ForwardToSyslog=yes

sudo sed -i 's/#ForwardToSyslog=yes/ForwardToSyslog=yes/g' /etc/systemd/journald.conf
sudo sed -i 's/#Compress=yes/Compress=yes/g' /etc/systemd/journald.conf
sudo sed -i 's/#Storage=auto/Storage=persistent/g' /etc/systemd/journald.conf

# Ensure permissions on all logfiles are configured

find /var/log -type f -exec chmod g-wx,o-rwx '{}' + -o -type d -exec chmod g-wx,o-rwx '{}' +

# Ensure /tmp is configured - enabled
# Ensure /tmp is configured - mount
# Ensure /dev/shm is configured - /etc/fstab
# Ensure noexec option set on /dev/shm partition

# echo " ..."
# cat >> /etc/fstab << "EOF"
# /tmp /var/tmp none rw,noexec,nosuid,nodev,bind,size=2G 0 0
# tmpfs /dev/shm tmpfs defaults,noexec,nodev,nosuid,seclabel 0 0
# EOF


# mount -a
# df -h

# Ensure /tmp is configured - enabled
# Ensure /tmp is configured - mount
# Ensure /dev/shm is configured - /etc/fstab
# Ensure noexec option set on /dev/shm partition
# echo "tmp,shm  ==> enabled, mount, configured, ..."


# Ensure sudo commands use pty
# Ensure sudo log file exists

cat > /etc/sudoers.d/black.conf << "EOF"
Defaults use_pty
Defaults logfile='/var/log/sudo.log'
EOF

# Ensure AIDE is installed
echo "Install AIDE ..."

sudo yum install aide -y
sudo aide --init
mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz

cat > crontab -u root -e << "EOF"
0 5 * * * /usr/sbin/aide --check
EOF


cat > /etc/systemd/system/aidecheck.service << "EOF"
[Unit] 
Description=Aide Check

[Service] 
Type=simple 
ExecStart=/usr/sbin/aide --check

[Install] 
WantedBy=multi-user.target
EOF
cat > /etc/systemd/system/aidecheck.timer << "EOF"
[Unit] 
Description=Aide check every day at 5AM

[Timer] 
OnCalendar=*-*-* 05:00:00 
Unit=aidecheck.service

[Install] 
WantedBy=multi-user.target
EOF


chown root:root /etc/systemd/system/aidecheck.* 
chmod 0644 /etc/systemd/system/aidecheck.*
systemctl daemon-reload
systemctl enable aidecheck.service 
systemctl --now enable aidecheck.timer


sudo yum install chrony -y
sudo yum install ntp -y

sudo sed -i 's/restrict default nomodify notrap nopeer noquery/restrict -4 default kod nomodify notrap nopeer noquery\nrestrict -6 default kod nomodify notrap nopeer noquery/g' /etc/ntp.conf

sudo sed -i 's/server 0.centos.pool.ntp.org iburst/#server 0.centos.pool.ntp.org iburst/g' /etc/ntp.conf
sudo sed -i 's/server 1.centos.pool.ntp.org iburst/#server 1.centos.pool.ntp.org iburst/g' /etc/ntp.conf
sudo sed -i 's/server 2.centos.pool.ntp.org iburst/#server 2.centos.pool.ntp.org iburst/g' /etc/ntp.conf
sudo sed -i 's/server 3.centos.pool.ntp.org iburst/#server 3.centos.pool.ntp.org iburst/g' /etc/ntp.conf
sudo sed -i 's/#server 0.centos.pool.ntp.org iburst/server 10.100.197.4/g' /etc/ntp.conf

sudo sed -i 's/OPTIONS=\"-g\"/OPTIONS=\"-u ntp:ntp\"/g' /etc/sysconfig/ntpd




sudo yum install chrony -y
sudo yum install ntp -y
sudo systemctl --now mask rsyncd
sudo yum remove rsync

sudo systemctl stop iptables

sudo systemctl stop ip6tables

sudo yum remove iptables-services


sudo sed -i 's/server 0.centos.pool.ntp.org iburst/#server 0.centos.pool.ntp.org iburst/g' /etc/chrony.conf
sudo sed -i 's/server 1.centos.pool.ntp.org iburst/#server 1.centos.pool.ntp.org iburst/g' /etc/chrony.conf
sudo sed -i 's/server 2.centos.pool.ntp.org iburst/#server 2.centos.pool.ntp.org iburst/g' /etc/chrony.conf
sudo sed -i 's/server 3.centos.pool.ntp.org iburst/#server 3.centos.pool.ntp.org iburst/g' /etc/chrony.conf
sudo sed -i 's/#server 0.centos.pool.ntp.org iburst/server 10.100.197.4/g' /etc/chrony.conf

sudo sed -i 's/OPTIONS=\"\"/OPTIONS=\"-u chrony\"/g' /etc/sysconfig/chronyd

#/usr/bin/systemctl is-enabled rsyncd ----> masked
# Ensure IP forwarding is disabled - sysctlc.conf sysctl.d

sudo systemctl restart ntpd
sudo systemctl restart chronyd
sudo systemctl enable ntpd
sudo systemctl enable chronyd

sed -i 's/inet_interfaces = localhost/inet_interfaces = loopback-only/g' /etc/postfix/main.cf
systemctl restart postfix

sed -i 's/GRUB_CMDLINE_LINUX=\"crashkernel=auto spectre_v2=retpoline rd.lvm.lv=centos\/root rd.lvm.lv=centos\/swap rhgb quiet\"/GRUB_CMDLINE_LINUX=\"audit=1\"/g' /etc/default/grub


grub2-mkconfig > /boot/grub2/grub.cfg

sudo yum install tcp_wrappers

echo 'sshd : ALL' > /etc/hosts.deny
# grep -Els '^s*net.ipv4.ip_forwards*=s*1' /etc/sysctl.conf /etc/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /run/sysctl.d/*.conf | while read filename; do sed -ri 's/^s*(net.ipv4.ip_forwards*)(=)(s*S+b).*$/# *REMOVED* 1/' $filename; 
# done; 
# sysctl -w net.ipv4.ip_forward=0; 
# sysctl -w net.ipv4.route.flush=1


cat > /etc/hosts.allow << "EOF"
sshd : 192.168.188.0/24
sshd : 192.168.139.0/24
sshd : 10.100.197.0/24
sshd : 10.204.120.234
sshd : 10.204.120.235
sshd : 10.204.120.236
sshd : 10.204.120.237
sshd : 10.204.120.238
sshd : 10.204.120.239
sshd : 10.100.50.100
sshd : 10.100.50.101
sshd : 10.8.4.11
sshd : 10.8.4.12
sshd : 10.8.4.13
sshd : 10.8.4.14
sshd : 127.0.0.1
sshd : [::1]
EOF

sed -i 's/#Port 22/Port 9876/g' /etc/ssh/sshd_config

sudo yum -y install firewalld
sudo yum -y install policycoreutils-python

sudo systemctl start firewalld 
sudo systemctl enable firewalld 

sudo semanage port -a -t ssh_port_t -p tcp 9876
sudo semanage port -m -t ssh_port_t -p tcp 9876

sudo firewall-cmd --permanent --add-port=9876/tcp 
sudo firewall-cmd --permanent --add-port=22/tcp 
sudo firewall-cmd --reload 
sudo systemctl restart sshd

firewall-cmd --permanent --allow-port=9876/tcp
firewall-cmd --permanent --allow-port=80/tcp
firewall-cmd --permanent --allow-port=443/tcp
firewall-cmd --permanent --remove-port=22/tcp
firewall-cmd --permanent --remove-service=ssh
firewall-cmd --reload
firewall-cmd --list-all

grep -Els '^s*net.ipv6.conf.all.forwardings*=s*1' /etc/sysctl.conf /etc/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /run/sysctl.d/*.conf | while read filename; do sed -ri 's/^s*(net.ipv6.conf.all.forwardings*)(=)(s*S+b).*$/# *REMOVED* 1/' 
$filename; done; sysctl -w net.ipv6.conf.all.forwarding=0; sysctl -w net.ipv6.route.flush=1

# Ensure packet redirect sending is disabled - 'net.ipv4.conf.all.send_redirects = 0'

sysctl -w net.ipv4.conf.all.send_redirects=0 
sysctl -w net.ipv4.conf.default.send_redirects=0 
sysctl -w net.ipv4.route.flush=1




##/usr/sbin/sysctl net.ipv4.conf.default.send_redirects

#  Ensure packet redirect sending is disabled - files 'net.ipv4.conf.all.send_redirects = 0'

cat > /etc/sysctl.d/limit313.conf << "EOF"
net.ipv4.conf.all.send_redirects = 0 
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0 
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_redirects = 0 
net.ipv6.conf.default.accept_redirects = 0
net.ipv4.route.flush=1

EOF

sysctl -w net.ipv4.conf.all.send_redirects=0 
sysctl -w net.ipv4.conf.default.send_redirects=0 
sysctl -w net.ipv4.conf.all.accept_source_route=0 
sysctl -w net.ipv4.conf.default.accept_source_route=0 
sysctl -w net.ipv6.conf.all.accept_redirects=0 
sysctl -w net.ipv6.conf.default.accept_redirects=0 
sysctl -w net.ipv6.route.flush=1

#  Ensure source routed packets are not accepted - files 'net.ipv4.conf.all.accept_source_route = 0'
sed -i 's/^max_log_file = 8$/max_log_file = 32/' /etc/audit/auditd.conf


#

# vim /etc/default/grub # and change GRUB_CMDLINE_LINUX="..." to GRUB_CMDLINE_LINUX='audit=1'
# ## before is ----->     GRUB_CMDLINE_LINUX="rd.lvm.lv=centos/root rd.lvm.lv=centos/swap rhgb quiet" OR GRUB_CMDLINE_LINUX='audit_backlog_limit=8192'
#     GRUB_CMDLINE_LINUX='audit=1' 
#     GRUB_CMDLINE_LINUX='audit_backlog_limit=8192'

# grub2-mkconfig -o /boot/grub2/grub.cfg


# Ensure audit log storage size is configured
sed -i 's/^max_log_file = 8$/max_log_file = 1024/' /etc/audit/auditd.conf

#  Ensure audit logs are not automatically deleted
sed -i 's/^max_log_file_action = ROTATE$/max_log_file_action = keep_logs/' /etc/audit/auditd.conf

sed -i 's/space_left_action = SYSLOG/space_left_action = email/g' /etc/audit/auditd.conf
sed -i 's/action_mail_acct.*/action_mail_acct = root/g' /etc/audit/auditd.conf
sed -i 's/admin_space_left_action = SYSLOG/admin_space_left_action = halt/g' /etc/audit/auditd.conf


echo "Removing GCC compiler..."
yum -y remove gcc*

echo "Removing legacy services..."
yum -y remove rsh-server rsh ypserv tftp tftp-server talk talk-server telnet-server xinetd >> $AUDITDIR/service_remove_$TIME.log

echo "Disabling LDAP..."
yum -y remove openldap-servers >> $AUDITDIR/service_remove_$TIME.log
yum -y remove openldap-clients >> $AUDITDIR/service_remove_$TIME.log

echo "Disabling DNS..."
yum -y remove bind >> $AUDITDIR/service_remove_$TIME.log

echo "Disabling FTP Server..."
yum -y remove vsftpd >> $AUDITDIR/service_remove_$TIME.log

echo "Disabling Dovecot..."
yum -y remove dovecot >> $AUDITDIR/service_remove_$TIME.log

echo "Disabling Samba..."
yum -y remove samba >> $AUDITDIR/service_remove_$TIME.log

echo "Disabling HTTP Proxy Server..."
yum -y remove squid >> $AUDITDIR/service_remove_$TIME.log

echo "Disabling SNMP..."
yum -y remove net-snmp >> $AUDITDIR/service_remove_$TIME.log

echo "Setting Daemon umask..."
cp /etc/init.d/functions $AUDITDIR/functions_$TIME.bak
echo "umask 027" >> /etc/init.d/functions

echo "Disabling Unnecessary Services..."
servicelist=(dhcpd avahi-daemon cups nfslock rpcgssd rpcbind rpcidmapd rpcsvcgssd)
for i in ${servicelist[@]}; do
  [ $(systemctl disable $i 2> /dev/null) ] || echo "$i is Disabled"
done

echo "Upgrading password hashing algorithm to SHA512..."
authconfig --passalgo=sha512 --update


echo "Setting core dump security limits..."
echo '* hard core 0' > /etc/security/limits.conf
echo 'fs.suid_dumpable = 0' > /etc/security/suid_dumpable.conf
sysctl -w fs.suid_dumpable=0

echo "Generating additional logs..."
echo 'auth,user.* /var/log/user' >> /etc/rsyslog.conf
echo 'kern.* /var/log/kern.log' >> /etc/rsyslog.conf
echo 'daemon.* /var/log/daemon.log' >> /etc/rsyslog.conf
echo 'syslog.* /var/log/syslog' >> /etc/rsyslog.conf
echo 'lpr,news,uucp,local0,local1,local2,local3,local4,local5,local6.* /var/log/unused.log' >> /etc/rsyslog.conf
touch /var/log/user /var/log/kern.log /var/log/daemon.log /var/log/syslog /var/log/unused.log
chmod og-rwx /var/log/user /var/log/kern.log /var/log/daemon.log /var/log/syslog /var/log/unused.log
chown root:root /var/log/user /var/log/kern.log /var/log/daemon.log /var/log/syslog /var/log/unused.log

echo "Enabling auditd service..."
systemctl enable auditd

echo "Configuring Audit Log Storage Size..."
cp -a /etc/audit/auditd.conf /etc/audit/auditd.conf.bak
sed -i 's/^space_left_action.*$/space_left_action = SYSLOG/' /etc/audit/auditd.conf
sed -i 's/^action_mail_acct.*$/action_mail_acct = root/' /etc/audit/auditd.conf
sed -i 's/^admin_space_left_action.*$/admin_space_left_action = SYSLOG/' /etc/audit/auditd.conf

echo "Setting audit rules..."
cat > /etc/audit/audit.rules << "EOF"
-D
-b 320

-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change
-a always,exit -F arch=b64 -S clock_settime -k time-change
-a always,exit -F arch=b32 -S clock_settime -k time-change
-w /etc/localtime -p wa -k time-change

-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity

-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale
-w /etc/issue -p wa -k system-locale
-w /etc/issue.net -p wa -k system-locale
-w /etc/hosts -p wa -k system-locale
-w /etc/sysconfig/network -p wa -k system-locale

-w /var/log/faillog -p wa -k logins
-w /var/log/lastlog -p wa -k logins
-w /var/log/tallylog -p wa -k logins

-w /var/run/utmp -p wa -k session
-w /var/log/wtmp -p wa -k session
-w /var/log/btmp -p wa -k session

-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=500 -F auid!=4294967295 -k perm_mod

-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=500 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=500 -F auid!=4294967295 -k access
-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=500 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=500 -F auid!=4294967295 -k access

-a always,exit -F arch=b64 -S mount -F auid>=500 -F auid!=4294967295 -k mounts
-a always,exit -F arch=b32 -S mount -F auid>=500 -F auid!=4294967295 -k mounts

-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=500 -F auid!=4294967295 -k delete
-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=500 -F auid!=4294967295 -k delete

-w /etc/sudoers -p wa -k scope

-w /var/log/sudo.log -p wa -k actions

-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=b64 -S init_module -S delete_module -k modules

-e 2
EOF

echo "Configuring Cron and Anacron..."
yum -y install cronie-anacron >> $AUDITDIR/service_install_$TIME.log
systemctl enable crond
chown root:root /etc/anacrontab
chmod og-rwx /etc/anacrontab
chown root:root /etc/crontab
chmod og-rwx /etc/crontab
chown root:root /etc/cron.hourly
chmod og-rwx /etc/cron.hourly
chown root:root /etc/cron.daily
chmod og-rwx /etc/cron.daily
chown root:root /etc/cron.weekly
chmod og-rwx /etc/cron.weekly
chown root:root /etc/cron.monthly
chmod og-rwx /etc/cron.monthly
chown root:root /etc/cron.d
chmod og-rwx /etc/cron.d
/bin/rm -f /etc/cron.deny

echo "Creating Banner..."

echo 'Authorized uses only. All activity may be monitored and reported.' > /etc/issue

sed -i "s/\#Banner none/Banner \/etc\/issue\.net/" /etc/ssh/sshd_config
cp -p /etc/issue.net $AUDITDIR/issue.net_$TIME.bak
cat > /etc/issue.net << 'EOF'
/------------------------------------------------------------------------\
|                       *** NOTICE TO USERS ***                          |
|                                                                        |
| This computer system is the private property of TAHLILYAR      |
| It is for authorized use only.                                         |
|                                                                        |
| Users (authorized or unauthorized) have no explicit or implicit        |
| expectation of privacy.                                                |
|                                                                        |
| Any or all uses of this system and all files on this system may be     |
| intercepted, monitored, recorded, copied, audited, inspected, and      |
| disclosed to your employer, to authorized site, government, and law    |
| enforcement personnel, as well as authorized officials of government   |
| agencies, both domestic and foreign.                                   |
|                                                                        |
| By using this system, the user consents to such interception,          |
| monitoring, recording, copying, auditing, inspection, and disclosure   |
| at the discretion of such personnel or officials.  Unauthorized or     |
| improper use of this system may result in civil and criminal penalties |
| and administrative or disciplinary action, as appropriate. By          |
| continuing to use this system you indicate your awareness of and       |
| consent to these terms and conditions of use. LOG OFF IMMEDIATELY if   |
| you do not agree to the conditions stated in this warning.             |
\------------------------------------------------------------------------/
EOF
cp -p /etc/motd /etc/motd_$TIME.bak
cat > /etc/motd << 'EOF'
TAHLILYAR AUTHORIZED USE ONLY
EOF

echo "Configuring SSH..."
cp /etc/ssh/sshd_config $AUDITDIR/sshd_config_$TIME.bak
sed -i 's/#LogLevel INFO/LogLevel VERBOSE/g' /etc/ssh/sshd_config
sed -i 's/#MaxAuthTries 6/MaxAuthTries 4/g' /etc/ssh/sshd_config
sed -i 's/#IgnoreRhosts yes/IgnoreRhosts yes/g' /etc/ssh/sshd_config
sed -i 's/#HostbasedAuthentication no/HostbasedAuthentication no/g' /etc/ssh/sshd_config
sed -i 's/#PermitRootLogin yes/PermitRootLogin no/g' /etc/ssh/sshd_config
sed -i 's/#PermitEmptyPasswords no/PermitEmptyPasswords no/g' /etc/ssh/sshd_config
sed -i 's/#PermitUserEnvironment no/PermitUserEnvironment no/g' /etc/ssh/sshd_config
sed -i 's/#ClientAliveInterval 0/ClientAliveInterval 300/g' /etc/ssh/sshd_config
sed -i 's/#ClientAliveCountMax 3/ClientAliveCountMax 0/g' /etc/ssh/sshd_config
sed -i 's/X11Forwarding yes/X11Forwarding no/g' /etc/ssh/sshd_config
sed -i 's/UsePAM yes/UsePAM yes/g' /etc/ssh/sshd_config
sed -i 's/AllowTcpForwarding yes/AllowTcpForwarding no/g' /etc/ssh/sshd_config
echo 'maxstartups 10:30:60' >> /etc/ssh/sshd_config
sed -i 's/#MaxSessions 10/MaxSessions 10/g' /etc/ssh/sshd_config



echo "Ciphers aes128-ctr,aes192-ctr,aes256-ctr"  >> /etc/ssh/sshd_config
chown root:root /etc/ssh/sshd_config
chmod 600 /etc/ssh/sshd_config

systemctl restart sshd >> $AUDITDIR/service_restart_$TIME.log

echo "Setting default umask for users..."
line_num=$(grep -n "^[[:space:]]*umask" /etc/bashrc | head -1 | cut -d: -f1)
sed -i ${line_num}s/002/027/ /etc/bashrc
line_num=$(grep -n "^[[:space:]]*umask" /etc/profile | head -1 | cut -d: -f1)
sed -i ${line_num}s/002/027/ /etc/profile

echo "Locking inactive user accounts..."
useradd -D -f 30

echo "Verifying System File Permissions..."
chmod 644 /etc/passwd
chmod 000 /etc/shadow
chmod 000 /etc/gshadow
chmod 644 /etc/group
chown root:root /etc/passwd
chown root:root /etc/shadow
chown root:root /etc/gshadow
chown root:root /etc/group

# Ensure password creation requirements are configured - dcredit
sed -i 's/# minlen = 9/minlen = 14/g' /etc/security/pwquality.conf 
sed -i 's/# minclass = 0/minclass = 4/g' /etc/security/pwquality.conf 
sed -i 's/# dcredit = 1/dcredit = -1/g' /etc/security/pwquality.conf 
sed -i 's/# ucredit = 1/ucredit = -1/g' /etc/security/pwquality.conf 
sed -i 's/# ocredit = 1/ocredit = -1/g' /etc/security/pwquality.conf 
sed -i 's/# lcredit = 1/lcredit = -1/g' /etc/security/pwquality.conf 

echo 'password requisite pam_pwquality.so try_first_pass retry=3' >> /etc/pam.d/password-auth
sed -i 's/password    requisite     pam_pwquality.so try_first_pass local_users_only retry=3 authtok_type=/password  requisite   pam_pwquality.so try_first_pass retry=3/g' /etc/pam.d/system-auth

# ----tttt !!!!!
# Ensure lockout for failed password attempts is configured - password-auth 'auth [default=die] pam_faillock.so'


#faillock --user <username> --reset


#pam_tally2 -u <username> --reset


# Ensure sticky bit is set on all world-writable directories
echo "Setting Sticky Bit on All World-Writable Directories..."
# df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null | xargs chmod a+t >> $AUDITDIR/sticky_on_world_$TIME.log
{
  read _                           # consume header
  while IFS= read -r dirname; do   # ...iterate over later lines...
    find "$dirname" -xdev -type d \
      '(' -perm -0002 -a ! -perm -1000 ')' \
      -exec chmod a+t '{}' + 2>/dev/null
  done
} < <(df --output=target --local)  # tell df to emit only the one column you want

echo "Searching for world writable files..."
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type f -perm -0002 >> $AUDITDIR/world_writable_files_$TIME.log

echo "Searching for Un-owned files and directories..."
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -nouser -ls >> $AUDITDIR/unowned_files_$TIME.log

#34: Find Un-grouped Files and Directories
echo "Searching for Un-grouped files and directories..."
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -nogroup -ls >> $AUDITDIR/ungrouped_files_$TIME.log

echo "Searching for SUID System Executables..."
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type f -perm -4000 -print >> $AUDITDIR/suid_exec_$TIME.log

echo "Searching for SGID System Executables..."
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type f -perm -2000 -print >> $AUDITDIR/sgid_exec_$TIME.log

echo "Searching for empty password fields..."
/bin/cat /etc/shadow | /bin/awk -F: '($2 == "" ) { print $1 " does not have a password "}' >> $AUDITDIR/empty_passwd_$TIME.log

echo "Reviewing User and Group Settings..."
echo "Reviewing User and Group Settings..." >> $AUDITDIR/reviewusrgrp_$TIME.log
/bin/grep '^+:' /etc/passwd >> $AUDITDIR/reviewusrgrp_$TIME.log
/bin/grep '^+:' /etc/shadow >> $AUDITDIR/reviewusrgrp_$TIME.log
/bin/grep '^+:' /etc/group >> $AUDITDIR/reviewusrgrp_$TIME.log
/bin/cat /etc/passwd | /bin/awk -F: '($3 == 0) { print $1 }' >> $AUDITDIR/reviewusrgrp_$TIME.log

echo "Checking root PATH integrity..."

if [ "`echo $PATH | /bin/grep :: `" != "" ]; then
    echo "Empty Directory in PATH (::)" >> $AUDITDIR/root_path_$TIME.log
fi

if [ "`echo $PATH | /bin/grep :$`"  != "" ]; then
    echo "Trailing : in PATH" >> $AUDITDIR/root_path_$TIME.log
fi

p=`echo $PATH | /bin/sed -e 's/::/:/' -e 's/:$//' -e 's/:/ /g'`
set -- $p
while [ "$1" != "" ]; do
    if [ "$1" = "." ]; then
        echo "PATH contains ." >> $AUDITDIR/root_path_$TIME.log
        shift
        continue
    fi
    if [ -d $1 ]; then
        dirperm=`/bin/ls -ldH $1 | /bin/cut -f1 -d" "`
        if [ `echo $dirperm | /bin/cut -c6 ` != "-" ]; then
            echo "Group Write permission set on directory $1" >> $AUDITDIR/root_path_$TIME.log
        fi
        if [ `echo $dirperm | /bin/cut -c9 ` != "-" ]; then
            echo "Other Write permission set on directory $1" >> $AUDITDIR/root_path_$TIME.log
        fi
            dirown=`ls -ldH $1 | awk '{print $3}'`
           if [ "$dirown" != "root" ] ; then
             echo "$1 is not owned by root" >> $AUDITDIR/root_path_$TIME.log
              fi
    else
            echo "$1 is not a directory" >> $AUDITDIR/root_path_$TIME.log
      fi
    shift
done

echo "Checking Permissions on User Home Directories..."

for dir in `/bin/cat /etc/passwd  | /bin/egrep -v '(root|halt|sync|shutdown)' |\
    /bin/awk -F: '($8 == "PS" && $7 != "/sbin/nologin") { print $6 }'`; do
        dirperm=`/bin/ls -ld $dir | /bin/cut -f1 -d" "`
        if [ `echo $dirperm | /bin/cut -c6 ` != "-" ]; then
            echo "Group Write permission set on directory $dir" >> $AUDITDIR/home_permission_$TIME.log
        fi
        if [ `echo $dirperm | /bin/cut -c8 ` != "-" ]; then
            echo "Other Read permission set on directory $dir" >> $AUDITDIR/home_permission_$TIME.log

        fi

        if [ `echo $dirperm | /bin/cut -c9 ` != "-" ]; then
            echo "Other Write permission set on directory $dir" >> $AUDITDIR/home_permission_$TIME.log
        fi
        if [ `echo $dirperm | /bin/cut -c10 ` != "-" ]; then
            echo "Other Execute permission set on directory $dir" >> $AUDITDIR/home_permission_$TIME.log
        fi
done

echo "Checking User Dot File Permissions..."
for dir in `/bin/cat /etc/passwd | /bin/egrep -v '(root|sync|halt|shutdown)' |
/bin/awk -F: '($7 != "/sbin/nologin") { print $6 }'`; do
    for file in $dir/.[A-Za-z0-9]*; do

        if [ ! -h "$file" -a -f "$file" ]; then
            fileperm=`/bin/ls -ld $file | /bin/cut -f1 -d" "`

            if [ `echo $fileperm | /bin/cut -c6 ` != "-" ]; then
                echo "Group Write permission set on file $file" >> $AUDITDIR/dotfile_permission_$TIME.log
            fi
            if [ `echo $fileperm | /bin/cut -c9 ` != "-" ]; then
                echo "Other Write permission set on file $file" >> $AUDITDIR/dotfile_permission_$TIME.log
            fi
        fi

    done

done

echo "Checking Permissions on User .netrc Files..."
for dir in `/bin/cat /etc/passwd | /bin/egrep -v '(root|sync|halt|shutdown)' |\
    /bin/awk -F: '($7 != "/sbin/nologin") { print $6 }'`; do
    for file in $dir/.netrc; do
        if [ ! -h "$file" -a -f "$file" ]; then
            fileperm=`/bin/ls -ld $file | /bin/cut -f1 -d" "`
            if [ `echo $fileperm | /bin/cut -c5 ` != "-" ]
            then
                echo "Group Read set on $file" >> $AUDITDIR/netrd_permission_$TIME.log
            fi
            if [ `echo $fileperm | /bin/cut -c6 ` != "-" ]
            then
                echo "Group Write set on $file" >> $AUDITDIR/netrd_permission_$TIME.log
            fi
            if [ `echo $fileperm | /bin/cut -c7 ` != "-" ]
            then
                echo "Group Execute set on $file" >> $AUDITDIR/netrd_permission_$TIME.log
            fi
            if [ `echo $fileperm | /bin/cut -c8 ` != "-" ]
            then
                echo "Other Read  set on $file" >> $AUDITDIR/netrd_permission_$TIME.log
            fi
            if [ `echo $fileperm | /bin/cut -c9 ` != "-" ]
            then
                echo "Other Write set on $file" >> $AUDITDIR/netrd_permission_$TIME.log
            fi
            if [ `echo $fileperm | /bin/cut -c10 ` != "-" ]
            then
                echo "Other Execute set on $file" >> $AUDITDIR/netrd_permission_$TIME.log
            fi
        fi
    done
done

echo "Checking for Presence of User .rhosts Files..."
for dir in `/bin/cat /etc/passwd | /bin/egrep -v '(root|halt|sync|shutdown)' |\
    /bin/awk -F: '($7 != "/sbin/nologin") { print $6 }'`; do
    for file in $dir/.rhosts; do
        if [ ! -h "$file" -a -f "$file" ]; then
            echo ".rhosts file in $dir" >> $AUDITDIR/rhosts_$TIME.log
        fi    done
done

echo "Checking Groups in /etc/passwd..."

for i in $(cut -s -d: -f4 /etc/passwd | sort -u ); do
  grep -q -P "^.*?:x:$i:" /etc/group
  if [ $? -ne 0 ]; then
    echo "Group $i is referenced by /etc/passwd but does not exist in /etc/group" >> $AUDITDIR/audit_$TIME.log
  fi
done

echo "Checking That Users Are Assigned Home Directories..."

cat /etc/passwd | awk -F: '{ print $1 " " $3 " " $6 }' | while read user uid dir; do
  if [ $uid -ge 500 -a ! -d "$dir" -a $user != "nfsnobody" ]; then
 echo "The home directory ($dir) of user $user does not exist." >> $AUDITDIR/audit_$TIME.log
 fi
done

echo "Checking That Defined Home Directories Exist..."

cat /etc/passwd | awk -F: '{ print $1 " " $3 " " $6 }' | while read user uid dir; do
 if [ $uid -ge 500 -a -d "$dir" -a $user != "nfsnobody" ]; then
 owner=$(stat -L -c "%U" "$dir")
 if [ "$owner" != "$user" ]; then
 echo "The home directory ($dir) of user $user is owned by $owner." >> $AUDITDIR/audit_$TIME.log
 fi
 fi
done

echo "Checking for Duplicate UIDs..."

/bin/cat /etc/passwd | /bin/cut -f3 -d":" | /bin/sort -n | /usr/bin/uniq -c |\
    while read x ; do
    [ -z "${x}" ] && break
    set - $x
    if [ $1 -gt 1 ]; then
        users=`/bin/gawk -F: '($3 == n) { print $1 }' n=$2 \
            /etc/passwd | /usr/bin/xargs`
        echo "Duplicate UID ($2): ${users}" >> $AUDITDIR/audit_$TIME.log
    fi
done

echo "Checking for Duplicate GIDs..."

/bin/cat /etc/group | /bin/cut -f3 -d":" | /bin/sort -n | /usr/bin/uniq -c |\
    while read x ; do
    [ -z "${x}" ] && break
    set - $x
    if [ $1 -gt 1 ]; then
        grps=`/bin/gawk -F: '($3 == n) { print $1 }' n=$2 \
            /etc/group | xargs`
        echo "Duplicate GID ($2): ${grps}" >> $AUDITDIR/audit_$TIME.log
    fi
done

echo "Checking That Reserved UIDs Are Assigned to System Accounts..."

defUsers="root bin daemon adm lp sync shutdown halt mail news uucp operator games
gopher ftp nobody nscd vcsa rpc mailnull smmsp pcap ntp dbus avahi sshd rpcuser
nfsnobody haldaemon avahi-autoipd distcache apache oprofile webalizer dovecot squid
named xfs gdm sabayon usbmuxd rtkit abrt saslauth pulse postfix tcpdump"
/bin/cat /etc/passwd | /bin/awk -F: '($3 < 500) { print $1" "$3 }' |\
    while read user uid; do
        found=0
        for tUser in ${defUsers}
        do
            if [ ${user} = ${tUser} ]; then
                found=1
            fi
        done
        if [ $found -eq 0 ]; then
            echo "User $user has a reserved UID ($uid)."  >> $AUDITDIR/audit_$TIME.log
        fi
    done

echo "Checking for Duplicate User Names..."

cat /etc/passwd | cut -f1 -d":" | sort -n | /usr/bin/uniq -c |\
    while read x ; do
    [ -z "${x}" ] && break
    set - $x
    if [ $1 -gt 1 ]; then
        uids=`/bin/gawk -F: '($1 == n) { print $3 }' n=$2 \
            /etc/passwd | xargs`
        echo "Duplicate User Name ($2): ${uids}"  >> $AUDITDIR/audit_$TIME.log
    fi
done

echo "Checking for Duplicate Group Names..."

cat /etc/group | cut -f1 -d":" | /bin/sort -n | /usr/bin/uniq -c |\
    while read x ; do
    [ -z "${x}" ] && break
    set - $x
    if [ $1 -gt 1 ]; then
        gids=`/bin/gawk -F: '($1 == n) { print $3 }' n=$2 \
            /etc/group | xargs`
        echo "Duplicate Group Name ($2): ${gids}"  >> $AUDITDIR/audit_$TIME.log
    fi
done

echo "Checking for Presence of User .netrc Files..."

for dir in `/bin/cat /etc/passwd |\
    /bin/awk -F: '{ print $6 }'`; do
    if [ ! -h "$dir/.netrc" -a -f "$dir/.netrc" ]; then
        echo ".netrc file $dir/.netrc exists"  >> $AUDITDIR/audit_$TIME.log
    fi
done

echo "Checking for Presence of User .forward Files..."

for dir in `/bin/cat /etc/passwd |\
    /bin/awk -F: '{ print $6 }'`; do
    if [ ! -h "$dir/.forward" -a -f "$dir/.forward" ]; then
        echo ".forward file $dir/.forward exists"  >> $AUDITDIR/audit_$TIME.log
    fi
done

echo "Modifying Network Parameters..."
cp /etc/sysctl.conf $AUDITDIR/sysctl.conf_$TIME.bak

cat > /etc/sysctl.conf << 'EOF'
net.ipv4.ip_forward=0
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.default.send_redirects=0
net.ipv4.conf.all.accept_source_route=0
net.ipv4.conf.default.accept_source_route=0
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.default.accept_redirects=0
net.ipv4.conf.all.secure_redirects=0
net.ipv4.conf.default.secure_redirects=0
net.ipv4.conf.all.log_martians=1
net.ipv4.conf.default.log_martians=1
net.ipv4.route.flush=1
net.ipv4.icmp_echo_ignore_broadcasts=1
net.ipv4.icmp_ignore_bogus_error_responses=1
net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.default.rp_filter=1
net.ipv4.tcp_syncookies=1
net.ipv6.conf.all.accept_ra=0
net.ipv6.conf.default.accept_ra=0
net.ipv6.conf.all.accept_redirects=0
net.ipv6.conf.default.accept_redirects=0
kernel.randomize_va_space = 2
EOF

sysctl -w kernel.randomize_va_space=2

echo "Disabling IPv6..."
cp /etc/sysconfig/network $AUDITDIR/network_$TIME.bak
echo "NETWORKING_IPV6=no" >> /etc/sysconfig/network
echo "IPV6INIT=no" >> /etc/sysconfig/network
echo "options ipv6 disable=1" >> /etc/modprobe.d/ipv6.conf
echo "net.ipv6.conf.all.disable_ipv6=1" >> /etc/sysctl.d/ipv6.conf

echo "Restricting Access to the su Command..."
cp /etc/pam.d/su $AUDITDIR/su_$TIME.bak
pam_su='/etc/pam.d/su'
line_num="$(grep -n "^\#auth[[:space:]]*required[[:space:]]*pam_wheel.so[[:space:]]*use_uid" ${pam_su} | cut -d: -f1)"
sed -i "${line_num} a auth		required	pam_wheel.so use_uid" ${pam_su}

echo "Clean history" 
history -c && history -w


echo ""
echo "Successfully Completed"
echo "Please check $AUDITDIR"


