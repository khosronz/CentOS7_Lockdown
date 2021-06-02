sudo fdisk /dev/sdb
#     m
#     o
#     n
#     p    

#     t
#     8e
#     w

lsblk 

sudo pvcreate /dev/sdb1
sudo vgcreate share /dev/sdb1

sudo lvcreate -n tmp -L 2G share
mkfs.xfs /dev/share/tmp

vim /etc/fstab
    /tmp /var/tmp none rw,noexec,nosuid,nodev,bind 0 0

sudo lvcreate -n var_log_audit -L 1G share
sudo mkfs.xfs /dev/share/var_log_audit
sudo mkdir -p /mnt/var_log_audit
sudo mount /dev/share/var_log_audit /mnt/var_log_audit
sudo rsync -aqxP /var/log/audit/* /mnt/var_log_audit
sudo umount /mnt/var_log_audit/ 
sudo df -h /mnt/var_log_audit
sudo vim /etc/fstab
    /dev/share/var_log_audit /var/log/audit  xfs     defaults   0 0
sudo mount -a
sudo df -hT | grep /var/log/audit
sudo vim /etc/fstab
    tmpfs /dev/shm tmpfs defaults,noexec,nodev,nosuid,seclabel 0 0
    
sudo mount -a
mount -o remount,noexec /dev/shm