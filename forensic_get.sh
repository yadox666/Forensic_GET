#!/bin/bash -i
#####################################################################################
# file: forensic_get.sh
# by Yago Hansen 2020 (and a lot of google searches)
# Script to get forensics information on live systems
# 
# WARNING:  Remember that this kind of live forensics is mostly not recommended!!!!
#           Do always a SNAPSHOT of the machine state before executing it!!!
#           Use this script in a Lab on Virtual machine SNAPSHOT to investigate!!!
#           I am not responsible for any damage caused by this script!!!
#           It's very important to analyze deleted files before running this script!!!
#
# TO-DO:    All logs could be acquired inside defined date range
#           Continue from last saved log or tool after stopping execution with ctrl+c
#           Users apache2,nginx and web application user usually is www-data
#           zgrep en vez de grep para ver dentro de tgz y zips
#           include some tools like exiftool in a binary format statically compiled
#####################################################################################

#########################################################################
# Get script configuration from forensic_get.conf
#########################################################################
config_file="$(pwd)/forensic_get.conf"
if [ -f "$config_file" ] ; then
	[ -x "$config_file" ] || chmod 755 "$config_file"
else
	echo "Cannot find configuration file: $config_file"
	echo "Please review or create config file!"
	exit 1
fi

if ! source "$config_file" ; then
	echo "Cannot read configuration file: $config_file"
	echo "Please review settings or format inside it!"
	exit 1
fi

#########################################################################
# Check data extraction destination disk
#########################################################################
usbdev=$(blkid | grep "$usbid" | cut -f1 -d' ' | tr -d ':')
if [ -z "$usbdev" ] ; then
	echo "Cannot find Flash disk $usbid ($usbdev), quitting now!"
	exit 2
fi
devicename=$(hostname -f)
filedate=$(date '+%Y%m%d%H%M')
biosdate=$(hwclock -r)
normaldate=$(date)
user=$(whoami)

[ -z "$mysqldb" ] && mysqldb="--all-databases"

if mount | grep -qi "$usbdev" ; then
	mountpoint=$(mount | grep $usbdev | awk '{print $3}')
else
	mkdir -p /tmp/pendrive/
	e2fsk -p -y $usbdev 2>1 >/tmp/e2fsc.log 
	if ! mount $usbdev /tmp/pendrive ; then
		echo "Cannot mount $usbdev pendrive, quitting now!"
		exit 3
	else
		mountpoint="/tmp/pendrive"
	fi
fi
base_dir="$mountpoint/$devicename/$filedate/"

#########################################################################
# Show beautiful ASCII logo
#########################################################################
if [ -f "forensic_logo.sh" ] ; then
	[ -x "forensic_logo.sh" ] || chmod 755 "forensic_logo.sh"
	./forensic_logo.sh
fi

#########################################################################
# Check if system is online
#########################################################################
wget -q -t1 -T3 google.com ; online=$? ; rm index.html 2>/dev/null
[ "$online" == "0" ] && online=1 || online=0

#########################################################################
# System information recopilation
#########################################################################
mkdir -p $base_dir

cp "$config_file"  >> "${base_dir}/fgconfig.txt"
echo "Config file $config_file included..."

echo ""  | tee -a "${base_dir}/index.txt"
echo " +-+-+-+-+-+-+-+-+ +-+-+-+-+ +-+-+-+-+-+-+-+-+-+" | tee -a "${base_dir}/index.txt"
echo " |F|o|r|e|n|s|i|c| |D|a|t|a| |E|x|t|r|a|c|t|o|r|" | tee -a "${base_dir}/index.txt"
echo " +-+-+-+-+-+-+-+-+ +-+-+-+-+ +-+-+-+-+-+-+-+-+-+" | tee -a "${base_dir}/index.txt"
echo ""  | tee -a "${base_dir}/index.txt"
echo "-----------------------------------------------------" | tee -a "${base_dir}/index.txt"
echo "System host name: $devicename" | tee -a "${base_dir}/index.txt"
echo "-----------------------------------------------------" | tee -a "${base_dir}/index.txt"
echo "Forensic investigator: $investigator" | tee -a "${base_dir}/index.txt"
echo "-----------------------------------------------------" | tee -a "${base_dir}/index.txt"
echo "Data extracted with user: $user" | tee -a "${base_dir}/index.txt"
echo "                          $(id)"  | tee -a "${base_dir}/index.txt"
echo "-----------------------------------------------------" | tee -a "${base_dir}/index.txt"
timedatectl | tee -a "${base_dir}/index.txt"
echo "Extraction time (OS): $normaldate" >> "${base_dir}/index.txt"
echo "Extraction time (BIOS): $normaldate" >> "${base_dir}/index.txt"
echo "System uptime: $(uptime)" | tee -a "${base_dir}/index.txt"
echo "System online now: $online" | tee -a "${base_dir}/index.txt"
echo "-----------------------------------------------------" | tee -a "${base_dir}/index.txt"
echo "Investigation suspicious initial date: $start_date" | tee -a "${base_dir}/index.txt"
echo "Investigation suspicious end date: $end_date" | tee -a "${base_dir}/index.txt"
echo "-----------------------------------------------------" | tee -a "${base_dir}/index.txt"
echo "Extracted data destination: $base_dir" | tee -a "${base_dir}/index.txt"
echo "Extracted data USB flashdisk serial: $usbid ($usbdev)" | tee -a "${base_dir}/index.txt"
echo "-----------------------------------------------------" | tee -a "${base_dir}/index.txt"
echo "Main investigation dir: $investigateonlydir" | tee -a "${base_dir}/index.txt"
echo "Web applicaton dir: $wwwdir" | tee -a "${base_dir}/index.txt"
echo "Web applicaton media dir: ${wwwmedia}" | tee -a "${base_dir}/index.txt"
echo "Web applicaton username: ${wwwuser}" | tee -a "${base_dir}/index.txt"
echo "Web applicaton group: ${wwwgroup}" | tee -a "${base_dir}/index.txt"
echo "-----------------------------------------------------" | tee -a "${base_dir}/index.txt"
echo "System OS: $(uname -a)" | tee -a "${base_dir}/index.txt"
cat /etc/*release* >> "${base_dir}/index.txt"
echo "-----------------------------------------------------" | tee -a "${base_dir}/index.txt"
echo

#########################################################################
# Command history investigation
#########################################################################
# Save the command history for every user, if present
echo "[Command history for root]"  | tee -a "${base_dir}/history_root.txt"
cp /root/.*history "${base_dir}/history_root_orig.txt" 2>>"${base_dir}/errors.log" 
HISTTIMEFORMAT='%F %T '   # Set the hitory time format.
set -o history            # Enable the history.
history >> "${base_dir}/history_root.txt"
for name in $(ls /home) ; do
	echo "[Command history for ${name}]"
	cp /home/$name/.*history "${base_dir}/history_${name}_orig.txt" 2>>"${base_dir}/errors.log" 
done

#########################################################################
# Fetch environment variables
#########################################################################
echo "[Environment variables]" | tee -a "${base_dir}/env.txt"
env >> "${base_dir}/env.txt"
echo -e "\n" >> "${base_dir}/env.txt"
echo "[Shell variables]" | tee -a "${base_dir}/env.txt"
set >> "${base_dir}/env.txt"

#########################################################################
# Auto Run investigation
#########################################################################
# /etc/profile
if [ -e "/etc/profile" ] ; then
    echo "[/etc/profile]" | tee -a "${base_dir}/shell.txt"
    ls -la /etc/profile >> "${base_dir}/shell.txt"
    cat /etc/profile >> "${base_dir}/shell.txt"
    echo -e "\n" >> "${base_dir}/shell.txt"
fi
if [ -e "/etc/bash.bashrc" ] ; then
    echo "[/etc/bash.bashrc]" | tee -a "${base_dir}/shell.txt"
    ls -la /etc/bash.bashrc >> "${base_dir}/shell.txt"
    cat /etc/bash.bashrc >> "${base_dir}/shell.txt"
    echo -e "\n" >> "${base_dir}/shell.txt"
fi

find /root /home -type f \( -name .bash* -o -name .profile* \) -a -not -name .bash_history -exec sh -c 'echo  "[session script found: $1]" ; ls -la $1 ; echo ; cat "$1"; echo' sh {} \; 2>>"${base_dir}/errors.log" >> "${base_dir}/shell.txt"


#########################################################################
# Programmed tasks investigation (cron jobs)
#########################################################################
echo "[Crontab for this user]" | tee -a "${base_dir}/cron.txt"
crontab -l 2>>"${base_dir}/cron.txt"  >>"${base_dir}/cron.txt" 
echo -e "\n" >> "${base_dir}/cron.txt"
echo "[Cron files]" | tee -a "${base_dir}/cron.txt"
echo -e "\n" >> "${base_dir}/cron.txt"
find /etc/cron* -type f -exec sh -c 'echo  "[cron file found: $1]" ; ls -la $1 ; echo ; cat "$1"; echo' sh {} \; 2>>"${base_dir}/errors.log" >> "${base_dir}/cron.txt"

#########################################################################
# System init scripts
#########################################################################
echo "[Autorun scripts]" | tee -a "${base_dir}/rcsysinit.txt"
echo -e "\n" >> "${base_dir}/sysinit.txt"
echo "[Present rc sysinit autorun scripts]" >> "${base_dir}/rcsysinit.txt"
find /etc/rc* -type f -exec sh -c 'echo  "[rc sysinit file found: $1]" ; ls -la $1 ; echo ; cat "$1"; echo' sh {} \; 2>>"${base_dir}/errors.log" >> "${base_dir}/rcsysinit.txt"

echo "[Actual initlevel: $(runlevel)]" | tee -a "${base_dir}/initd.txt"
echo -e "\n" >> "${base_dir}/initd.txt"
echo "[Present init.d autorun scripts]" | tee -a "${base_dir}/initd.txt"
echo -e "\n" >> "${base_dir}/initd.txt"
find /etc/init.d/ -type f -exec sh -c 'echo  "[init.d script found: $1]" ; ls -la $1 ; echo ; cat "$1"; echo' sh {} \; 2>>"${base_dir}/errors.log" >> "${base_dir}/initd.txt"

echo "[Present systemd services configuration files]" | tee -a "${base_dir}/systemd.txt"
find /etc/systemd/ -type f -exec sh -c 'echo  "[systemd configuration file found: $1]" ; ls -la $1 ; echo ; cat "$1"; echo' sh {} \; 2>>"${base_dir}/errors.log" >> "${base_dir}/systemd.txt"

#########################################################################
# Running processes investigation
#########################################################################
echo "[All running processes]" | tee -a "${base_dir}/proc.txt"
ps aux  2>>"${base_dir}/errors.log" >> "${base_dir}/proc.txt"
echo -e "\n" >> "${base_dir}/proc.txt"
echo "[User processes]" | tee -a "${base_dir}/proc.txt"
ps -l  2>>"${base_dir}/errors.log" >> "${base_dir}/proc.txt"
echo -e "\n" >> "${base_dir}/proc.txt"
echo "[Top processes]" | tee -a "${base_dir}/proc.txt"
top n 1 b  2>>"${base_dir}/errors.log" >> "${base_dir}/proc.txt"
echo -e "\n" >> "${base_dir}/proc.txt"
echo "[Open files]" | tee -a "${base_dir}/proc.txt"
lsof 2>>"${base_dir}/errors.log" >> "${base_dir}/proc.txt"

#########################################################################
# System devices and drivers (USB connected devices)
#########################################################################
echo "[Used modules]" | tee -a "${base_dir}/modules.txt"
lsmod  >> "${base_dir}/modules.txt"
echo -e "\n" >> "${base_dir}/modules.txt"
echo "[Kernel messages]" | tee -a "${base_dir}/modules.txt"
dmesg >> "${base_dir}/modules.txt"
echo -e "\n" >> "${base_dir}/modules.txt"
echo "[USB connected devices]" | tee -a "${base_dir}/modules.txt"
lsusb -v 2>>"${base_dir}/errors.log" >> "${base_dir}/modules.txt"
echo -e "\n" >> "${base_dir}/modules.txt"
echo "[PCI connected devices]" | tee -a "${base_dir}/modules.txt"
lspci -v 2>>"${base_dir}/errors.log" >> "${base_dir}/modules.txt"

#########################################################################
# Users investigation
#########################################################################
echo "[Users passwd file date]" | tee -a "${base_dir}/users.txt"
ls -la /etc/passwd >> "${base_dir}/users.txt"
echo -e "\n" >> "${base_dir}/users.txt"
echo "[System users]" | tee -a "${base_dir}/users.txt"
sort -nk3 -t: /etc/passwd >> "${base_dir}/users.txt"
echo -e "\n" >> "${base_dir}/users.txt"
echo "[groups file date]" | tee -a "${base_dir}/users.txt"
ls -la /etc/group >> "${base_dir}/users.txt"
echo -e "\n" >> "${base_dir}/users.txt"
echo "[System groups]" | tee -a "${base_dir}/users.txt"
sort -nk3 -t: /etc/group >> "${base_dir}/users.txt"
echo -e "\n" >> "${base_dir}/users.txt"
echo "[shadow password hashes]" | tee -a "${base_dir}/users.txt"
ls -la /etc/shadow >> "${base_dir}/users.txt"
echo -e "\n" >> "${base_dir}/users.txt"
echo "[shadow hashes]" | tee -a "${base_dir}/users.txt"
cat /etc/shadow >> "${base_dir}/users.txt"

echo "[sudo related files]"| tee -a "${base_dir}/sudoers.txt"
echo "Name,Last access,Last modification,Last status chg,User/ID,Group/ID,Permissions,Size(bytes),type" >> "${base_dir}/sudoers.txt"
find /etc -type f -name '*sudoers*' -printf "%p,%A+,%T+,%C+,%u,%g,%m,%M,%s," -exec sh -c 'file "$1" | cut -d: -f2-' sh {} \; 2>>"${base_dir}/errors.log" >> "${base_dir}/sudoers.txt"
echo -e "\n" >> "${base_dir}/sudoers.txt"
echo "[sudoers.d directory files]" >> "${base_dir}/sudoers.txt"
find /etc/sudoers.d/ -type f -exec sh -c 'echo  "[sudoers.d configuration file found: $1]" ; ls -la $1 ; echo ; cat "$1"; echo' sh {} \; 2>>"${base_dir}/errors.log" >> "${base_dir}/sudoers.txt"

#########################################################################
# Login investigation
#########################################################################
echo "[last login]" | tee -a "${base_dir}/loginsnow.txt"
last >> "${base_dir}/loginsnow.txt"
echo -e "\n" >> "${base_dir}/loginsnow.txt"

# /var/run/utmp - users who are currently logged onto the system
echo "[last login utmp - users who are currently logged in]" | tee -a "${base_dir}/loginsnow.txt"
last -f /var/run/utmp >> "${base_dir}/loginsnow.txt"

# /var/log/btmp - bad login attempts
echo "[btmp - bad login attempts]" | tee -a "${base_dir}/loginsfail.txt"
ls -lat /var/log/wtmp* >> "${base_dir}/loginsfail.txt"
echo -e "\n" >> "${base_dir}/loginsfail.txt"
echo "[System btmp bad logins $start_date-$end_date]" | tee -a "${base_dir}/loginsfail.txt"
find /var/log/ -type f -name btmp* -print0 | xargs -0 ls -tr | while read file ; do
	gunzip $file 2>/dev/null
	filename="${file%.gz}"
	if last --help 2>&1 | grep -q '\-s' ; then  ## last version supports time range parameter -s
		if [ -n "$start_date" ] ; then  ## Defined date range start date
			if [ -n "$end_date" ] ; then  ## Defined date range end date
				last -s "$start_date" -t "$end_date" -f "$filename" >>"${base_dir}/loginsfail.txt"
			else
				last -s "$start_date" -f "$filename" >>"${base_dir}/loginsfail.txt"
			fi
		else
			last -f "$filename" >>"${base_dir}/loginsfail.txt"
		fi
	else  ## does not support time range
		last -f "$filename" >>"${base_dir}/loginsfail.txt"
	fi
done

# /var/log/wtmp - history for utmp file. Logs of all logged in and logged out users in the past
# Files that match access time inside of the investigation period
echo "[wtmp - Logs of all logged in and logged out users in the past]" | tee -a "${base_dir}/logins.txt"
ls -lat /var/log/wtmp* >> "${base_dir}/logins.txt"
echo -e "\n" >> "${base_dir}/logins.txt"
echo "[System wtmp logins $start_date-$end_date]" | tee -a "${base_dir}/logins.txt"
find /var/log/ -type f -name wtmp* -print0 | xargs -0 ls -tr | while read file ; do
	gunzip $file 2>/dev/null
	filename="${file%.gz}"
	if last --help 2>&1 | grep -q '\-s' ; then  ## last version supports time range parameter -s
		if [ -n "$start_date" ] ; then
			if [ -n "$end_date" ] ; then
				last -s "$start_date" -t "$end_date" -f "$filename" >>"${base_dir}/logins.txt"
			else
				last -s "$start_date" -f "$filename" >>"${base_dir}/logins.txt"
			fi
		else
			last -f "$filename" >>"${base_dir}/logins.txt"
		fi
	else   ## does not support time range
		last -f "$filename" >>"${base_dir}/logins.txt"
	fi
done

echo "[SSH successfull logins]" | tee -a "${base_dir}/loginSSHok.txt"
echo "[SSH Invalid logins]" | tee -a "${base_dir}/loginSSHfail.txt"
find /var/log/ -type f -name auth.log* -print0 | xargs -0 ls -tr | while read file ; do
	zgrep -i "sshd" $file 2>>"${base_dir}/errors.log" | grep "opened" >> "${base_dir}/loginSSHok.txt"
	zgrep -i "invalid|failed" $file 2>>"${base_dir}/errors.log" >> "${base_dir}/loginSSHfail.txt"
done
# Try to get fail2ban service logs
if [ -d /etc/fail2ban/ ] ; then
	echo "[Analyze fail2ban service logs]" | tee -a "${base_dir}/fail2banlogs.txt"
	zgrep -h "Ban " /var/log/fail2ban.log* | awk '{print $NF}' | sort | uniq -c | sort -n 2>>"${base_dir}/errors.log" >> "${base_dir}/fail2banlogs.txt"
fi

#########################################################################
# Network investigation
#########################################################################
echo "[Network interfaces status]" | tee -a "${base_dir}/network.txt"
ifconfig -a 2>>"${base_dir}/errors.log" >> "${base_dir}/network.txt" || ip address 2>>"${base_dir}/errors.log"  >> "${base_dir}/network.txt"
echo -e "\n" >> "${base_dir}/network.txt"
echo "[Network configuration files]" | tee -a "${base_dir}/network.txt"
echo -e "\n" >> "${base_dir}/network.txt"
find /etc/network/ -type f -exec sh -c 'echo  "[session script found: $1]" ; ls -la $1 ; echo ; cat "$1"; echo' sh {} \; 2>>"${base_dir}/errors.log" >> "${base_dir}/network.txt"
echo -e "\n" >> "${base_dir}/network.txt"
echo "[DNS configuration file]" | tee -a "${base_dir}/network.txt"
cat /etc/resolv.conf 2>>"${base_dir}/errors.log" >> "${base_dir}/network.txt"
echo -e "\n" >> "${base_dir}/network.txt"
echo "[Linux hosts file]" | tee -a "${base_dir}/network.txt"
cat /etc/hosts 2>>"${base_dir}/errors.log" >> "${base_dir}/network.txt"
echo -e "\n" >> "${base_dir}/network.txt"
echo "[System hostname]" | tee -a "${base_dir}/network.txt"
cat /etc/hostname 2>>"${base_dir}/errors.log" >> "${base_dir}/network.txt"
echo -e "\n" >> "${base_dir}/network.txt"
echo "[Routing table]" | tee -a "${base_dir}/network.txt"
ip route 2>>"${base_dir}/errors.log" >> "${base_dir}/network.txt"
echo -e "\n" >> "${base_dir}/network.txt"
echo "[Network connections (netstat)]" | tee -a "${base_dir}/network.txt"
netstat -putan  2>>"${base_dir}/errors.log" >> "${base_dir}/network.txt"
echo -e "\n" >> "${base_dir}/network.txt"
echo "[Network connections (listening)]" | tee -a "${base_dir}/network.txt"
ss -tunpo state listening >> "${base_dir}/network.txt"
echo -e "\n" 2>>"${base_dir}/errors.log" >> "${base_dir}/network.txt"
echo "[Network connections (established)]" | tee -a "${base_dir}/network.txt"
ss -tunpo state established 2>>"${base_dir}/errors.log" >> "${base_dir}/network.txt"
echo -e "\n" >> "${base_dir}/network.txt"

echo "[Network Firewall rules]" | tee -a "${base_dir}/network.txt"
iptables -vL -t filter 2>>"${base_dir}/errors.log" >> "${base_dir}/network.txt"
iptables -vL -t nat 2>>"${base_dir}/errors.log" >> "${base_dir}/network.txt"
iptables -vL -t mangle 2>>"${base_dir}/errors.log" >> "${base_dir}/network.txt"
iptables -vL -t raw 2>>"${base_dir}/errors.log" >> "${base_dir}/network.txt"
iptables -vL -t security 2>>"${base_dir}/errors.log" >> "${base_dir}/network.txt"
echo -e "\n" >> "${base_dir}/network.txt"

echo "[OpenSSH Server version]" | tee -a "${base_dir}/network.txt"
sshd -V 2>&1 | grep -i openssh >> "${base_dir}/network.txt"
echo -e "\n" >> "${base_dir}/network.txt"
echo "[OpenSSH Server configuration]" | tee -a "${base_dir}/network.txt"
cat /etc/ssh/sshd_config >> "${base_dir}/network.txt"

#########################################################################
# General files investigation
#########################################################################
echo "[Filesystems investigation]"
echo "[Physical and virtual harddisks present in the system]" >> "${base_dir}/fsinfo.txt"
fdisk -l 2>>"${base_dir}/errors.log" >> "${base_dir}/fsinfo.txt"
echo -e "\n" >> "${base_dir}/fsinfo.txt"
echo "[Mounted filesystems]" >> "${base_dir}/fsinfo.txt"
mount 2>>"${base_dir}/errors.log" >> "${base_dir}/fsinfo.txt"
echo -e "\n" >> "${base_dir}/fsinfo.txt"
echo "[FStab automount config file]" >> "${base_dir}/fsinfo.txt"
cat /etc/fstab 2>>"${base_dir}/errors.log" >> "${base_dir}/fsinfo.txt"
echo -e "\n" >> "${base_dir}/fsinfo.txt"
echo "[Mtab actually mounted filesystems]" >> "${base_dir}/fsinfo.txt"
cat /etc/mtab 2>>"${base_dir}/errors.log" >> "${base_dir}/fsinfo.txt"

echo "[All files timeline in CSV format]"
echo "Name,Last access,Last modification,Last status chg,User/ID,Group/ID,Permissions,Size(bytes),type" >> "${base_dir}/allfilestimeline.csv"
find "$investigateonlydir" ! -path "${mountpoint}*" -type f -printf "%p,%A+,%T+,%C+,%u,%g,%m,%M,%s," -exec sh -c 'file "$1" | cut -d: -f2-' sh {} \; 2>>"${base_dir}/errors.log" >> "${base_dir}/allfilestimeline.csv"

echo "[All directories timeline in CSV format]"
echo "	" >> "${base_dir}/alldirstimeline.csv"
find "$investigateonlydir" ! -path "${mountpoint}*" -type d -printf "%p,%A+,%T+,%C+,%u,%g,%m,%M,%s," 2>>"${base_dir}/errors.log" >> "${base_dir}/alldirstimeline.csv"

echo "[List of all directories in a tree format]" | tee -a "${base_dir}/dirtree.txt"
tree -dxn -o /tmp/dirtree.txt "$investigateonlydir" 2>>"${base_dir}/errors.log" || ls -R "$investigateonlydir" | grep ":$" | sed -e 's/:$//' -e 's/[^-][^\/]*\//--/g' -e 's/^/   /' -e 's/-/|/' 2>>"${base_dir}/errors.log" >> "${base_dir}/dirtree.txt"

echo "[/tmp directory properties]" | tee -a "${base_dir}/filestmp.txt"
ls -lRa /tmp/ 2>>"${base_dir}/errors.log" >> "${base_dir}/filestmp.txt"

echo "[/mnt directory properties]" | tee -a "${base_dir}/filesmnt.txt"
ls -lRa /mnt/ 2>>"${base_dir}/errors.log" >> "${base_dir}/filesmnt.txt"

#########################################################################
# Files that match access time inside of the investigation period
#########################################################################
if [ -n "$start_date" ] ; then
	if [ -n "$end_date" ] ; then
		echo "[Suspicious files in period $start_date-$end_date in CSV format in $investigateonlydir]"
		echo "Name,Last access,Last modification,Last status chg,User/ID,Group/ID,Permissions,Size(bytes),type" >> "${base_dir}/filesperiod.csv"
		find "$investigateonlydir" ! -path "${mountpoint}*" ! -path "${wwwdir}*" -type f -newerat "$start_date" ! -newerat "$end_date" -printf "%p,%A+,%T+,%C+,%u,%g,%m,%M,%s," -exec sh -c 'file "$1" | cut -d: -f2-' sh {} \; 2>>"${base_dir}/errors.log" >> "${base_dir}/filesperiod.csv"
		echo "[Suspicious files in period $start_date-$end_date in CSV format in Webdir]"
		echo "Name,Last access,Last modification,Last status chg,User/ID,Group/ID,Permissions,Size(bytes),type" >> "${base_dir}/filesperiod_webdir.csv"
		find "$wwwdir" -type f -newerat "$start_date" ! -newerat "$end_date" -printf "%p,%A+,%T+,%C+,%u,%g,%m,%M,%s," -exec sh -c 'file "$1" | cut -d: -f2-' sh {} \; 2>>"${base_dir}/errors.log" >> "${base_dir}/filesperiod_webdir.csv"
		if [ "$archive" == "1" ] ; then
		    find "$investigateonlydir" -type f -newerat "$start_date" ! -newerat "$end_date" -exec tar -rf "${base_dir}/filesperiod.tar" {} 2>>"${base_dir}/errors.log" \;
		fi
	else
		echo "[Suspicious files in period $start_date-$end_date in CSV format in $investigateonlydir]"
		echo "Name,Last access,Last modification,Last status chg,User/ID,Group/ID,Permissions,Size(bytes),type" >> "${base_dir}/filesperiod.csv"
		find "$investigateonlydir" ! -path "${mountpoint}*" ! -path "${wwwdir}*" -type f -newerat "$start_date" -printf "%p,%A+,%T+,%C+,%u,%g,%m,%M,%s," -exec sh -c 'file "$1" | cut -d: -f2-' sh {} \; 2>>"${base_dir}/errors.log" >> "${base_dir}/filesperiod.csv"
		echo "[Suspicious files in period $start_date-$end_date in CSV format in $wwwdir]"
		echo "Name,Last access,Last modification,Last status chg,User/ID,Group/ID,Permissions,Size(bytes),type" >> "${base_dir}/filesperiod_webdir.csv"
		find "$wwwdir" -type f -newerat "$start_date" -printf "%p,%A+,%T+,%C+,%u,%g,%m,%M,%s," -exec sh -c 'file "$1" | cut -d: -f2-' sh {} \; 2>>"${base_dir}/errors.log" >> "${base_dir}/filesperiod_webdir.csv"
		if [ "$archive" == "1" ] ; then
		    find "$investigateonlydir" ! -path "${mountpoint}*" -type f -newerat "$start_date" -exec tar -rf "${base_dir}/filesperiod.tar" {} 2>>"${base_dir}/errors.log" \;
		fi
	fi
fi

#########################################################################
# Investigating executable files
#########################################################################
echo "[Suspicious files .bin .exe .sh extension]"
echo "Name,Last access,Last modification,Last status chg,User/ID,Group/ID,Permissions,Size(bytes),type" >> "${base_dir}/filesbin.csv"
find "$investigateonlydir" ! -path "${mountpoint}*" ! -path "${wwwdir}*" -type f \( -name "*.exe" -o -name "*.bin" -o -name "*.sh" \) -printf "%p,%A+,%T+,%C+,%u,%g,%m,%M,%s," -exec sh -c 'file "$1" | cut -d: -f2-' sh {} \; 2>>"${base_dir}/errors.log" >> "${base_dir}/filesbin.csv"
echo "Name,Last access,Last modification,Last status chg,User/ID,Group/ID,Permissions,Size(bytes),type" >> "${base_dir}/filesbin_webdir.csv"
find "$wwwdir" -type f \( -name "*.exe" -o -name "*.bin" -o -name "*.sh" \) -printf "%p,%A+,%T+,%C+,%u,%g,%m,%M,%s," -exec sh -c 'file "$1" | cut -d: -f2-' sh {} \; 2>>"${base_dir}/errors.log" >> "${base_dir}/filesbin_webdir.csv"
echo "[Suspicious files marked as executables]"
echo "Name,Last access,Last modification,Last status chg,User/ID,Group/ID,Permissions,Size(bytes),type" >> "${base_dir}/filesexecperm.csv"
find "$investigateonlydir" ! -path "${mountpoint}*" ! -path "${wwwdir}*" -type f -perm /u=x,g=x,o=x -type f -executable -printf "%p,%A+,%T+,%C+,%u,%g,%m,%M,%s," -exec sh -c 'file "$1" | cut -d: -f2-' sh {} \; 2>>"${base_dir}/errors.log" >> "${base_dir}/filesexecperm.csv"
echo "Name,Last access,Last modification,Last status chg,User/ID,Group/ID,Permissions,Size(bytes),type" >> "${base_dir}/filesexecperm_webdir.csv"
find "$wwwdir" -type f -perm /u=x,g=x,o=x -type f -executable -printf "%p,%A+,%T+,%C+,%u,%g,%m,%M,%s," -exec sh -c 'file "$1" | cut -d: -f2-' sh {} \; 2>>"${base_dir}/errors.log" >> "${base_dir}/filesexecperm_webdir.csv"

echo "[Executable files in media directory]"
if [ -n "${wwwmedia}" ] && [ -d "${wwwmedia}" ] ; then
	echo "Name,Last access,Last modification,Last status chg,User/ID,Group/ID,Permissions,Size(bytes),type" >> "${base_dir}/filesexe_media.csv"
	find "$wwwmedia" -type f -perm /u=x,g=x,o=x -executable -printf "%p,%A+,%T+,%C+,%u,%g,%m,%M,%s," -exec sh -c 'file "$1" | cut -d: -f2-' sh {} \; 2>>"${base_dir}/errors.log" >> "${base_dir}/filesexe_media.csv"
fi

#########################################################################
# Image EXIF type metadata investigation in media directory
#########################################################################
if [ "$imgmetadata" == "1" ] ; then
	if [ -n "${wwwmedia}" ] && [ -d "${wwwmedia}" ] ; then
		[ "$online" == "1" ] && apt-get --yes --force-yes install exiftool
		echo "[Extracting EXIF image metadata from images]"  | tee -a "${base_dir}/imagesmetadata_media.txt"
		echo "Name,Last access,Last modification,Last status chg,User/ID,Group/ID,Permissions,Size(bytes),type" >> "${base_dir}/imagesmetadata_media.txt"
		find "$wwwmedia" \( -name "*.jpg" -o -name "*.jpeg" -o -name "*.png" -o -name "*.tif" -o -name "*.tiff" \)-type f -printf "%p,%A+,%T+,%C+,%u,%g,%m,%M,%s\n" -exec sh -c 'exiftool "$1" ; printf -- '-%.0s' $(seq 40); echo "" ' sh {} \; 2>>"${base_dir}/errors.log" >> "${base_dir}/imagesmetadata_media.txt"
	fi
fi

#########################################################################
# Investigating files and directories permissions
#########################################################################
echo "[Files owned by root]"
echo "[Name,Last access,Last modification,Last status chg,User/ID,Group/ID,Permissions,Size(bytes)]" >> "${base_dir}/filesroot.csv"
find "$investigateonlydir" ! -path "${mountpoint}*" ! -path "${wwwdir}*" -type f -user root -o -group root -printf "%p,%A+,%T+,%C+,%u,%g,%m,%M,%s\n" 2>>"${base_dir}/errors.log" >> "${base_dir}/filesroot.csv"
echo "[Name,Last access,Last modification,Last status chg,User/ID,Group/ID,Permissions,Size(bytes)]" >> "${base_dir}/filesroot_webdir.csv"
find "$wwwdir" -type f -user root -o -group root -printf "%p,%A+,%T+,%C+,%u,%g,%m,%M,%s\n" 2>>"${base_dir}/errors.log" >> "${base_dir}/filesroot_webdir.csv"

echo "[Files in Webdir owned by a different user than ${wwwuser} or group than ${wwwgroup} inside Webdir]"
echo "[Name,Last access,Last modification,Last status chg,User/ID,Group/ID,Permissions,Size(bytes)]" >> "${base_dir}/filesbaduser_webdir.csv"
find "${wwwdir}" -type f -o -type d -not -user "${wwwuser}" -o -not -group "${wwwgroup}" -printf "%p,%A+,%T+,%C+,%u,%g,%m,%M,%s\n" 2>>"${base_dir}/errors.log" >> "${base_dir}/filesbaduser_webdir.csv"

echo "[Files in Webdir with unrecommended permissions (644 or 660)]"
echo "[Name,Last access,Last modification,Last status chg,User/ID,Group/ID,Permissions,Size(bytes)]" >> "${base_dir}/filesbadperms_webdir.csv"
find ${wwwdir} -type f \( -not -perm 0660 -a -not -perm 0644 \) -printf "%p,%A+,%T+,%C+,%u,%g,%m,%M,%s\n" 2>>"${base_dir}/errors.log" >>"${base_dir}/filesbadperms_webdir.csv"

echo "[Directories in Webdir with unrecommended permissions (755, 770) except /var, app/etc, /media and /static: 777)]"
echo "[Name,Last access,Last modification,Last status chg,User/ID,Group/ID,Permissions,Size(bytes)]" >> "${base_dir}/dirsbadperms_webdir.csv"
find ${wwwdir} -type d -type d \( -not -perm 0770 -a -not -perm 0755 \) -printf "%p,%A+,%T+,%C+,%u,%g,%m,%M,%s\n" 2>>"${base_dir}/errors.log" >>"${base_dir}/dirsbadperms_webdir.csv"

#########################################################################
# Files with rare properties
#########################################################################
echo "[Search for hidden files in $investigateonlydir]"
echo "Name,Last access,Last modification,Last status chg,User/ID,Group/ID,Permissions,Size(bytes),type" >> "${base_dir}/fileshidden.csv"
find "$investigateonlydir" ! -path "${mountpoint}*" ! -path "${wwwdir}*" -type f -iname ".*" -printf "%p,%A+,%T+,%C+,%u,%g,%m,%M,%s," -exec sh -c 'file "$1" | cut -d: -f2-' sh {} \; 2>>"${base_dir}/errors.log" >> "${base_dir}/fileshidden.csv"
echo "[Search for hidden files in Webdir]" | tee -a "${base_dir}/fileshidden_webdir.csv"
echo "Name,Last access,Last modification,Last status chg,User/ID,Group/ID,Permissions,Size(bytes),type" >> "${base_dir}/fileshidden_webdir.csv"
find "$wwwdir" -type f -iname ".*" -printf "%p,%A+,%T+,%C+,%u,%g,%m,%M,%s," -exec sh -c 'file "$1" | cut -d: -f2-' sh {} \; 2>>"${base_dir}/errors.log" >> "${base_dir}/fileshidden_webdir.csv"

echo "[Suspicious files without group]"
echo "[Name,Last access,Last modification,Last status chg,User/ID,Group/ID,Permissions,Size(bytes)]" >> "${base_dir}/filesnogroup.csv"
find "$investigateonlydir" ! -path "${mountpoint}*" ! -path "${wwwdir}*" -nogroup -printf "%p,%A+,%T+,%C+,%u,%g,%m,%M,%s\n" >> "${base_dir}/filesnogroup.csv" 2>>"${base_dir}/errors.log"
echo "[Name,Last access,Last modification,Last status chg,User/ID,Group/ID,Permissions,Size(bytes)]" >> "${base_dir}/filesnogroup_webdir.csv"
find "$wwwdir" -nogroup -printf "%p,%A+,%T+,%C+,%u,%g,%m,%M,%s\n" >> "${base_dir}/filesnogroup_webdir.csv" 2>>"${base_dir}/errors.log"

echo "[Suspicious files without user]"
echo "[Name,Last access,Last modification,Last status chg,User/ID,Group/ID,Permissions,Size(bytes)]" >> "${base_dir}/filesnouser.csv"
find "$investigateonlydir" ! -path "${mountpoint}*" ! -path "${wwwdir}*" -nouser -printf "%p,%A+,%T+,%C+,%u,%g,%m,%M,%s\n" 2>>"${base_dir}/errors.log" >> "${base_dir}/filesnouser.csv"
echo "[Name,Last access,Last modification,Last status chg,User/ID,Group/ID,Permissions,Size(bytes)]" >> "${base_dir}/filesnouser_webdir.csv"
find "$wwwdir" -nouser -printf "%p,%A+,%T+,%C+,%u,%g,%m,%M,%s\n" 2>>"${base_dir}/errors.log" >> "${base_dir}/filesnouser_webdir.csv"

futuredate=$(date --date="24 hours" '+%Y-%m-%d')  ## date in the future for finding future files
echo "[Files in the future >= ($futuredate)]"
echo "[Name,Last access,Last modification,Last status chg,User/ID,Group/ID,Permissions,Size(bytes)]" >> "${base_dir}/filesfuture.csv"
if [ "$archive" == "1" ] ; then
	find "$investigateonlydir" ! -path "${mountpoint}*" ! -path "${wwwdir}*" -type f -newerat "$futuredate" -printf "%p,%A+,%T+,%C+,%u,%g,%m,%M,%s\n" -exec tar -rf "${base_dir}/filesfuture.tar" {} 2>>"${base_dir}/errors.log" \; 2>>"${base_dir}/errors.log" >> "${base_dir}/filesfuture.csv"
else
	find "$investigateonlydir" ! -path "${mountpoint}*" ! -path "${wwwdir}*" -type f -newerat "$futuredate" -printf "%p,%A+,%T+,%C+,%u,%g,%m,%M,%s\n" 2>>"${base_dir}/errors.log" >> "${base_dir}/filesfuture.csv"
fi
echo "[Name,Last access,Last modification,Last status chg,User/ID,Group/ID,Permissions,Size(bytes)]" >> "${base_dir}/filesfuture_webdir.csv"
find "$wwwdir" -type f -newerat "$futuredate" -printf "%p,%A+,%T+,%C+,%u,%g,%m,%M,%s\n" 2>>"${base_dir}/errors.log" >> "${base_dir}/filesfuture_webdir.csv"

datetoold=$(date --date="4 years ago" '+%Y-%m-%d')   ### seems that 4 years ago is a very old and strange date for the system
echo "[Files older than $datetoold]"
echo "[Name,Last access,Last modification,Last status chg,User/ID,Group/ID,Permissions,Size(bytes)]" >> "${base_dir}/filesbefore${datetoold}.csv"
if [ "$archive" == "1" ] ; then
	find "$investigateonlydir" ! -path "${mountpoint}*" -type f -not -newerat "$datetoold" -printf "%p,%A+,%T+,%C+,%u,%g,%m,%M,%s\n" -exec tar -rf "${base_dir}/filesbefore${datetoold}.tar" {} 2>>"${base_dir}/errors.log" \; 2>>"${base_dir}/errors.log" >> "${base_dir}/filesbefore${datetoold}.csv"
else
	find "$investigateonlydir" ! -path "${mountpoint}*" -type f -not -newerat "$datetoold" -printf "%p,%A+,%T+,%C+,%u,%g,%m,%M,%s\n" 2>>"${base_dir}/errors.log" >> "${base_dir}/filesbefore${datetoold}.csv"
fi
echo "[Name,Last access,Last modification,Last status chg,User/ID,Group/ID,Permissions,Size(bytes)]" >> "${base_dir}/filesbefore${datetoold}_webdir.csv"
find "$wwwdir" -type f -not -newerat "$datetoold" -printf "%p,%A+,%T+,%C+,%u,%g,%m,%M,%s\n" 2>>"${base_dir}/errors.log" >> "${base_dir}/filesbefore${datetoold}_webdir.csv"

#########################################################################
# Big files usually mean backups, data dumps, data leaks...
#########################################################################
echo "[Big files greater than 100MB]"
echo "[Name,Last access,Last modification,Last status chg,User/ID,Group/ID,Permissions,Size(bytes)]" >> "${base_dir}/filesgreater100MB.csv"
find "$investigateonlydir" ! -path "${mountpoint}*" ! -path "${wwwdir}*" -type f -size +100M -printf "%p,%A+,%T+,%C+,%u,%g,%m,%M,%s\n" 2>>"${base_dir}/errors.log" >> "${base_dir}/filesgreater100MB.csv"
echo "[Name,Last access,Last modification,Last status chg,User/ID,Group/ID,Permissions,Size(bytes)]" >> "${base_dir}/filesgreater100MB_webdir.csv"
find "$wwwdir" -type f -size +100M -printf "%p,%A+,%T+,%C+,%u,%g,%m,%M,%s\n" 2>>"${base_dir}/errors.log" >> "${base_dir}/filesgreater100MB_webdir.csv"

echo "[Big files greater than 10MB]"
echo "[Name,Last access,Last modification,Last status chg,User/ID,Group/ID,Permissions,Size(bytes)]" >> "${base_dir}/filesgreater10MB.csv"
find "$investigateonlydir" ! -path "${mountpoint}*" ! -path "${wwwdir}*" -type f -size +10M -printf "%p,%A+,%T+,%C+,%u,%g,%m,%M,%s\n" 2>>"${base_dir}/errors.log" >> "${base_dir}/filesgreater10MB.csv"
echo "[Name,Last access,Last modification,Last status chg,User/ID,Group/ID,Permissions,Size(bytes)]" >> "${base_dir}/filesgreater10MB_webdir.csv"
find "$wwwdir" -type f -size +10M -printf "%p,%A+,%T+,%C+,%u,%g,%m,%M,%s\n" 2>>"${base_dir}/errors.log" >> "${base_dir}/filesgreater10MB_webdir.csv"

#########################################################################
# Web server configuration investigation
# Nginx collection
#########################################################################
if [ -d "/etc/nginx" ] ; then
	echo "[Nginx version]"| tee -a "${base_dir}/http.txt"
	nginx -V 2>/dev/null >>"${base_dir}/http.txt"
	echo -e "\n" >> "${base_dir}/http.txt"
	echo "[Nginx Files]"| tee -a "${base_dir}/http.txt"
	echo "[Name,Last access,Last modification,Last status chg,User/ID,Group/ID,Permissions,Size(bytes)]" >> "${base_dir}/http.txt"
	find / ! -path "${mountpoint}*" -name 'nginx' -printf "%p,%A+,%T+,%C+,%u,%g,%m,%M,%s\n"  2>>"${base_dir}/errors.log" >> "${base_dir}/http.txt"
	echo -e "\n" >> "${base_dir}/http.txt"
	if [ -d "/etc/nginx/sites-enabled/" ] ; then
		for site in $(ls /etc/nginx/sites-enabled/) ; do 
			echo "[Nginx Info for site: $site]" | tee -a "${base_dir}/http.txt"
			cat "/etc/nginx/sites-enabled/$site" >> "${base_dir}/http.txt"
			echo -e "\n" >> "${base_dir}/http.txt"
		done
	fi
	if [ "$archive" == "1" ] ; then
		# archive default nginx configuration
		echo "[Archive nginx configuration]"
		tar -zfc $base_dir/HTTP_SERVER_DIR_nginx.tgz /usr/local/nginx /etc/nginx 2>>"${base_dir}/errors.log"
	fi
fi

#########################################################################
# Web server configuration investigation
# Apache2 data collection
#########################################################################
if [ -e "/etc/apache2" ] ; then
	echo "[Apache2 Version]" | tee -a "${base_dir}/http.txt"
	apache2 -v 2>/dev/null >> "${base_dir}/http.txt"
	echo -e "\n" >> "${base_dir}/http.txt"
	echo "[Apache2 Files]"
	echo "[Name,Last access,Last modification,Last status chg,User/ID,Group/ID,Permissions,Size(bytes)]" >> "${base_dir}/http.txt"
	find / ! -path "${mountpoint}*" -name 'apache2' -printf "%p,%A+,%T+,%C+,%u,%g,%m,%M,%s\n" 2>>"${base_dir}/errors.log" >> "${base_dir}/http.txt"
	echo -e "\n" >> "${base_dir}/http.txt"
	if [ -d "/etc/apache2/sites-enabled/" ] ; then
		for site in $(ls /etc/apache2/sites-enabled/) ; do 
			echo "[Apache2 Info for site: $site]" | tee -a "${base_dir}/http.txt"
			cat "/etc/apache2/sites-enabled/$site" >> "${base_dir}/http.txt"
			echo -e "\n" >> "${base_dir}/http.txt"
		done
	fi
	if [ "$archive" == "1" ] ; then
		# archive default apache2 directory
		if [ -e "/etc/apache2" ] ; then
		    echo "[Archive apache2 configuration]"
		    tar -zfc -f $base_dir/HTTP_SERVER_DIR_apache.tar.gz /etc/apache2 2>>"${base_dir}/errors.log"
		fi
	fi
fi

#########################################################################
# Web server configuration investigation
# robots.txt and .htaccess files
#########################################################################
find "$wwwdir" -name 'robots.txt' -exec sh -c 'echo  "[robots.txt found: $1]" ; ls -la $1 ; echo ; cat "$1"; echo' sh {} \; 2>>"${base_dir}/errors.log" >> "${base_dir}/robots_webdir.txt"
echo "[Find .htaccess files in Webdir]" | tee -a "${base_dir}/emails_webdir.txt"
find "$wwwdir" -name .htaccess -exec sh -c 'echo "[.htaccess file found: $1]" ; cat "$1" ; echo' sh {} \; 2>>"${base_dir}/errors.log" >> "${base_dir}/htaccess_webdir.txt"


#########################################################################
# Web server configuration investigation
# PHP related collection
#########################################################################
echo "[PHP executable Version]"| tee -a "${base_dir}/php.txt"
php -v 2>&1 >> "${base_dir}/php.txt"
echo -e "\n" >> "${base_dir}/php.txt"
echo "[PHP Info]" >>"${base_dir}/php.txt"
php -i 2>> "${base_dir}/php.txt" >> "${base_dir}/php.txt"
echo -e "\n" >> "${base_dir}/php.txt"
echo "[PHP Configuration files]" >>"${base_dir}/php.txt"
echo -e "\n" >> "${base_dir}/php.txt"
if [ "$archive" == "1" ] ; then
	find "$wwwdir" "/etc" -name php*ini -type f -exec sh -c 'echo  "[PHP configuration found: $1]" ; ls -la $1 ; echo ; cat "$1"; echo ; tar -rf "${base_dir}/HTTP_SERVER_DIR_php.tar" $1' sh {} \; 2>>"${base_dir}/errors.log" >> "${base_dir}/php.txt"
	tar -rf "${base_dir}/HTTP_SERVER_DIR_php.tar" /etc/php 2>>"${base_dir}/errors.log"
else
	find "$wwwdir" "/etc" -name php*ini -type f -exec sh -c 'echo  "[PHP configuration found: $1]" ; ls -la $1 ; echo ; cat "$1"; echo' sh {} \; 2>>"${base_dir}/errors.log" >> "${base_dir}/php.txt"
fi

#########################################################################
# MySQL database server
#########################################################################
if which mysql >> "${base_dir}/mysql.txt" 2>> "${base_dir}/mysql.txt" ; then
	echo "[MySQL database]" | tee -a "${base_dir}/mysql.txt"
	mysql --version 2>>"${base_dir}/mysql.txt"  >>"${base_dir}/mysql.txt" 
	echo -e "\n" >> "${base_dir}/mysql.txt"
	echo "[MySQL configuration files]" | tee -a "${base_dir}/mysql.txt"
	echo -e "\n" >> "${base_dir}/mysql.txt"
	find /etc/mysql/ -type f -exec sh -c 'echo  "[mysql file found: $1]" ; ls -la $1 ; echo ; cat "$1"; echo' sh {} \; 2>>"${base_dir}/errors.log" >> "${base_dir}/mysql.txt"
	if [ "$archive" == "1" ] && [-n "$mysqluser" ] && [-n "$mysqlpass" ] ; then
		mysqldump -u"$mysqluser" -p"$mysqlpass" "$mysqldb" | gzip -cf > mysql.sql.gz 2>> "${base_dir}/errors.log"
	fi 
fi

#########################################################################
# Investigate python, gcc, perl, and other development frameworks
#########################################################################
echo "[Python 2 executable Version]"| tee -a "${base_dir}/python.txt"
python2 --version 2>> "${base_dir}/python.txt" >> "${base_dir}/python.txt"
echo -e "\n" >> "${base_dir}/python.txt"
echo "[Python 2 Modules installed]" >> "${base_dir}/python.txt"
pip freeze 2>>"${base_dir}/errors.log" >> "${base_dir}/python.txt" || python -c 'help("modules")' 2>> "${base_dir}/python.txt" >> "${base_dir}/python.txt"
echo -e "\n" >> "${base_dir}/python.txt"
echo "[Python 3 Version]" >> "${base_dir}/python.txt"
python3 --version 2>> "${base_dir}/python.txt" >> "${base_dir}/python.txt"

echo "[Perl executable Version]"| tee -a "${base_dir}/perl.txt"
perl -V 2>> "${base_dir}/perl.txt" >> "${base_dir}/perl.txt"

echo "[C compilers investigation]"| tee -a "${base_dir}/compilers.txt"
dpkg --list | grep compiler 2>> "${base_dir}/compilers.txt" >> "${base_dir}/compilers.txt"

echo "[Crypto libraries investigation]"| tee -a "${base_dir}/crypto.txt"
dpkg --list | grep -i ssl 2>> "${base_dir}/cripto.txt" >> "${base_dir}/cripto.txt"
echo -e "\n" >> "${base_dir}/cripto.txt"
echo "[OpenSSL executable version]" >> "${base_dir}/cripto.txt"
openssl version 2>> "${base_dir}/cripto.txt" >> "${base_dir}/cripto.txt"

#########################################################################
# Find certificate files and private keys in server
#########################################################################
# If key and certificate files match together, modulus must be the same
echo "[Web server Certificates and keys in /etc and Webdir]"
grep -R "BEGIN CERTIFICATE" /etc "${wwwdir}" 2>>"${base_dir}/errors.log" | while read line ; do
	certfile="$(echo "$line" | cut -d: -f1)"
	echo "[Certificate Public key file: $certfile]" >> "${base_dir}/certspub.txt"
	openssl x509 -text -noout -in "$certfile" >> "${base_dir}/certspub.txt"
	echo -e "\n" >> "${base_dir}/certspub.txt"
	echo "[Certificate Modulus MD5 hash: $certfile]" >> "${base_dir}/certspub.txt"
	openssl x509 -noout -modulus -in "$certfile" | openssl md5 >> "${base_dir}/certspub.txt"
	echo -e "----------------------------------------------------------\n\n" >> "${base_dir}/certspub.txt"
done 2>>"${base_dir}/errors.log" >>"${base_dir}/certspub.txt"

grep -R "PRIVATE KEY" "/etc" "${wwwdir}" 2>>"${base_dir}/errors.log" | while read line ; do 
	certfile="$(echo "$line" | cut -d: -f1)"
	echo "[Certificate Private Key file: $certfile]" >> "${base_dir}/certskey.txt"
	openssl rsa -check -in "$certfile" >> "${base_dir}/certskey.txt"
	echo -e "\n" >> "${base_dir}/certskey.txt"
	echo "[Key Modulus MD5 hash: $certfile]" >> "${base_dir}/certskey.txt"
	openssl rsa -noout -modulus -in "$certfile" | openssl md5 >> "${base_dir}/certskey.txt"
	echo -e "----------------------------------------------------------\n\n" >> "${base_dir}/certspub.txt"
done 2>>"${base_dir}/errors.log" >>"${base_dir}/certskey.txt"

#########################################################################
# Passwords investigation
#########################################################################
# Search for passwords inside files in webdir
echo "[Execute password scanner]" | tee -a "${base_dir}/passwords_webdir.txt"
grep -REni -m1 -o ".{0,20}password.{0,20}" "$wwwdir/" >> "${base_dir}/passwords_webdir.txt" 2>>"${base_dir}/errors.log"

#########################################################################
# Installer files investigation
#########################################################################
echo "[Execute installer files scanner]" | tee -a "${base_dir}/installers_webdir.txt"
find "$wwwdir" -name '*install*.php' -exec sh -c 'echo "[installer file found: $1]" ; ls -la "$1" ; echo' sh {} \; 2>>"${base_dir}/errors.log" >> "${base_dir}/installers_webdir.txt"

#########################################################################
# Endpoints investigation
#########################################################################
# Search for terms related to hacking (hack, malware, infected, compromised, protonmail), stupid but sometimes successful
echo "[Execute hack related terms scanner]"
echo "hack|malware|infected|compromis|protonmail|tormail|silentcircle|torguard|oneshar|pastebin|dropbox|drive.google|guerrillamail]" >> "${base_dir}/hack_webdir.txt"
grep -REni -m1 -o ".{0,80}hack|malware|infected|compromis|protonmail|tormail|silentcircle|torguard|oneshar|pastebin|dropbox|drive.google|guerrillamail.{0,80}" "$wwwdir/" >> "${base_dir}/hack_webdir.txt" 2>>"${base_dir}/errors.log"

# Search for emails inside files in webdir
echo "[Execute email scanner]" | tee -a "${base_dir}/emails_webdir.txt"
grep -REno "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b" "$wwwdir/" >> "${base_dir}/emails_webdir.txt" 2>>"${base_dir}/errors.log"

# Search for URLs inside files in webdir
echo "[Execute URLs scanner]" | tee -a "${base_dir}/urls_webdir.txt"
grep -REno "(http|https)://[a-zA-Z0-9./?=_%:-]*" "$wwwdir/" >> "${base_dir}/urls_webdir.txt" 2>>"${base_dir}/errors.log"

# Search for IP addresses inside all files in webdir except in log files
echo "[Execute IPv4 scanner]" | tee -a "${base_dir}/ips_webdir.txt"
grep -REno "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)" --exclude='*.log' "$wwwdir/" >> "${base_dir}/ips_webdir.txt" 2>>"${base_dir}/errors.log"

# Search for javascript endpoints inside code
echo "[Execute Javascript endpoint scanner]" | tee -a "${base_dir}/javascript_webdir.txt"
grep -Rni "<script src=\"http" "$wwwdir/" >> "${base_dir}/javascript_webdir.txt" 2>>"${base_dir}/errors.log"

# Find javascript code inside css files
echo "[Find JavaScript and urls inside CSS files]" | tee -a "${base_dir}/javascriptcss_webdir.txt"
grep -RE "<script|<link|url\(" --include "\*.css" "$wwwdir/" 2>>"${base_dir}/errors.log" >> "${base_dir}/javascriptcss_webdir.txt"

# Other kind of javascript malware like //domain.com/src/example.com.js
echo "[Execute another Javascript endpoint scanner]" | tee -a "${base_dir}/jsendpoints_webdir.txt"
grep -REno "//[a-zA-Z0-9./?=_%:-]*.js" "$wwwdir/" >> "${base_dir}/jsendpoints_webdir.txt" 2>>"${base_dir}/errors.log"

echo "[Find non-printable characters inside files in Webdir]" | tee -a "${base_dir}/binarymalware_webdir.txt"
find "$wwwdir" \( -name '*.php' -o -name '*.js' \) -type f -printf "%p,%A+,%T+,%C+,%u,%g,%m,%M,%s," -exec file -b --mime-type {} \; | grep application 2>>"${base_dir}/errors.log" >> "${base_dir}/binarymalware_webdir.txt"

# Find base64 encoded strings inside files (to-do second grep should evaluate only expression after "filename:"xxxxxxx)
echo "[Find some base64 encoded long strings]" | tee -a "${base_dir}/base64encoded_webdir.txt"
grep -Po '(?:[A-Za-z0-9+/]{4}){4,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?' "$wwwdir/" | grep -P '(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).*' 2>>"${base_dir}/errors.log" >> "${base_dir}/base64encoded_webdir.txt"

#########################################################################
# Data archive for further investigation
#########################################################################
if [ "$archive" == "1" ] ; then
	# /var/log/
	echo "[Archive logs]"
	tar -zcf $base_dir/VAR_LOG.tgz /var/log/ 2>>"${base_dir}/errors.log"
	# /root/
	echo "[Archive root]"
	tar -zcf $base_dir/ROOT_HOME.tgz /root/ 2>>"${base_dir}/errors.log"
	# /etc/
	echo "[Archive etc]"
	tar -zcf $base_dir/ETC.tgz /etc/ 2>>"${base_dir}/errors.log"
	# /home/
	echo "[Archive home]"
	for name in $(ls /home) ; do
	    tar -zcf $base_dir/HOME_$name.tgz /home/$name 2>>"${base_dir}/errors.log"
	done
	# /var/www/
	echo "[Archive Webdir]"
	tar -zcf $base_dir/VAR_WWW.tgz "$wwwdir" 2>>"${base_dir}/errors.log"
fi

#########################################################################
# Execute security scanners
#########################################################################
# functions to search in web access log
# cat /var/log/apache2/access.log | awk -F\" ' { print $1,$2 } ' | grep "file"
# python scalp-0.4.py -l /var/log/apache2/access.log -f filter.xml -o output -html
# Other possible scanners
# Maldet: 
# apt-get install --yes --force-yes clamav
# wget http://www.rfxn.com/downloads/maldetect-current.tar.gz
# tar -xvf maldetect-current.tar.gz
# cd maldetect-*
# sudo ./install.sh
# maldet -d -u -a "$wwwdir/"
# cp /usr/local/maldet/
#########################################################################
if [ "$secscan" == "1" ] ; then
	# Should stop some processes to free some memory (apache2, ngnix, HHVM, php-fpm)
	killall apache2 2>/dev/null 
	killall nginx 2>/dev/null 
	/etc/init.d/php7.0-fpm stop >/dev/null 

	# Run Lynis if present
	if [ -x "$mountpoint/lynis/lynis" ] ; then
		echo "[Execute Lynis security scanner]"
		cd "$mountpoint/lynis/"
		chown -R 0:0 *
		./lynis audit system --log-file "${base_dir}/lynis.log" >> "${base_dir}/errors.log" 2>>"${base_dir}/errors.log"
	fi

	# Run chkrootkit if present
	# wget -c ftp://ftp.pangeia.com.br/pub/seg/pac/chkrootkit.tar.gz
	if [ -x "$mountpoint/chkrootkit/chkrootkit" ] ; then
		echo "[Execute chkrootkit malware scanner]"
		cd "$mountpoint/chkrootkit/"
		./chkrootkit >> "${base_dir}/chkrootkit.txt"
	fi

	# rkhunter malware scanner
	# wget https://downloads.sourceforge.net/project/rkhunter/rkhunter/1.4.6/rkhunter-1.4.6.tar.gz
	# apt install prelink
	if [ -f "$mountpoint/rkhunter/files/rkhunter" ] ; then
		echo "[Execute rkhunter malware scanner]"
		cd "$mountpoint/rkhunter/files/"
		./rkhunter --check --sk >> "${base_dir}/rkhunter.txt" 2>>"${base_dir}/errors.log"
	fi

	# php shell detector (Warning: does not work offline)
	# wget https://raw.github.com/emposha/Shell-Detector/master/shelldetect.py 
	if [ -f "$mountpoint/Shell-Detector/shelldetect.py" ] ; then
		echo "[Execute Shell Detector malware scanner]"
		cd "$mountpoint/Shell-Detector/"
		python2 shelldetect.py -d "$wwwdir" >> "${base_dir}/shelldetector.txt" 2>>"${base_dir}/errors.log"
	fi

	# NeoPI-master# python neopi.py -a -A /var/www/
	# git clone https://github.com/Neohapsis/NeoPI
	if [ -f "$mountpoint/NeoPI/neopi.py" ] ; then
		echo "[Execute NeoPi Shell Detector malware scanner]"
		cd "$mountpoint/NeoPI/"
		python neopi.py -a -A "$wwwdir" >> "${base_dir}/neopi_shelldetect.txt" 2>>"${base_dir}/errors.log"
	fi

	# php malware scanner
	if [ -x "$mountpoint/php-malware-scanner/scan" ] ; then
		echo "[Execute PHP malware scanner]"
		cd "$mountpoint/php-malware-scanner/"
		./scan -E -s -b -x -c -d "$wwwdir" >> "${base_dir}/php-malware-scanner.txt" 2>>"${base_dir}/errors.log"
	fi

	# php malware finder (requirements: apt install autoconf libssl-dev)
	# wget https://github.com/plusvic/yara/archive/v3.4.0.tar.gz
	# cd yara-3.4.0 ; ./bootstrap ; ./configure ; make ; make install
	if [ -f "$mountpoint/php-malware-finder/php-malware-finder/phpmalwarefinder" ] ; then
		echo "[Execute PHP malware finder]"
		cd "$mountpoint/php-malware-finder/yara-3.4.0/"
		[ "$online" == "1" ] && apt-get install --yes --force-yes autoconf libssl-dev
		make install
		cd "$mountpoint/php-malware-finder/php-malware-finder/"
		./phpmalwarefinder "$wwwdir" >> "${base_dir}/php-malware-finder.txt" 2>>"${base_dir}/errors.log"
	fi

	# Additional and too simple function scanner to check manually for possible shells
	echo "[Execute grep malware scanner]" | tee -a "${base_dir}/manual_shelldetect.txt"
	grep -RPno "(passthru|shell_exec|cmd|sh -c|system|phpinfo|base64_decode|edoced_46esab|chmod|mkdir|gzinflate|fopen|fclose|readfile|php_uname|eval|atob|fromCharCode) *\(" "$wwwdir/" >> "${base_dir}/manual_shelldetect.txt" 2>>"${base_dir}/errors.log"

	if [ "$magentosite" == "1" ] ; then
		# Magento malware known files finder
		echo "[Execute Magento known files malware scanner]"
		echo "[Name,Last access,Last modification,Last status chg,User/ID,Group/ID,Permissions,Size(bytes)]" >> "${base_dir}/magentomalware_webdir.csv"
		find "$wwwdir" -name \( -name "jquery.php" -o -name "jquery.pl" -o -name "css.php" -o -name "opp.php" -o -name "xrc.php" -o -name "order.php" -o -name "jquerys.php" -o -name "mage_ajax.php" -o -name "Maged.php" \) -printf "%p,%A+,%T+,%C+,%u,%g,%m,%M,%s," -exec sh -c 'file "$1" | cut -d: -f2-' sh {} \; 2>>"${base_dir}/errors.log" >> "${base_dir}/magentomalware_webdir.csv"
		grep -Reno "googleLabel|updMsg|propVersion|cachefooter|sortproc|subCatalog|sumMenu|onClipboard|optViewport|targetscope|appendtooltip|setupScreen|strictheight|hashProcedure|onepage|checkout|onestep|firecheckout" "$wwwdir/" >> "${base_dir}/magentoskimmer_webdir.txt" 2>>"${base_dir}/errors.log"

		# PANHunter Credit Card scanner
		if [ -f "$mountpoint/PANHunter/exec_pan_hunter.py" ] ; then
			echo "[Execute PANHunter CC scanner. Sorry it takes a lot of time to scan the system...]"
			cd "$mountpoint/PANHunter/"
			python ./exec_pan_hunter.py "${base_dir}/PANHunter_webdir.log" "$wwwdir/"
		fi

		# Another PANhunter version in python
		# apt install python-colorama python-progressbarcd 
		if [ -f "$mountpoint/PANhunt/panhunt.py" ] ; then
			echo "[Execute another PANhunter CC scanner]"
			cd "$mountpoint/PANhunt/"
			python panhunt.py -s "$investigateonlydir" -t  .doc,.xls,.xml,.txt,.csv,.log,.php -z .docx,.xlsx,.zip,.tgz -o "${base_dir}/PANhunt.log" 2>>"${base_dir}/errors.log" 
		fi
	fi
fi

#########################################################################
# End of recopilation reached
#########################################################################
echo "[End of recopilation]"

#########################################################################
# Creating forensic package for later analisys
#########################################################################
# to decript later read decryptpackage.txt file 
echo "[Packaging recopilated data]"
if tar czf - "$base_dir" 2>>"${base_dir}/errors.log" | openssl aes-256-cbc -salt -md sha512 -pbkdf2 -iter 100000 -e -pass pass:"$packagepassword" -out "$mountpoint/$devicename_$filedate.tgz.enc" 2>>"${base_dir}/errors.log" ; then
	sha1sum "$mountpoint/$devicename_$filedate.tgz.enc" > "$mountpoint/$devicename_$filedate.tgz.enc.sha1"
	echo "[Data successfully packed]"
	echo "[Relevant files are: sha1sum -c $devicename_$filedate.tgz.enc, sha1sum -c $devicename_$filedate.tgz.enc.sha1, decryptpackage.txt]"
	echo "# Readme file for forensic data extraction" > "$mountpoint/decryptpackage.txt"
	echo "#####################################" >> "$mountpoint/decryptpackage.txt"
	echo "" >> "$mountpoint/decryptpackage.txt"
	cat "${base_dir}/index.txt"  >> "$mountpoint/decryptpackage.txt"
	echo "# Relevant files included:" >> "$mountpoint/decryptpackage.txt"
	echo "#####################################" >> "$mountpoint/decryptpackage.txt"
	echo "# $devicename_$filedate.tgz.enc # Forensic data extracted, compressed and encrypted" >> "$mountpoint/decryptpackage.txt"
	echo "# $devicename_$filedate.tgz.enc.sha1 # Forensic package SHA1 signature to check integrity" >> "$mountpoint/decryptpackage.txt"
	echo "# decryptpackage.txt # This index file" >> "$mountpoint/decryptpackage.txt"
	echo "#####################################" >> "$mountpoint/decryptpackage.txt"
	echo "" >> "$mountpoint/decryptpackage.txt"
	echo "# To decrypt forensic data run in LAB:" >> "$mountpoint/decryptpackage.txt"
	echo "######################################" >> "$mountpoint/decryptpackage.txt"
	echo "sha1sum -c $devicename_$filedate.tgz.enc.sha1" >> "$mountpoint/decryptpackage.txt"
	echo "openssl aes-256-cbc -salt -pbkdf2 -md sha512 -iter 100000 -d -in ./$devicename_$filedate.tgz.enc -out $devicename_$filedate.tgz" >> "$mountpoint/decryptpackage.txt"
	echo "tar -xzf  $devicename_$filedate.tgz" >> "$mountpoint/decryptpackage.txt"
	echo "######################################" >> "$mountpoint/decryptpackage.txt"
	echo -ne "Encrypted with " >> "$mountpoint/decryptpackage.txt"
	openssl version 2>> "${base_dir}/decryptpackage.txt" >> "${base_dir}/decryptpackage.txt"
else
	echo "[Error packing data! Please do it manually]"
fi

#########################################################################
# Power off if required
#########################################################################
if [ "$poweroffwhenfinish"  == "1" ] ; then
	echo -ne "[Going to power off after 60 seconds, press CTRL+C to avoid."
	for i in {1..60}; do echo -ne "." ; sleep 1; done
	echo -ne "]"
	poweroff	
fi


