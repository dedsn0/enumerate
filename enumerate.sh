#!/bin/bash

##
## The biggy first enum script.
## @author ded_sn0
##


## Services, ports and functions
tcp_services=("SSH Known Credentials" "SSH Brute Force" "SMB/Samba" "Nmap TCP Top 200")
tcp_port=("22" "22" "139 445" "*")
tcp_enumeration=("ssh-known" "ssh-brute" "samba" "nmap-tcp-200")

udp_services=("SNMP")
udp_port=("161")
udp_enumeration=("snmp")

default_modules="ssh-known samba nmap-tcp-200 snmp"

found_users=/root/lists/users.txt
found_passwords=/root/lists/pass-reuse.txt
brute_passwords=/usr/share/wordlists/rockyou.txt

info_snmp=/root/lists/interest-snmp.txt
info_samba=/root/lists/interest-samba.txt

#snmp_community=/root/lists/snmp-community.txt


red="$(tput setaf 1)"
green="$(tput setaf 2)"
blue="$(tput setaf 4)"
der="$(tput sgr0)"

echo "==- ${green}Enumeration${red} by ${blue}ded_sn0${der} -=="

#########################################################################
#
#
#
#  Enumeration functions go here - zero params 
#	useful variables: target
#
#
#########################################################################


function snmp {
	echo "[*] Running snmpwalk against v1 SNMP"

	if ! dosnmpwalk 1 ; then
		echo "[*] v1 SNMP failed, so trying v2"
		if ! dosnmpwalk 2c ; then 
			echo "[*] v2 also failed (may be v3)"
		fi
	fi 

}


# $1 is the data & $2 is the info file
function checkinfo {
	while read info; do
		delim="$(echo "$info" | cut -c2)"
		search="$(echo "$info" |cut -d"$delim" -f2)"
		fields="$(echo "$info" |cut -d"$delim" -f3)"
		text="$(echo "$info" |cut -d"$delim" -f4-)"
		echo "search is $search"
		line="$(echo "$1" | grep "$search")"
		
		if [ -n "$line" ]; then
			echo "[*]  ${blue}${text}: $(echo "$line" | cut -d" " -f$fields)$der"
		fi
 	done < $2

}

function dosnmpwalk {
	report="$(snmpwalk -v $1 -c public $target)"
	if [ "$report" ==  "snmpwalk: Timeout" ]; then
		return 1
	else
		echo "[*]  ${green}Check snmpwalk-$1.txt${der}"
		echo "$report" > snmpwalk-$1.txt
		checkinfo "$report" "$info_snmp"
		return 0
	fi
}

function nmap-tcp-200 {
	nmap --top-ports 200 -sV --open $target > nmap-tcp-200.txt
	echo "[*]  ${green}Check nmap-tcp-200.txt for port scan${der}"
}

function ssh-known {
	hydra_attack ssh $found_users $found_passwords
}

function ssh-brute {
	hydra_attack ssh $found_users $brute_passwords
}

# generic hydra attack for credentials
# $1 = protocol, $2 = users, $3 = passwords
function hydra_attack {
	echo "[*] Running hydra attack against $1 on $target with"
	echo "[*]        users:$2 & passwords:$3"
	report="$(hydra -L $2 -P $3 $1://$target 2>&1)"
	if [ -n "$(echo "$report" |grep "not support password auth")" ]; then
		echo "[*]  ${red}$1 does not support passwords - keys only${der}"
	else 
		n="$(echo "$report" |grep "valid passwords found" |cut -d" " -f6)"
		if [ -z "$n" ]; then echo "[*] Error running hydra"
		elif [ "$n" -eq "0" ]; then echo "{*} No valid $1 creds found"
		else
		echo "[*}  ${red}Found $n valid credentials for $1${der}"
		fi
	fi
	echo "$report" >> hydra-$1.txt

	
}

function samba {

	echo "[*] Running enum4linux"
	e4l="$(enum4linux $target 2>&1)"
	echo "$e4l" > smb-enum4linux.txt
	echo "[*]  ${green}Check enum4linux.txt${der}"
	checkinfo "$e4l" "$info_samba"
	## OS info 
	os="$(echo "$e4l" |grep "Got OS info for $target from smbclient" |cut -d" " -f9-)"
	if [ -n "$os" ]; then echo "[*]  ${red}$os${der}"; fi
	echo "[*] Running nmap smb-vuln* scripts"
	scan="$(nmap -p139,445 --script smb-vuln* $target)"
	vuln="$(echo "$scan" | grep "CVE:" |cut -c17-)"
	echo "$scan" > nmap-smb-vuln.txt
	echo "[*]  ${green}Check nmap-smb-vuln.txt${der}"
	if [ -z "$vuln" ]; then 
		echo "[*]  Nothing interesting noted (still check output)"
	else
		echo "[*]  ${blue}Possible vulnerabilities: $vuln${der}"
	fi
	echo "[*] Running nmap smb-os-discovery script"
	v="$(nmap -p139,445 --script smb-os-discovery $target)"
	echo "$v" > nmap-smb-os-discovery.txt
	echo "[*]  ${green}Check nmap-smb-os-discovery.txt${der}"
	os="$(echo "$v" |grep "OS:" |cut -d" " -f2-)"
	if [ -z "$os" ]; then
		echo "[*] -Nothing interesting noted (but still check)"
	else
		echo "[*]${red}$os${der}"
	fi
}


##
## Check target
##
function check_target() {
        if [ -z "$1" ]; then
                echo "Missing target"
                echo "Use $0 -h for help"
                exit 1
        fi

        target=$1
        echo "[*] Target is $target"
}

function indexof {
	declare -a my_array=("${!1}")
	value=$2
	for i in "${!my_array[@]}"; do
		if [[ "${my_array[$i]}" = "${value}" ]]; then
			echo "$i"
			return 0;
		fi
	done
	return 0;
}

function single_module {
	#find index for module
	index="$(indexof tcp_enumeration[@] $1)"
	if [ -z "$index" ]; then
		single_module_udp $1
		exit 10
	fi

        ports="${tcp_port[$index]}"
        service="${tcp_services[$index]}"


	enumerate_service "$service" "$ports" sS $1 
}


function single_module_udp {
        #find index for module
        index="$(indexof udp_enumeration[@] $1)"
        if [ -z "$index" ]; then
                echo "[*] ${red}Unknown module: $1${der}"
                exit 1
        fi

        ports="${udp_port[$index]}"
        service="${udp_services[$index]}"


        enumerate_service "$service" "$ports" sU $1 
}



#
# Function to check a port is open in a scan
# $1 is the port and $2 is the scan type
function port_open {

	#allow empty ports to auto pass
	if [ "$1" == "*" ]; then return 0; fi

	o="$(nmap -p$1 -$2 $target | grep open)"

	if [ -n "$o" ]; then
		return 0
	else
		return 1
	fi
}


function finish {
	echo "[*] Complete. "
	echo "==- ${red}Hack to burn${der} -=="
}

# Function to test if any of the supplied ports are open.
# $1 is a set of ports, $2 is the scan type 
function any_open_ports {
        for port in $1; do
                if (port_open "$port" "$2"); then return 0; fi
        done
        return 1
}

##
## Run a single module
## $1 module. $2 ports, $3 scan type, $4 function
function enumerate_service {
       echo "[*] Checking $1 on port(s) $2" 
        if (any_open_ports "$2" "$3"); then
                echo "[*] ${green}Enumerating $1${der}"
                $4
        else
                echo "[*] $1 not available, skipping"
        fi

}



##
## Deal with options
##
while getopts ":hlm:" opt; do
        case $opt in
                h)
                        echo "This script enumerates a fresh target ip."
                        echo " Usage: $(basename $0) <target-ip>"
                        echo ""
                        echo " Options:"
                        echo "     -h          Help (this message)"
                        echo "     -l          List all the enumeration modules"
                        echo "     -m <module> Run a specific  enumeration module"
                        exit 0
                        ;;
                l)
                        echo "Modules available for enumeration are:${green}"
                        for m in "${tcp_enumeration[@]}"; do
                                echo "$m"
                        done
                        echo ""
                        echo "${der}By default all modules are run"
                        exit 0
                ;;
                m)
                        module=$OPTARG
			shift 2
                ;;
                \?)
                        echo "Fubarred option: -$OPTARG"
                        echo "Use $0 -h for help"
                        exit 1
                        ;;
        esac
done


check_target $1


if [ -z "$module" ]; then
	##
	## run all modules
	##
	echo "[*] Running all default modules"
	echo "[*} Running TCP modules"
	index=0
	for service in ${tcp_enumeration[@]}; do
		if [[ $default_modules == *$service* ]]; then 
			ports="${tcp_port[$index]}"
			service="${tcp_services[$index]}"
			funct="${tcp_enumeration[$index]}"

			enumerate_service "$service" "$ports" sS "$funct"
		fi
		index=$(($index + 1))
	done

        echo "[*} Running UDP modules"
        index=0
        for service in ${udp_enumeration[@]}; do
                if [[ $default_modules == *$service* ]]; then 
                        ports="${udp_port[$index]}"
                        service="${udp_services[$index]}"
                        funct="${udp_enumeration[$index]}"

                        enumerate_service "$service" "$ports" sU "$funct"
                fi
                index=$(($index + 1))
        done

else
	echo "[*] Running $module module"
	single_module $module
fi

finish
