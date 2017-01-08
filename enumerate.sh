#!/bin/bash

##
## The biggy first enum script.
## @author ded_sn0
##


## Services, ports and functions
tcp_services=("SSH Credentials" "SMB/Samba")
tcp_port=("22" "139 445")
tcp_enumeration=("ssh-creds" "samba")

found_users=/root/lists/users.txt
found_passwords=/root/lists/pass-reuse.txt

red="$(tput setaf 1)"
green="$(tput setaf 2)"
der="$(tput sgr0)"

echo "==- ${green}Enumeration by ${red}ded_sn0${der} -=="

#########################################################################
#
#
#
#  Enumeration functions go here - zero params 
#	useful variables: target
#
#
#########################################################################

function ssh-creds {
	hydra_attack ssh $found_users $found_passwords
}

# generic hydra attack for credentials
# $1 = protocol, $2 = users, $3 = passwords
function hydra_attack {
	echo "[*] Running hydra attack against $1 on $target with users:$2
	hydra -L $2 -P $3 $1://$target
}

function samba {

	echo "[*] -Running enum4linux"
	e4l="$(enum4linux $target)"
	echo "$e4l" > smb-enum4linux.txt
	echo "[*] -Complete. ${green}Check enum4linux.txt${der}"
	## OS info 
	os="$(echo "$e4l" |grep "Got OS info for $target from smbclient" |cut -d" " -f9-)"
	if [ -n "$os" ]; then echo "[*]  ${red}$os${der}"; fi
	echo "[*] -Running nmap smb-vuln* scripts"
	scan="$(nmap -p139,445 --script smb-vuln* $target)"
	vuln="$(echo "$scan" | grep "CVE:" |cut -c17-)"
	echo "$scan" > nmap-smb-vuln.txt
	echo "[*] -Complete. ${green}Check nmap-smb-vuln.txt${der}"
	if [ -z "$vuln" ]; then 
		echo "[*] -Nothing interesting noted (still check)"
	else
		echo "[*]  ${red}$vuln${der}"
	fi
	echo "[*] -Running nmap smb-os-discovery script"
	v="$(nmap -p139,445 --script smb-os-discovery $target)"
	echo "$v" > nmap-smb-os-discovery.txt
	echo "[*] -Complete. ${green}Check nmap-smb-os-discovery.txt${der}"
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
		echo "[*] ${red}Unknown module: $1${der}"
		exit 1
	fi

        ports="${tcp_port[$index]}"
        service="${tcp_services[$index]}"


	enumerate_service "$service" "$ports" sS $1 
}


#
# Function to check a port is open in a scan
# $1 is the port and $2 is the scan type
function port_open {

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
	echo "[*] Running all modules"
	index=0
	for service in ${tcp_enumeration[@]}; do
		ports="${tcp_port[$index]}"
		service="${tcp_services[$index]}"
		funct="${tcp_enumeration[$index]}"

		enumerate_service "$service" "$ports" sS "$funct"

		index=$(($index + 1))
	done
else
	echo "[*] Running $module module"
	single_module $module
fi

finish
