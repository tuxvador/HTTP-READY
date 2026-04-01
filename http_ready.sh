#!/bin/bash
#Function to detect all port responding to http request during a pentest
#-------------------------
#String def
#-------------------------
s_namp="Nmap command : "
s_host_def="Enter file or host definition in nmap format example ---- hosts.txt ---- 192.168.1.0/24 ---- 192.168.1.0"
v_debug=0
v_workdir=$(mktemp -d)
v_host_list=${v_workdir}"/hosts.nmap"
v_port_list=${v_workdir}"/ports.nmap"
v_host_ports=$v_workdir"/host_ports.ready"
v_wait=5
v_thread=500
v_nmap_stats="60s"
v_min_paral=200
v_max_paral=400
#-----------------------------
#Generate Nmap file
#-----------------------------
mkdir -p $v_workdir
echo $s_host_def
read -p "Hosts(s) : " v_host_def

if test -f $v_host_def
then
	if [[ $v_debug == 1 ]]
	then
	    nmap -n -T5 --min-parallelism=$v_min_paral --max-parallelism=$v_max_paral -sn -stats-every $v_nmap_stats -iL $v_host_def | grep "scan report for" | grep -Eo "([0-9]{1,3}[\.]){3}[0-9]{1,3}" | tee $v_host_list >/dev/null 2>&1
	else
	    nmap -n --min-parallelism=$v_min_paral --max-parallelism=$v_max_paral -sn -iL $v_host_def | grep "scan report for" | grep -Eo "([0-9]{1,3}[\.]){3}[0-9]{1,3}" | tee $v_host_list >/dev/null 2>&1
	fi
else
	if [[ $v_debug == 1 ]]
	then
	    sudo nmap -n --min-parallelism=$v_min_paral --max-parallelism=$v_max_paral -sn -stats-every $v_nmap_stats $v_host_def | grep "scan report for" | grep -Eo "([0-9]{1,3}[\.]){3}[0-9]{1,3}" | tee $v_host_list >/dev/null 2>&1
	else
	    sudo nmap -n --min-parallelism=$v_min_paral --max-parallelism=$v_max_paral -sn $v_host_def | grep "scan report for" | grep -Eo "([0-9]{1,3}[\.]){3}[0-9]{1,3}" | tee $v_host_list >/dev/null 2>&1
	fi

fi

if [[ $v_debug == 1 ]]
then
    sudo nmap -sS --min-parallelism=$v_min_paral --max-parallelism=$v_max_paral -stats-every $v_nmap_stats -iL $v_host_list -oG $v_port_list >/dev/null 2>&1
else
    sudo nmap -sT --min-parallelism=$v_min_paral --max-parallelism=$v_max_paral -stats-every $v_nmap_stats -iL $v_host_list -oG $v_port_list >/dev/null 2>&1
fi

#-----------------------------
#Generate function file
#-----------------------------
cat $v_port_list | grep -v "Up" | while read line
do
	host=$(echo $line | grep -Eo '([0-9]{1,3}[\.]){3}[0-9]{1,3}')
	if [[ $? == 0 ]]
	then
		echo "------ host :$host ------" | tee -a $v_host_ports >/dev/null 2>&1
		ports=$(echo $line | grep -Po '(?<= )([0-9]{1,})(?=/)')
		if [[ $? == 0 ]]
		then
			for y in $ports
			do
				echo $host" --- Ports: "$y | tee -a $v_host_ports >/dev/null 2>&1
			done
		fi
	fi
done
#-----------------------------
#Compute result
#-----------------------------
rm http_ready.txt
cat $v_host_ports | grep -v "host" | xargs -P $v_thread -I{} bash -c 'host=$(grep -Eo "^([0-9]{1,3}[\.]){3}[0-9]{1,3}" <<< "{}") ; port=$(grep -Po "(?<=Ports: )([0-9]{1,})" <<< "{}") ; curl -s -m '$v_wait' -o /dev/null -w "Host : $host Port :$port +++ http://$host:$port --- http_code : %{response_code}\n" http://$host:$port ; curl -s -m '$v_wait' -o /dev/null -k -w "Host : $host Port :$port  +++ https://$host:$port --- https_code : %{response_code}\n" https://$host:$port' | tee -a http_ready.ready | grep -v '000'
#-----------------------------
#Output
#-----------------------------
if [[ $v_debug == 1 ]]
then
echo "---output---"
echo $v_workdir
#cat $v_host_list
#cat $v_port_list
#cat v_host_ports
cat $v_host_ports
echo "---end output---"
fi
#-----------------------------
