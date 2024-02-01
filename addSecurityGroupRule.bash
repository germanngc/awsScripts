#!/bin/bash

# Add Security Group Rule

#
# Die Function
#
die () {
  printf >&2 "Error!\n\t./$0 AWS_PROFILE SECURITY_GROUP_NAME PROTOCOL PORT IP_ADDRESS\nExit with failure...\n"
  exit 1
}

#
# Logger Function
#
logger () {
  printf >&2 $(date +"%Y%m%dT%H%M%S")"\t$@\n"
}

logger "Initializing..."

#
# Validate arguments
#
[ "$#" -ge 4 ] || die "4 arguments are required, $# provided."

#
# Arguments
#
aws_profile=$1
security_group_name=$2
protocol=$3
port=$4
ip_address=$5
block_cidr=32

if [ "$ip_address" = "" ]; then
  ip_address=`curl -s http://whatismyip.akamai.com`;
elif [ "$ip_address" = "0.0.0.0" ]; then
  block_cidr=0
fi

logger "AWS Profile = $aws_profile"
logger "Security Group Name = $security_group_name"
logger "Protocol = $protocol"
logger "Port = $port"
logger "IP Address = $ip_address"
logger "CIDR Block = $block_cidr"

#
# Add Security Group Rule
#

aws ec2 authorize-security-group-ingress \
  --group-name "${security_group_name}" \
  --protocol ${protocol} --port ${port} \
  --cidr ${ip_address}/${block_cidr} \
  --profile ${aws_profile} \
  --output text

aws --profile $aws_profile ec2 describe-security-groups

exit 0
