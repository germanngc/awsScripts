from dotenv import load_dotenv
import boto3
import ipaddress
import os
import sys

sec_group_id = ''
sec_group_name = ''
port=22
my_name = 'AddMyIp2SecGroup'
my_ip = '127.0.0.1'
ec2 = ''

def configure_aws():
    global ec2
    load_dotenv()
    aws_access_key_id = os.getenv('AWS_ACCESS_KEY_ID')
    aws_secret_access_key = os.getenv('AWS_SECRET_ACCESS_KEY')
    aws_region = os.getenv('AWS_REGION')
    try:
        boto3.setup_default_session(aws_access_key_id=aws_access_key_id,
                                    aws_secret_access_key=aws_secret_access_key,
                                    region_name=aws_region)
        ec2 = boto3.client('ec2')
    except Exception as e:
        print(f'\033[31mErr! {e}\033[0m')
        quit()

def list_security_groups():
    try:
        response = ec2.describe_security_groups()
        return sorted(response['SecurityGroups'], key=lambda k: k['GroupName'])
    except Exception as e:
        print(f'\033[31mErr! {e}\033[0m')
        quit()

def add_my_ip_to_security_group(security_groups):
    global sec_group_id, sec_group_name, my_name, my_ip, port
    for i, sg in enumerate(security_groups, 1):
        print(f"\t\033[32m[{i}] {sg['GroupName']}\033[0m")
    try:
        print('')
        choice = int(input('Enter the number of the SG you want to modify: '))
        assert 1 <= choice <= len(security_groups)
        sec_group_id = security_groups[choice - 1]['GroupId']
        sec_group_name = security_groups[choice - 1]['GroupName']
        print('')
        choice = input('Enter the port (default 22): ') or 22
        if (int(choice)):
            choice = int(choice)
            assert 1 <= choice <= 65535
        else:
            throw = ValueError('Invalid port = {port}')
        port = choice
        my_name = str(input('Enter the description for this change: '))
        assert 1 <= len(my_name) <= 64
    except (ValueError, AssertionError):
        print(f'\033[31mErr! Invalid choice.\033[0m')
        return

    try:
        my_ip = str(input('Enter the ip for add: '))
        ipaddress.ip_address(my_ip)
        ec2.authorize_security_group_ingress(GroupId=sec_group_id,
                                            IpPermissions=[
                                                {'IpProtocol': 'tcp',
                                                'FromPort': port,
                                                'ToPort': port,
                                                'IpRanges': [{'CidrIp': my_ip+'/32', 'Description': 'TEMP:'+my_name}]}
                                            ])
    except (ValueError, Exception, AssertionError) as e:
        print(f'\n\033[31mErr! {e}\033[0m')
        return
    print(f'\n\033[32mSuccess! Your IP {my_ip} was added to the security group {sec_group_name} for port {port}!\033[0m')

def main():
    security_groups = list_security_groups()
    if not security_groups:
        print(f'\033[31mErr! No security groups found.\033[0m')
        return
    add_my_ip_to_security_group(security_groups)

if __name__ == '__main__':
    print('\n##############################################')
    print('# Adding my IP to a security group           #')
    print('##############################################\n')
    configure_aws()
    main()