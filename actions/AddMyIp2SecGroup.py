from dotenv import load_dotenv
import boto3
import ipaddress
import os
import sys
from datetime import datetime


def configure_aws():
    """Configure AWS session from environment variables."""
    load_dotenv()
    aws_access_key_id = os.getenv('AWS_ACCESS_KEY_ID')
    aws_secret_access_key = os.getenv('AWS_SECRET_ACCESS_KEY')
    aws_region = os.getenv('AWS_REGION')
    
    if not all([aws_access_key_id, aws_secret_access_key, aws_region]):
        print('\033[31mErr! Missing AWS credentials in .env file\033[0m')
        sys.exit(1)
    
    try:
        boto3.setup_default_session(
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key,
            region_name=aws_region
        )
        return boto3.client('ec2')
    except Exception as e:
        print(f'\033[31mErr! Failed to configure AWS: {e}\033[0m')
        sys.exit(1)


def list_security_groups(ec2):
    """List all available security groups."""
    try:
        response = ec2.describe_security_groups()
        return sorted(response['SecurityGroups'], key=lambda k: k['GroupName'])
    except Exception as e:
        print(f'\033[31mErr! Failed to list security groups: {e}\033[0m')
        sys.exit(1)


def check_rule_exists(ec2, group_id, ip_address, port):
    """Check if a rule already exists for the given IP and port."""
    try:
        response = ec2.describe_security_groups(GroupIds=[group_id])
        if not response['SecurityGroups']:
            return False
        
        sg = response['SecurityGroups'][0]
        cidr = f'{ip_address}/32'
        
        for permission in sg.get('IpPermissions', []):
            if (permission.get('FromPort') == port and 
                permission.get('ToPort') == port and
                permission.get('IpProtocol') == 'tcp'):
                for ip_range in permission.get('IpRanges', []):
                    if ip_range.get('CidrIp') == cidr:
                        return True
        return False
    except Exception as e:
        print(f'\033[33mWarning! Could not check for existing rule: {e}\033[0m')
        return False


def validate_port(port_input):
    """Validate and return port number."""
    try:
        port = int(port_input)
        if not 1 <= port <= 65535:
            raise ValueError(f'Port must be between 1 and 65535, got {port}')
        return port
    except ValueError as e:
        raise ValueError(f'Invalid port: {e}')


def validate_ip(ip_input):
    """Validate and return IP address."""
    try:
        ipaddress.ip_address(ip_input)
        return ip_input
    except ValueError:
        raise ValueError(f'Invalid IP address: {ip_input}')


def validate_description(description):
    """Validate description length."""
    if not 1 <= len(description) <= 64:
        raise ValueError('Description must be between 1 and 64 characters')
    return description


def add_ip_to_security_group(ec2, security_groups):
    """Add an IP address to a selected security group."""
    # Display security groups
    print('== Available Security Groups:\n')
    for i, sg in enumerate(security_groups, 1):
        print(f"\t\033[32m[{i}] {sg['GroupName']}\033[0m (ID: {sg['GroupId']})")
    
    try:
        # Select security group
        print('')
        choice = int(input('Enter the number of the SG you want to modify: '))
        if not 1 <= choice <= len(security_groups):
            print('\033[31mErr! Invalid choice.\033[0m')
            return
        
        selected_sg = security_groups[choice - 1]
        sec_group_id = selected_sg['GroupId']
        sec_group_name = selected_sg['GroupName']
        
        # Get and validate IP address
        print('')
        ip_input = input('Enter the IP address to add: ').strip()
        ip_address = validate_ip(ip_input)
        
        # Get and validate port
        port_input = input('Enter the port (default 22): ').strip() or '22'
        port = validate_port(port_input)
        
        # Check if rule already exists
        if check_rule_exists(ec2, sec_group_id, ip_address, port):
            print(f'\n\033[33mWarning! A rule for {ip_address}/32 on port {port} already exists in {sec_group_name}\033[0m')
            confirm = input('Do you want to continue anyway? (y/N): ').strip().lower()
            if confirm != 'y':
                print('Operation cancelled.')
                return
        
        # Get description
        description = input('Enter the description for this change: ').strip()
        validate_description(description)
        
        # Generate date string
        date_str = datetime.now().strftime('%Y%m%d')
        full_description = f'TEMP:{date_str}:{description}'
        
        # Confirmation
        print(f'\n\033[33m== Confirm:\033[0m')
        print(f'   Security Group: {sec_group_name} ({sec_group_id})')
        print(f'   IP Address: {ip_address}/32')
        print(f'   Port: {port}')
        print(f'   Description: {full_description}')
        confirm = input('\nProceed with adding this rule? (y/N): ').strip().lower()
        
        if confirm != 'y':
            print('Operation cancelled.')
            return
        
        # Add the rule
        ec2.authorize_security_group_ingress(
            GroupId=sec_group_id,
            IpPermissions=[{
                'IpProtocol': 'tcp',
                'FromPort': port,
                'ToPort': port,
                'IpRanges': [{
                    'CidrIp': f'{ip_address}/32',
                    'Description': full_description
                }]
            }]
        )
        
        print(f'\n\033[32mSuccess! IP {ip_address} was added to security group {sec_group_name} for port {port}!\033[0m')
        
    except ValueError as e:
        print(f'\n\033[31mErr! {e}\033[0m')
        return
    except KeyboardInterrupt:
        print('\n\nOperation cancelled by user.')
        return
    except Exception as e:
        print(f'\n\033[31mErr! Failed to add rule: {e}\033[0m')
        return


def main():
    """Main function."""
    ec2 = configure_aws()
    security_groups = list_security_groups(ec2)
    
    if not security_groups:
        print('\033[31mErr! No security groups found.\033[0m')
        return
    
    add_ip_to_security_group(ec2, security_groups)


if __name__ == '__main__':
    print('\n##############################################')
    print('# Adding my IP to a security group           #')
    print('##############################################\n')
    main()