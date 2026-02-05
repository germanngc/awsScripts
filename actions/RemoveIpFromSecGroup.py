from dotenv import load_dotenv
import boto3
import os
import sys


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


def list_rules_for_group(ec2, group_id):
    """List all ingress rules for a security group."""
    try:
        response = ec2.describe_security_groups(GroupIds=[group_id])
        if not response['SecurityGroups']:
            return []
        
        sg = response['SecurityGroups'][0]
        rules = []
        
        for idx, permission in enumerate(sg.get('IpPermissions', []), 1):
            protocol = permission.get('IpProtocol', 'unknown')
            from_port = permission.get('FromPort', 'N/A')
            to_port = permission.get('ToPort', 'N/A')
            
            for ip_range in permission.get('IpRanges', []):
                cidr = ip_range.get('CidrIp', 'N/A')
                description = ip_range.get('Description', 'No description')
                rules.append({
                    'index': len(rules),
                    'protocol': protocol,
                    'from_port': from_port,
                    'to_port': to_port,
                    'cidr': cidr,
                    'description': description,
                    'permission': permission,
                    'ip_range': ip_range
                })
        
        return rules
    except Exception as e:
        print(f'\033[31mErr! Failed to list rules: {e}\033[0m')
        sys.exit(1)


def remove_rule_from_security_group(ec2, security_groups):
    """Remove an IP rule from a selected security group."""
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
        
        # List rules
        print(f'\n== Rules in {sec_group_name}:\n')
        rules = list_rules_for_group(ec2, sec_group_id)
        
        if not rules:
            print('\033[33mNo ingress rules found in this security group.\033[0m')
            return
        
        for i, rule in enumerate(rules, 1):
            port_str = f"{rule['from_port']}" if rule['from_port'] == rule['to_port'] else f"{rule['from_port']}-{rule['to_port']}"
            print(f"\t\033[32m[{i}]\033[0m {rule['protocol']} | Port: {port_str} | IP: {rule['cidr']} | Desc: {rule['description']}")
        
        # Select rule to remove
        print('')
        rule_choice = int(input('Enter the number of the rule to remove: '))
        if not 1 <= rule_choice <= len(rules):
            print('\033[31mErr! Invalid choice.\033[0m')
            return
        
        rule_to_remove = rules[rule_choice - 1]
        
        # Confirmation
        print(f'\n\033[33m== Confirm Removal:\033[0m')
        print(f'   Security Group: {sec_group_name} ({sec_group_id})')
        print(f'   Protocol: {rule_to_remove["protocol"]}')
        print(f'   Port: {rule_to_remove["from_port"]}' + (f'-{rule_to_remove["to_port"]}' if rule_to_remove["from_port"] != rule_to_remove["to_port"] else ''))
        print(f'   IP CIDR: {rule_to_remove["cidr"]}')
        print(f'   Description: {rule_to_remove["description"]}')
        confirm = input('\nProceed with removing this rule? (y/N): ').strip().lower()
        
        if confirm != 'y':
            print('Operation cancelled.')
            return
        
        # Remove the rule
        ec2.revoke_security_group_ingress(
            GroupId=sec_group_id,
            IpPermissions=[{
                'IpProtocol': rule_to_remove['permission']['IpProtocol'],
                'FromPort': rule_to_remove['from_port'],
                'ToPort': rule_to_remove['to_port'],
                'IpRanges': [{
                    'CidrIp': rule_to_remove['cidr']
                }]
            }]
        )
        
        print(f'\n\033[32mSuccess! Rule removed from security group {sec_group_name}!\033[0m')
        
    except ValueError:
        print('\n\033[31mErr! Invalid input.\033[0m')
        return
    except KeyboardInterrupt:
        print('\n\nOperation cancelled by user.')
        return
    except Exception as e:
        print(f'\n\033[31mErr! Failed to remove rule: {e}\033[0m')
        return


def main():
    """Main function."""
    ec2 = configure_aws()
    security_groups = list_security_groups(ec2)
    
    if not security_groups:
        print('\033[31mErr! No security groups found.\033[0m')
        return
    
    remove_rule_from_security_group(ec2, security_groups)


if __name__ == '__main__':
    print('\n##############################################')
    print('# Remove IP from a security group            #')
    print('##############################################\n')
    main()
