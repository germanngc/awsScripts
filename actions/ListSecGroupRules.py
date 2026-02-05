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


def format_port_range(from_port, to_port):
    """Format port range for display."""
    if from_port == to_port:
        return str(from_port)
    return f'{from_port}-{to_port}'


def display_rules_for_group(ec2, group_id, group_name):
    """Display all ingress and egress rules for a security group."""
    try:
        response = ec2.describe_security_groups(GroupIds=[group_id])
        if not response['SecurityGroups']:
            print('\033[31mErr! Security group not found.\033[0m')
            return
        
        sg = response['SecurityGroups'][0]
        
        print(f'\n\033[36m{"="*70}\033[0m')
        print(f'\033[36mSecurity Group: {group_name}\033[0m')
        print(f'\033[36mGroup ID: {group_id}\033[0m')
        print(f'\033[36mVPC ID: {sg.get("VpcId", "N/A")}\033[0m')
        print(f'\033[36mDescription: {sg.get("Description", "N/A")}\033[0m')
        print(f'\033[36m{"="*70}\033[0m')
        
        # Display Ingress Rules
        print('\n\033[33m== INGRESS RULES (Inbound):\033[0m\n')
        ingress_rules = sg.get('IpPermissions', [])
        
        if not ingress_rules:
            print('  \033[90mNo ingress rules\033[0m')
        else:
            for idx, permission in enumerate(ingress_rules, 1):
                protocol = permission.get('IpProtocol', 'unknown')
                if protocol == '-1':
                    protocol = 'All'
                    port_str = 'All'
                else:
                    from_port = permission.get('FromPort', 'N/A')
                    to_port = permission.get('ToPort', 'N/A')
                    port_str = format_port_range(from_port, to_port)
                
                # IP Ranges (IPv4)
                for ip_range in permission.get('IpRanges', []):
                    cidr = ip_range.get('CidrIp', 'N/A')
                    description = ip_range.get('Description', '')
                    desc_str = f' - {description}' if description else ''
                    print(f'  \033[32m[{idx}]\033[0m Protocol: {protocol:8} | Port: {port_str:10} | Source: {cidr:18}{desc_str}')
                
                # IPv6 Ranges
                for ipv6_range in permission.get('Ipv6Ranges', []):
                    cidr = ipv6_range.get('CidrIpv6', 'N/A')
                    description = ipv6_range.get('Description', '')
                    desc_str = f' - {description}' if description else ''
                    print(f'  \033[32m[{idx}]\033[0m Protocol: {protocol:8} | Port: {port_str:10} | Source: {cidr:18}{desc_str}')
                
                # Security Groups
                for sg_ref in permission.get('UserIdGroupPairs', []):
                    sg_id = sg_ref.get('GroupId', 'N/A')
                    description = sg_ref.get('Description', '')
                    desc_str = f' - {description}' if description else ''
                    print(f'  \033[32m[{idx}]\033[0m Protocol: {protocol:8} | Port: {port_str:10} | Source: SG {sg_id}{desc_str}')
        
        # Display Egress Rules
        print('\n\033[33m== EGRESS RULES (Outbound):\033[0m\n')
        egress_rules = sg.get('IpPermissionsEgress', [])
        
        if not egress_rules:
            print('  \033[90mNo egress rules\033[0m')
        else:
            for idx, permission in enumerate(egress_rules, 1):
                protocol = permission.get('IpProtocol', 'unknown')
                if protocol == '-1':
                    protocol = 'All'
                    port_str = 'All'
                else:
                    from_port = permission.get('FromPort', 'N/A')
                    to_port = permission.get('ToPort', 'N/A')
                    port_str = format_port_range(from_port, to_port)
                
                # IP Ranges (IPv4)
                for ip_range in permission.get('IpRanges', []):
                    cidr = ip_range.get('CidrIp', 'N/A')
                    description = ip_range.get('Description', '')
                    desc_str = f' - {description}' if description else ''
                    print(f'  \033[32m[{idx}]\033[0m Protocol: {protocol:8} | Port: {port_str:10} | Dest: {cidr:18}{desc_str}')
                
                # IPv6 Ranges
                for ipv6_range in permission.get('Ipv6Ranges', []):
                    cidr = ipv6_range.get('CidrIpv6', 'N/A')
                    description = ipv6_range.get('Description', '')
                    desc_str = f' - {description}' if description else ''
                    print(f'  \033[32m[{idx}]\033[0m Protocol: {protocol:8} | Port: {port_str:10} | Dest: {cidr:18}{desc_str}')
                
                # Security Groups
                for sg_ref in permission.get('UserIdGroupPairs', []):
                    sg_id = sg_ref.get('GroupId', 'N/A')
                    description = sg_ref.get('Description', '')
                    desc_str = f' - {description}' if description else ''
                    print(f'  \033[32m[{idx}]\033[0m Protocol: {protocol:8} | Port: {port_str:10} | Dest: SG {sg_id}{desc_str}')
        
        print()
        
    except Exception as e:
        print(f'\033[31mErr! Failed to display rules: {e}\033[0m')


def list_security_group_rules(ec2, security_groups):
    """List rules for selected security group(s)."""
    print('== Available Security Groups:\n')
    for i, sg in enumerate(security_groups, 1):
        print(f"\t\033[32m[{i}] {sg['GroupName']}\033[0m (ID: {sg['GroupId']})")
    
    print(f"\t\033[32m[0] All security groups\033[0m")
    
    try:
        print('')
        choice = input('Enter the number of the SG to view (or 0 for all): ').strip()
        
        if choice == '0':
            # Show all security groups
            for sg in security_groups:
                display_rules_for_group(ec2, sg['GroupId'], sg['GroupName'])
        else:
            choice_num = int(choice)
            if not 1 <= choice_num <= len(security_groups):
                print('\033[31mErr! Invalid choice.\033[0m')
                return
            
            selected_sg = security_groups[choice_num - 1]
            display_rules_for_group(ec2, selected_sg['GroupId'], selected_sg['GroupName'])
        
    except ValueError:
        print('\n\033[31mErr! Invalid input.\033[0m')
        return
    except KeyboardInterrupt:
        print('\n\nOperation cancelled by user.')
        return
    except Exception as e:
        print(f'\n\033[31mErr! {e}\033[0m')
        return


def main():
    """Main function."""
    ec2 = configure_aws()
    security_groups = list_security_groups(ec2)
    
    if not security_groups:
        print('\033[31mErr! No security groups found.\033[0m')
        return
    
    list_security_group_rules(ec2, security_groups)


if __name__ == '__main__':
    print('\n##############################################')
    print('# List Security Group Rules                  #')
    print('##############################################\n')
    main()
