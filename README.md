# AWS Scripts

This collection of scripts helps you manage AWS Security Groups and CloudWatch Logs. Designed for any AWS Account IAM user with proper permissions.

## Features

### Security Groups
- **Add IP to Security Group**: Add your IP address to a security group with port specification
- **Remove IP from Security Group**: Remove existing IP rules from security groups
- **List Security Group Rules**: View all ingress and egress rules for security groups
- Duplicate rule detection
- Confirmation prompts before making changes
- Input validation for IPs, ports, and descriptions

### CloudWatch Logs
- **Search CloudWatch Logs**: Search and download logs from CloudWatch log groups
- Filter by search string (optional)
- Configurable time range (default: last 8 hours)
- Saves results locally to `outputs/` folder

## Setup

> PLEASE NOTE: This requires python3 installed

### 1. Create an env file

```bash
cp .env.example .env
```

```.env
AWS_ACCESS_KEY_ID=AAA...
AWS_SECRET_ACCESS_KEY=yXAS...
AWS_REGION=us-west-1
```

### 2. Install dependencies

```bash
python3 -m venv .venv
source .venv/bin/activate
pip3 install -r requirements.txt
```

### 3. Run it

```baListSecGroupRules.py** - View all rules in security groups
3. **RemoveIpFromSecGroup.py** - Remove an IP rule from a security group
4. **SearchLogs.py** - Search and download CloudWatch Log
```

## Available Actions

1. **AddMyIp2SecGroup.py** - Add an IP address to a security group
2. **RemoveIpFromSecGroup.py** - Remove an IP rule from a security group
3. **ListSecGroupRules.py** - View all rules in security groups

## Requirements

- Python 3.6+
- boto3
- python-dotenv
- Valid AWS credentials with EC2 permissions
