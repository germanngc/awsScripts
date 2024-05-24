# AWS Scripts

This portion of code was intended for any AWS Account IAM user that contain the proper permissions.

## Setup

> PLEASE NOT: This requires pytnon3 installed

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
pip3 install boto3 python-dotenv
```

### 3. Run it

```bash
python3 launcher.py
```
