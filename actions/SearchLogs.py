from dotenv import load_dotenv
import boto3
import os
import sys
from datetime import datetime, timedelta


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
        return boto3.client('logs')
    except Exception as e:
        print(f'\033[31mErr! Failed to configure AWS: {e}\033[0m')
        sys.exit(1)


def list_log_groups(logs_client):
    """List all available CloudWatch log groups."""
    try:
        log_groups = []
        paginator = logs_client.get_paginator('describe_log_groups')
        
        print('Fetching log groups...')
        for page in paginator.paginate():
            log_groups.extend(page['logGroups'])
        
        return sorted(log_groups, key=lambda k: k['logGroupName'])
    except Exception as e:
        print(f'\033[31mErr! Failed to list log groups: {e}\033[0m')
        sys.exit(1)


def search_logs(logs_client, log_group_name, search_string=None, hours=8):
    """Search logs in a log group for the last N hours."""
    try:
        # Calculate time range (last N hours)
        end_time = datetime.now()
        start_time = end_time - timedelta(hours=hours)
        
        # Convert to milliseconds since epoch
        start_ms = int(start_time.timestamp() * 1000)
        end_ms = int(end_time.timestamp() * 1000)
        
        print(f'\nSearching logs from {start_time.strftime("%Y-%m-%d %H:%M:%S")} to {end_time.strftime("%Y-%m-%d %H:%M:%S")}')
        if search_string:
            print(f'Filter: "{search_string}"')
        print()
        
        events = []
        kwargs = {
            'logGroupName': log_group_name,
            'startTime': start_ms,
            'endTime': end_ms,
            'limit': 10000  # Maximum per request
        }
        
        # Add filter pattern if search string provided
        if search_string:
            kwargs['filterPattern'] = search_string
        
        # Paginate through results
        while True:
            response = logs_client.filter_log_events(**kwargs)
            events.extend(response.get('events', []))
            
            # Check if there are more results
            next_token = response.get('nextToken')
            if not next_token:
                break
            
            kwargs['nextToken'] = next_token
            print(f'Fetched {len(events)} events so far...')
        
        print(f'\n\033[32mTotal events found: {len(events)}\033[0m')
        return events
        
    except Exception as e:
        print(f'\033[31mErr! Failed to search logs: {e}\033[0m')
        sys.exit(1)


def save_logs_to_file(events, log_group_name):
    """Save log events to a local file."""
    try:
        # Create outputs directory if it doesn't exist
        output_dir = 'outputs'
        os.makedirs(output_dir, exist_ok=True)
        
        # Generate filename from log group name (sanitize it)
        safe_name = log_group_name.replace('/', '_').replace('\\', '_')
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f'{safe_name}_{timestamp}.log'
        filepath = os.path.join(output_dir, filename)
        
        # Write events to file
        with open(filepath, 'w', encoding='utf-8') as f:
            for event in events:
                # Format: timestamp | log_stream | message
                timestamp_str = datetime.fromtimestamp(event['timestamp'] / 1000).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
                log_stream = event.get('logStreamName', 'unknown')
                message = event.get('message', '').rstrip()
                
                f.write(f'[{timestamp_str}] [{log_stream}] {message}\n')
        
        print(f'\n\033[32mLogs saved to: {filepath}\033[0m')
        return filepath
        
    except Exception as e:
        print(f'\033[31mErr! Failed to save logs: {e}\033[0m')
        sys.exit(1)


def search_cloudwatch_logs(logs_client, log_groups):
    """Main function to search CloudWatch logs."""
    # Display log groups
    print('== Available Log Groups:\n')
    for i, lg in enumerate(log_groups, 1):
        storage_bytes = lg.get('storedBytes', 0)
        storage_mb = storage_bytes / (1024 * 1024)
        print(f"\t\033[32m[{i}]\033[0m {lg['logGroupName']} ({storage_mb:.2f} MB)")
    
    try:
        # Select log group
        print('')
        choice = int(input('Enter the number of the log group: '))
        if not 1 <= choice <= len(log_groups):
            print('\033[31mErr! Invalid choice.\033[0m')
            return
        
        selected_log_group = log_groups[choice - 1]
        log_group_name = selected_log_group['logGroupName']
        
        # Ask for search string
        print('')
        search_option = input('Do you want to search for a specific string? (y/N): ').strip().lower()
        
        search_string = None
        if search_option == 'y':
            search_string = input('Enter the search string: ').strip()
            if not search_string:
                print('\033[33mWarning: Empty search string, will fetch all logs\033[0m')
                search_string = None
        
        # Ask for time range (default 8 hours)
        hours_input = input('\nEnter hours to look back (default 8): ').strip()
        try:
            hours = int(hours_input) if hours_input else 8
            if hours < 1:
                print('\033[33mWarning: Hours must be at least 1, using default 8\033[0m')
                hours = 8
        except ValueError:
            print('\033[33mWarning: Invalid input, using default 8 hours\033[0m')
            hours = 8
        
        # Search logs
        print(f'\n\033[33mSearching logs in: {log_group_name}\033[0m')
        events = search_logs(logs_client, log_group_name, search_string, hours)
        
        if not events:
            print('\n\033[33mNo log entries found matching your criteria.\033[0m')
            return
        
        # Save to file
        save_logs_to_file(events, log_group_name)
        
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
    logs_client = configure_aws()
    log_groups = list_log_groups(logs_client)
    
    if not log_groups:
        print('\033[31mErr! No log groups found.\033[0m')
        return
    
    search_cloudwatch_logs(logs_client, log_groups)


if __name__ == '__main__':
    print('\n##############################################')
    print('# Search CloudWatch Logs                     #')
    print('##############################################\n')
    main()
