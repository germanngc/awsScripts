import os
import subprocess

ACTIONS_DIR = 'actions'

def list_scripts():
    return [f for f in os.listdir(ACTIONS_DIR) if f.endswith('.py')]

def run_script(script):
    print(f'Running {os.path.join(ACTIONS_DIR, script)}...')
    subprocess.call(['python3', os.path.join(ACTIONS_DIR, script)])

def main():
    scripts = list_scripts()
    if not scripts:
        print(f'\033[31mErr: No actions found.\033[0m')
        return
    print('== Available actions:\n')
    for i, script in enumerate(scripts, 1):
        print(f'\t\033[32m[{i}] {script}\033[0m')
    try:
        print('')
        choice = int(input('Enter the number of the action you want to run: '))
        assert 1 <= choice <= len(scripts)
    except (ValueError, AssertionError):
        print(f'\033[31mErr: Invalid choice.\033[0m')
        return
    run_script(scripts[choice - 1])

if __name__ == '__main__':
    print('##############################################')
    print('# Welcome to Evalart AWS Scripts!            #')
    print('##############################################\n')
    main()