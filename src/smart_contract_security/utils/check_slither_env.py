import subprocess
import sys
import os
from typing import Dict, Any

def check_slither_installation() -> Dict[str, Any]:
    """Check if Slither and Solc are properly installed and available.
    
    Returns:
        Dict[str, Any]: Status of the installation including versions and any errors
    """
    result = {
        'python_executable': sys.executable,
        'path': os.environ.get('PATH'),
        'slither_installed': False,
        'solc_installed': False,
        'slither_version': None,
        'solc_version': None,
        'errors': []
    }
    
    try:
        # Check slither
        process = subprocess.run(["slither", "--version"], capture_output=True, text=True, timeout=30, check=False)
        if process.returncode == 0:
            result['slither_installed'] = True
            result['slither_version'] = process.stdout.strip()
        else:
            result['errors'].append(f"Slither error: {process.stderr}")

        # Check solc
        process_solc = subprocess.run(["solc", "--version"], capture_output=True, text=True, timeout=30, check=False)
        if process_solc.returncode == 0:
            result['solc_installed'] = True
            result['solc_version'] = process_solc.stdout.strip()
        else:
            result['errors'].append(f"Solc error: {process_solc.stderr}")

    except FileNotFoundError as e:
        result['errors'].append(f"Error: {e}. One of the commands (slither or solc) was not found in the PATH.")
    except Exception as e:
        result['errors'].append(f"An unexpected error occurred: {e}")

    return result

if __name__ == '__main__':
    status = check_slither_installation()
    print("\nSlither Environment Check:")
    print(f"Python Executable: {status['python_executable']}")
    print(f"PATH: {status['path']}")
    print(f"Slither Installed: {status['slither_installed']}")
    print(f"Solc Installed: {status['solc_installed']}")
    if status['slither_version']:
        print(f"Slither Version: {status['slither_version']}")
    if status['solc_version']:
        print(f"Solc Version: {status['solc_version']}")
    if status['errors']:
        print("\nErrors:")
        for error in status['errors']:
            print(f"- {error}")
