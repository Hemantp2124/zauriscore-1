import subprocess
import json
import os
import logging
from typing import Dict, Any

logger = logging.getLogger(__name__)

class MythrilAnalyzer:
    def __init__(self):
        self.logger = logger

    def analyze(self, source_path: str) -> Dict[str, Any]:
        """Run Mythril analysis on the contract source."""
        self.logger.info(f"Running Mythril analysis on {source_path}")
        try:
            # Prepare command: use --solv to auto-detect solc if needed
            cmd = ['myth', 'analyze', source_path, '--json-stdout', '--max-depth', '10']
            if os.path.isdir(source_path):
                cmd.append('--solc')
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600,  # 10 minutes timeout
                cwd=os.path.dirname(source_path)
            )
            if result.returncode != 0:
                self.logger.error(f"Mythril failed: {result.stderr}")
                return {'error': result.stderr, 'score': 0.0, 'vulnerabilities': []}

            data = json.loads(result.stdout)
            issues = data.get('issues', [])

            # Count severities
            severity_counts = {'high': 0, 'medium': 0, 'low': 0, 'informational': 0}
            for issue in issues:
                sev = issue.get('severity', 'informational').lower()
                severity_counts[sev] = severity_counts.get(sev, 0) + 1

            # Compute score (0-10 scale, higher = more vulnerable)
            mythril_score = min(10.0,
                severity_counts['high'] * 4.0 +
                severity_counts['medium'] * 2.0 +
                severity_counts['low'] * 0.5 +
                severity_counts['informational'] * 0.1
            )

            # Format vulnerabilities
            vulnerabilities = []
            for issue in issues:
                vul = {
                    'title': issue.get('title', 'Unknown Issue'),
                    'description': issue.get('description', 'No description provided'),
                    'severity': issue.get('severity', 'low'),
                    'filename': issue.get('filename', 'Unknown'),
                    'line_number': issue.get('line', 0),
                    'function': issue.get('function', 'Unknown'),
                    'overflow': issue.get('overflow', False)
                }
                vulnerabilities.append(vul)

            return {
                'score': round(mythril_score, 2),
                'vulnerabilities': vulnerabilities,
                'severity_counts': severity_counts,
                'total_issues': len(issues),
                'raw_data': data
            }
        except json.JSONDecodeError as e:
            self.logger.error(f"Failed to parse Mythril JSON output: {e}")
            return {'error': 'Invalid JSON output from Mythril', 'score': 0.0, 'vulnerabilities': []}
        except subprocess.TimeoutExpired:
            self.logger.error("Mythril analysis timed out after 10 minutes")
            return {'error': 'Analysis timeout', 'score': 0.0, 'vulnerabilities': []}
        except FileNotFoundError:
            self.logger.error("Mythril not found in PATH. Ensure mythril is installed.")
            return {'error': 'Mythril not installed', 'score': 0.0, 'vulnerabilities': []}
        except Exception as e:
            self.logger.error(f"Unexpected error in Mythril analysis: {str(e)}")
            return {'error': str(e), 'score': 0.0, 'vulnerabilities': []}