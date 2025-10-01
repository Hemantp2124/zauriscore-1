import sys
import argparse
import logging
from zauriscore.analyzers.comprehensive_contract_analysis import ComprehensiveContractAnalyzer
import os

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

def print_section_header(title):
    print(f"\n{'=' * 80}")
    print(f"{title}")
    print(f"{'=' * 80}")

def print_subsection_header(title):
    print(f"\n{'-' * 80}")
    print(f"{title}")
    print(f"{'-' * 80}")

def format_dict(data, indent=2):
    if not isinstance(data, dict):
        return str(data)
    result = []
    for key, value in data.items():
        if isinstance(value, dict):
            result.append(f"{' ' * indent}{key}:")
            result.append(format_dict(value, indent + 2))
        else:
            result.append(f"{' ' * indent}{key}: {value}")
    return '\n'.join(result)

def validate_address(contract_address):
    if not contract_address.startswith('0x') or len(contract_address) != 42:
        return False, "Invalid format. Must start with '0x' and be 42 characters long."
    return True, ""

def main():
    parser = argparse.ArgumentParser(description='Analyze Ethereum smart contracts for security risks.')
    parser.add_argument('addresses', nargs='+', help='One or more contract addresses to analyze (e.g., 0xbb9bc244d798123fde783fcc1c72d3bb8c189413)')
    parser.add_argument('--api-key', help='Etherscan API key (optional, will use environment variable if not provided)')
    args = parser.parse_args()
    
    # Set API key if provided
    if args.api_key:
        os.environ['ETHERSCAN_API_KEY'] = args.api_key
    
    addresses = args.addresses
    
    for contract_address in addresses:
        is_valid, error_msg = validate_address(contract_address)
        if not is_valid:
            print(f"Error: {contract_address} - {error_msg}")
            continue
        
        print_section_header(f"Analyzing contract: {contract_address}")
        
        try:
            # Initialize the analyzer
            analyzer = ComprehensiveContractAnalyzer()
            
            # Get raw source code first
            print("\n[+] Fetching raw contract data from Etherscan...")
            raw_data = analyzer.get_contract_source(contract_address, chain='ethereum')
            
            print("\n[+] Raw Data Received:")
            print(f"Status: {raw_data.get('status', 'N/A')}")
            print(f"Message: {raw_data.get('message', 'N/A')}")
            
            if raw_data.get('status') == '1':
                contract_data = raw_data.get('result', [{}])[0]
                print("\n[+] Contract Details:")
                print(f"Name: {contract_data.get('ContractName', 'N/A')}")
                print(f"Compiler: {contract_data.get('CompilerVersion', 'N/A')}")
                print(f"Optimization: {contract_data.get('OptimizationUsed', 'N/A')}")
                print(f"License: {contract_data.get('LicenseType', 'N/A')}")
                
                # Handle source code
                source_code = contract_data.get('SourceCode', '')
                if source_code:
                    print("\n[+] Source Code Analysis:")
                    print(f"Source Code Length: {len(source_code)} bytes")
                    print(f"Is JSON: {source_code.startswith('{')}")
                    
                    # Try to parse JSON source code
                    if source_code.startswith('{'):
                        try:
                            import json
                            source_json = json.loads(source_code)
                            print("\n[+] JSON Source Structure:")
                            print(f"Files: {len(source_json.get('sources', {}))}")
                            for file_path, file_data in source_json.get('sources', {}).items():
                                print(f"\nFile: {file_path}")
                                print(f"Content Length: {len(file_data.get('content', ''))} bytes")
                                print(f"First 100 chars: {file_data.get('content', '')[:100]}")
                        except json.JSONDecodeError as e:
                            print(f"\n[!] JSON parsing error: {e}")
                            print("Raw source code (first 100 chars):")
                            print(source_code[:100])
                else:
                    print("\n[!] No source code verified found in response")
            else:
                print(f"\n[!] Error from Etherscan: {raw_data.get('message', 'Unknown error')}")
                print(f"Details: {raw_data.get('result', 'No details')}")
                
            # Analyze the contract
            print("\n[+] Running full analysis...")
            result = analyzer.analyze_contract(contract_address=contract_address)
            
            # Print key scores for validation
            print_subsection_header("Risk Scores")
            print(f"Slither Score: {result.get('slither_score', 'N/A')}")
            print(f"ML Score: {result.get('ml_score', 'N/A')}")
            print(f"Mythril Score: {result.get('mythril_score', 'N/A')}")
            print(f"Overall Weighted Score: {result.get('overall_score', 'N/A')} (Higher indicates higher risk)")
            
            # Print vulnerabilities summary
            if 'vulnerabilities' in result:
                print_subsection_header("Vulnerabilities")
                for vuln in result['vulnerabilities']:
                    print(f"- {vuln.get('type', 'Unknown')}: {vuln.get('description', '')} (Severity: {vuln.get('severity', 'N/A')})")
            
            # Print the analysis results (abbreviated for validation)
            print_subsection_header("Contract Information")
            print(format_dict({
                'Name': result.get('contract_name', 'N/A'),
                'Compiler Version': result.get('compiler_version', 'N/A'),
                'Optimization Used': result.get('optimization_used', 'N/A'),
                'Optimization Runs': result.get('optimization_runs', 'N/A'),
                'License Type': result.get('license_type', 'N/A'),
                'Source Code Size': f"{len(result.get('source_code', ''))} bytes"
            }))
            
            # Security Analysis summary
            print_subsection_header("Security Analysis Summary")
            if 'security_issues' in result and result['security_issues']:
                for idx, issue in enumerate(result['security_issues'], 1):
                    print(f"{idx}. {issue['check']} ({issue['impact'].upper()})")
                    print(f"   Description: {issue['description'][:100]}...")
            else:
                print("No security issues found")
            
        except Exception as e:
            print(f"\n[!] Error analyzing contract {contract_address}: {str(e)}")
            if hasattr(e, '__traceback__'):
                import traceback
                traceback.print_exc()
        
        print_section_header(f"Analysis for {contract_address} Complete\n")
    
if __name__ == "__main__":
    main()
