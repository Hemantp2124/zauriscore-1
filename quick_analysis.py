# Quick contract analysis
import re

# Read contract
with open('src/zauriscore/data/contracts/samples/sample_contract.sol', 'r') as f:
    code = f.read()

print("🛡️ ZauriScore Quick Analysis")
print("=" * 30)
print(f"Contract size: {len(code)} chars")

# Security check
issues = []
if '.call(' in code: issues.append("External calls detected")
if 'tx.origin' in code: issues.append("tx.origin usage - phishing risk")
if 'block.timestamp' in code: issues.append("Timestamp dependency")

print(f"\n🔒 Security Issues: {len(issues)}")
for issue in issues:
    print(f"  • {issue}")

# Gas optimization
print(f"\n⛽ Gas Opportunities:")
if 'mapping' in code: print("  • Consider private mappings")
if 'for' in code: print("  • Loop optimization possible")
if 'require(' in code: print("  • Use custom errors")

# Complexity
functions = len(re.findall(r'function\s+\w+', code))
print(f"\n📈 Complexity:")
print(f"  • Functions: {functions}")
print(f"  • Lines: {len(code.split('\\n'))}")

# Risk level
risk = "HIGH" if issues else "LOW"
print(f"\n🎯 Risk Level: {risk}")
print("✅ Analysis complete!")