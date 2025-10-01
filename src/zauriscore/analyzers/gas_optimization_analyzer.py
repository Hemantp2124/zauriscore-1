from typing import List, Dict, Any, Union
from slither import Slither
from slither.core.declarations import Contract, Structure
from slither.core.variables.state_variable import StateVariable
from slither.slithir.variables import Constant
from slither.core.cfg.node import Node
from slither.core.expressions.expression import Expression
import logging
import tempfile
import os
import json

class GasOptimizationAnalyzer:
    def __init__(self):
        self.optimizations = []

    def analyze_storage_packing(self, contract: Contract) -> List[Dict[str, Any]]:
        """
        Analyze storage packing opportunities.
        """
        optimizations = []
        
        # Group state variables by their storage slot
        storage_slots = {}
        for var in contract.state_variables:
            if var.visibility in ['public', 'internal', 'private']:
                slot = var.storage_slot
                if slot not in storage_slots:
                    storage_slots[slot] = []
                storage_slots[slot].append(var)
        
        # Check for storage packing opportunities
        for slot, vars_in_slot in storage_slots.items():
            if len(vars_in_slot) > 1:
                # Check if variables can be packed
                can_pack = True
                total_size = 0
                for var in vars_in_slot:
                    # Get variable size in bytes
                    var_size = self._get_variable_size(var.type)
                    if var_size > 32:
                        can_pack = False
                        break
                    total_size += var_size
                
                if can_pack and total_size <= 32:
                    optimizations.append({
                        'issue': 'Storage Packing Opportunity',
                        'severity': 'medium',
                        'suggestion': 'These variables can be packed into a single storage slot',
                        'saving': '~2000-5000 gas per slot saved',
                        'category': 'storage',
                        'matched_code': ', '.join([v.name for v in vars_in_slot]),
                        'example_before': '\n'.join([f'{v.type} {v.name};' for v in vars_in_slot]),
                        'example_after': '// Consider packing these variables together\n' +
                                        '\n'.join([f'{v.type} {v.name};' for v in vars_in_slot]),
                        'rationale': 'Multiple small variables can be packed into a single storage slot to save gas'
                    })
        
        return optimizations

    def analyze(self, contract: Union[Contract, str]) -> List[Dict[str, Any]]:
        """
        Analyze a contract for gas optimization opportunities.
        
        Args:
            contract: Either a Slither Contract object or a string containing Solidity source code
        
        Returns:
            List of optimization opportunities
        """
        optimizations = []
        
        # If input is a string, parse it as Solidity source code
        if isinstance(contract, str):
            try:
                # First try direct string analysis (faster and more reliable for simple cases)
                string_optimizations = self.analyze_solidity_source(contract)
                if string_optimizations:
                    return string_optimizations
                
                # If no optimizations found via string analysis, try Slither
                with tempfile.NamedTemporaryFile(mode='w', suffix='.sol', delete=False) as temp:
                    temp.write(contract)
                    temp_path = temp.name
                
                slither = Slither(temp_path)
                if not slither.contracts:
                    logging.warning("No contracts found in the provided source code")
                    return []
                
                # Analyze each contract in the file
                for contract_obj in slither.contracts:
                    optimizations.extend(self.analyze_contract(contract_obj))
                
                return optimizations
                
            except Exception as e:
                logging.error(f"Error analyzing contract with Slither: {e}")
                # Fall back to string analysis if Slither parsing fails
                return self.analyze_solidity_source(contract)
                
            finally:
                # Clean up the temporary file
                if 'temp_path' in locals() and os.path.exists(temp_path):
                    try:
                        os.unlink(temp_path)
                    except Exception as e:
                        logging.warning(f"Failed to delete temporary file {temp_path}: {e}")
        
        # If input is already a Contract object
        elif isinstance(contract, Contract):
            return self.analyze_contract(contract)
        
        else:
            raise ValueError("Input must be either a Solidity source code string or a Slither Contract object")
    
    def analyze_contract(self, contract: Contract) -> List[Dict[str, Any]]:
        """
        Analyze a single contract for all gas optimizations.
        """
        optimizations = []
        optimizations.extend(self.analyze_storage_packing(contract))
        optimizations.extend(self.analyze_public_mappings(contract))
        optimizations.extend(self.analyze_struct_packing(contract))
        optimizations.extend(self.analyze_dynamic_bytes(contract))
        optimizations.extend(self.analyze_mapping_initialization(contract))
        optimizations.extend(self.analyze_multiple_small_uints(contract))
        return optimizations
    
    def analyze_solidity_source(self, source_code: str) -> List[Dict[str, Any]]:
        """
        Analyze Solidity source code using string matching when Slither parsing fails.
        """
        optimizations = []
        
        # Check for public mappings
        if 'mapping(' in source_code and 'public' in source_code and ';' in source_code.split('public')[-1]:
            optimizations.append({
                'issue': 'Public Mapping',
                'severity': 'low',
                'suggestion': 'Consider making the mapping private and adding a getter function',
                'saving': '~2000 gas per access',
                'category': 'storage',
                'matched_code': 'mapping(...) public ...',
                'example_before': 'mapping(...) public name;',
                'example_after': 'mapping(...) private _name;\n\n    function getName(...) public view returns (...) {\n        return _name[...];\n    }',
                'rationale': 'Public mappings generate an implicit getter function that can be expensive. Making it private with an explicit getter can save gas.'
            })

    def analyze_public_mappings(self, contract: Contract) -> List[Dict[str, Any]]:
        """Detect public mappings that could be made private."""
        optimizations = []
        
        for var in contract.state_variables:
            if var.visibility == 'public' and str(var.type).startswith('mapping'):
                # Check if there's a getter function that could replace the public mapping
                has_getter = any(
                    f.is_constructor is False and 
                    f.visibility in ['public', 'external'] and 
                    f.pure or f.view
                    for f in contract.functions
                )
                
                if not has_getter:
                    optimizations.append({
                        'issue': 'Public Mapping',
                        'severity': 'low',
                        'suggestion': f'Consider making mapping {var.name} private and adding a getter function',
                        'saving': '~2000 gas per access',
                        'category': 'storage',
                        'matched_code': f'mapping(...) public {var.name}' if hasattr(var, 'name') else str(var),
                        'example_before': f'mapping(...) public {var.name};',
                        'example_after': f'mapping(...) private {var.name};\n\n    function get{var.name.capitalize()}(...) public view returns (...) {{\n        return {var.name}[...];\n    }}',
                        'rationale': 'Public mappings generate an implicit getter function. Using a private mapping with an explicit getter can save gas.'
                    })
        
        return optimizations

    def analyze_struct_packing(self, contract: Contract) -> List[Dict[str, Any]]:
        """Detect inefficient struct packing."""
        optimizations = []
        
        for struct in contract.structures:
            # Get all variables in the struct
            vars_in_struct = struct.elems_ordered
            
            # Calculate current storage usage
            current_slots = 0
            current_slot_used = 0
            
            for var in vars_in_struct:
                var_size = self._get_variable_size(var.type)
                
                if current_slot_used + var_size > 32:
                    current_slots += 1
                    current_slot_used = var_size
                else:
                    current_slot_used += var_size
            
            if current_slot_used > 0:
                current_slots += 1
            
            # Calculate optimal packing
            vars_sorted = sorted(vars_in_struct, key=lambda v: self._get_variable_size(v.type), reverse=True)
            optimal_slots = 0
            optimal_used = 0
            
            for var in vars_sorted:
                var_size = self._get_variable_size(var.type)
                
                if optimal_used + var_size > 32:
                    optimal_slots += 1
                    optimal_used = var_size
                else:
                    optimal_used += var_size
            
            if optimal_used > 0:
                optimal_slots += 1
            
            # If we can save slots, add an optimization
            if optimal_slots < current_slots:
                optimizations.append({
                    'issue': 'Inefficient Struct Packing',
                    'severity': 'medium',
                    'suggestion': f'Reorganize struct {struct.name} to use fewer storage slots',
                    'saving': f'~{2000 * (current_slots - optimal_slots)} gas per instance',
                    'category': 'storage',
                    'matched_code': f'struct {struct.name} {{ ... }}',
                    'example_before': f'struct {struct.name} {{\n    ' + '\n    '.join(f'{var.type} {var.name};' for var in vars_in_struct) + '\n}',
                    'example_after': f'struct {struct.name} {{\n    ' + '\n    '.join(f'{var.type} {var.name};' for var in vars_sorted) + '\n}',
                    'rationale': 'Reordering struct variables can reduce storage slots used, saving gas.'
                })
        
        return optimizations

    def analyze_dynamic_bytes(self, contract: Contract) -> List[Dict[str, Any]]:
        """Detect dynamic bytes arrays that could be fixed-size."""
        optimizations = []
        
        for var in contract.state_variables:
            if str(var.type) == 'bytes' and var.visibility in ['public', 'private', 'internal']:
                optimizations.append({
                    'issue': 'Dynamic Bytes Array',
                    'severity': 'medium',
                    'suggestion': f'Consider using bytes32 instead of dynamic bytes for {var.name} if the maximum size is known',
                    'saving': '~20000 gas for storage, ~100 gas per access',
                    'category': 'storage',
                    'matched_code': f'bytes public {var.name};',
                    'example_before': f'bytes public {var.name};',
                    'example_after': f'bytes32 public {var.name};  // If max size is 32 bytes',
                    'rationale': 'Dynamic bytes arrays are more expensive in terms of gas than fixed-size bytes.'
                })
        
        return optimizations

    def analyze_mapping_initialization(self, contract: Contract) -> List[Dict[str, Any]]:
        """Detect mappings that are initialized with values."""
        optimizations = []
        
        for var in contract.state_variables:
            if str(var.type).startswith('mapping') and var.expression:
                optimizations.append({
                    'issue': 'Mapping with Initial Value',
                    'severity': 'low',
                    'suggestion': f'Initialize mapping {var.name} in the constructor instead of at declaration',
                    'saving': '~20000 gas per mapping',
                    'category': 'deployment',
                    'matched_code': f'mapping(...) public {var.name} = ...;',
                    'example_before': f'mapping(...) public {var.name} = {{ ... }};',
                    'example_after': f'mapping(...) public {var.name};\n\n    constructor() {{\n        {var.name}[...] = ...;\n    }}',
                    'rationale': 'Initializing mappings at declaration is more expensive than in the constructor.'
                })
        
        return optimizations

    def _get_variable_size(self, var_type) -> int:
        """Get the size of a variable type in bytes."""
        if isinstance(var_type, str):
            if var_type.startswith('uint'):
                # For uint types, get the size from the type name
                size = int(var_type[4:]) // 8 if var_type[4:] else 32
                return size
            elif var_type == 'bool':
                return 1
            elif var_type.startswith('bytes'):
                # For bytes types, get the size from the type name
                size = int(var_type[5:]) if var_type[5:] else 32
                return size
        return 32