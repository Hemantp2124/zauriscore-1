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
import slither.core.solidity_types

class GasOptimizationAnalyzer:
    def __init__(self):
        self.optimizations = []

    def analyze_storage_packing(self, contract: Contract) -> List[Dict[str, Any]]:
        optimizations = []
        for var in contract.state_variables:
            slot = var.slot  # Changed from var.storage_slot
            adjacent_slot = contract.get_state_variable_at_slot(slot + 1) if slot is not None else None
            if adjacent_slot is not None and self.can_pack_variables(var, adjacent_slot):
                optimizations.append({
                    'issue': 'Storage Packing Opportunity',
                    'severity': 'medium',
                    'suggestion': f'Pack {var.name} with adjacent variable to save storage slots',
                    'saving': '~20000 gas per slot saved',
                    'category': 'storage',
                    'matched_code': str(var.type) + ' ' + var.name + ';',
                    'example_before': str(var.type) + ' ' + var.name + ';\n' + str(adjacent_slot.type) + ' ' + adjacent_slot.name + ';',
                    'example_after': str(var.type) + ' ' + var.name + '; ' + str(adjacent_slot.type) + ' ' + adjacent_slot.name + '; // packed',
                    'rationale': 'Packing small variables into the same storage slot saves gas on reads/writes.'
                })
        return optimizations

    def analyze_multiple_small_uints(self, contract: Contract) -> List[Dict[str, Any]]:
        """
        Analyze for multiple small uint variables that can be packed.
        """
        optimizations = []
        small_uints = []
        
        for var in contract.state_variables:
            if str(var.type).startswith('uint') and 'uint256' not in str(var.type):
                size = self._get_variable_size(var.type)
                if size < 32:
                    small_uints.append(var)
        
        if len(small_uints) > 1:
            total_size = sum(self._get_variable_size(var.type) for var in small_uints)
            if total_size <= 32:
                optimizations.append({
                    'issue': 'Multiple Small Uints',
                    'severity': 'medium',
                    'suggestion': 'Pack multiple small uint variables into a single slot',
                    'saving': f'~{2000 * (len(small_uints) - 1)} gas per access',
                    'category': 'storage',
                    'matched_code': ', '.join([f'{v.type} {v.name}' for v in small_uints]),
                    'example_before': '\n'.join([f'{var.type} {var.name};' for var in small_uints]),
                    'example_after': '// Pack these into one uint256 or struct',
                    'rationale': 'Small uints waste storage slots; packing them saves gas.'
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
            if isinstance(var.type, slither.core.solidity_types.MappingType) and var.visibility == 'public':  # Changed from str(var.type).startswith('mapping')
                optimizations.append({
                    'issue': 'Public Mapping Getter',
                    'severity': 'medium',
                    'suggestion': f'Make mapping {var.name} private and add explicit getter function',
                    'saving': '~3000 gas per call to implicit getter',
                    'category': 'storage',
                    'matched_code': f'mapping(...) public {var.name}',
                    'example_before': f'mapping(...) public {var.name};',
                    'example_after': f'mapping(...) private {var.name};\n\n    function get{var.name.capitalize()}(...) public view returns (...) {{ return {var.name}[...]; }}',
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
            from slither.core.solidity_types import DynamicBytes
            if isinstance(var.type, DynamicBytes):
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
            if isinstance(var.type, slither.core.solidity_types.MappingType) and var.expression:  # Changed from str(var.type).startswith('mapping')
                optimizations.append({
                    'issue': 'Mapping with Initial Value',
                    'severity': 'low',
                    'suggestion': f'Initialize mapping {var.name} in the constructor instead of at declaration',
                    'saving': '~20000 gas per mapping',
                    'category': 'deployment',
                    'matched_code': f'mapping(...) public {var.name} = ...;',
                    'example_before': f'mapping(...) public {var.name} = {{ ... }};',
                    'example_after': f'mapping(...) public {var.name};\n\n    constructor() {{ {var.name}[...] = ...; }}',
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