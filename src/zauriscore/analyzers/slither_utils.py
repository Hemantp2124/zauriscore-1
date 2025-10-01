import slither
import json
import logging
import networkx as nx
from typing import Dict, Any, List, Tuple

from slither.core.cfg.node import Node
from slither.slithir.operations import LibraryCall, InternalCall
from slither.slithir.variables import Constant

logger = logging.getLogger(__name__)

class SlitherUtils:
    """
    Shared utility class for Slither initialization, CFG extraction, and basic taint analysis.
    Designed to reduce code duplication across analyzers.
    """

    @staticmethod
    def init_slither(contract_path: str):
        """
        Initialize and return Slither instance.
        :param contract_path: Path to the Solidity contract file.
        :return: Slither instance
        """
        try:
            slither_instance = slither.Slither(contract_path)
            logger.info(f'Slither initialized successfully for {contract_path}')
            return slither_instance
        except Exception as e:
            logger.error(f'Failed to initialize Slither: {e}')
            raise

    @staticmethod
    def extract_features(contract):
        """Extract detailed features from the contract AST using Slither."""
        from slither.core.cfg.node import NodeType  # Assuming this is available
        features = {
            'functions': [],
            'state_variables': [],
            'modifiers': [],
            'loops': 0
        }
    
        # Extract functions
        for func in contract.functions:
            func_info = {
                'name': func.name,
                'visibility': func.visibility,
                'is_constructor': func.is_constructor,
                'returns': [ret.type.name if ret.type else 'void' for ret in func.returns],
                'parameters': [param.type.name if param.type else 'unknown' for param in func.parameters]
            }
            features['functions'].append(func_info)
    
            # Extract modifiers
            if func.modifiers:
                for mod in func.modifiers:
                    if mod.name not in features['modifiers']:
                        features['modifiers'].append(mod.name)
    
            # Count loops in function body
            for node in func.nodes:
                if hasattr(node, 'type') and node.type == NodeType.IFLOOP:
                    features['loops'] += 1

        # Extract state variables (storage)
        for var in contract.state_variables:
            var_info = {
                'name': var.name,
                'type': var.type.name if var.type else 'unknown',
                'visibility': var.visibility,
                'is_constant': var.is_constant,
                'is_immutable': var.is_immutable
            }
            features['state_variables'].append(var_info)
    
        return features

    def extract_cfg(self, slither_instance) -> Dict[str, nx.DiGraph]:
        """
        Extract Control Flow Graphs for all functions in the contracts.
        :param slither_instance: Initialized Slither instance
        :return: Dictionary of function names to their CFG graphs.
        """
        cfg_graphs = {}
        for contract in slither_instance.contracts:
            for function in contract.functions_declared:
                func_name = f'{contract.name}.{function.full_name}'
                graph = nx.DiGraph()

                # Build CFG nodes and edges
                for node in function.nodes:
                    graph.add_node(node.node_id, statement=str(node.expression), lineno=node.source_mapping.lineno if node.source_mapping else None)

                for node in function.nodes:
                    for son in node.sons:
                        graph.add_edge(node.node_id, son.node_id)

                cfg_graphs[func_name] = graph

        return cfg_graphs

    @staticmethod
    def run_slither_detectors(slither_instance) -> List[Dict[str, Any]]:
        """
        Run Slither detectors and collect issues as list of dicts.
        :param slither_instance: Initialized Slither instance
        :return: List of issue dictionaries
        """
        issues = []
        try:
            for detector in slither_instance.detectors:
                try:
                    detector_issues = detector.detect()
                    for issue in detector_issues:
                        issues.append({
                            'title': issue.title if hasattr(issue, 'title') else 'Unknown',
                            'description': issue.description if hasattr(issue, 'description') else '',
                            'impact': detector.IMPACT.name if hasattr(detector, 'IMPACT') else 'LOW',
                            'confidence': detector.CONFIDENCE.name if hasattr(detector, 'CONFIDENCE') else 'MEDIUM',
                            'lines': issue.slithir_to_human() if hasattr(issue, 'slithir_to_human') else []  # Adjust as needed
                        })
                except Exception as e:
                    logger.error(f"Error running detector {detector.__class__.__name__}: {e}")
                    continue
        except Exception as e:
            logger.error(f'Error accessing detectors: {e}')
        return issues

    def perform_basic_taint_analysis(self, slither_instance) -> Dict[str, List[Dict[str, Any]]]:
        """
        Perform basic taint analysis to track data flows from user inputs to sensitive operations.
        :param slither_instance: Initialized Slither instance
        :return: Dictionary of function names to list of tainted operations.
        """
        taint_results = {}

        for contract in slither_instance.contracts:
            for function in contract.functions_declared:
                func_name = f'{contract.name}.{function.full_name}'
                tainted_vars = set()
                tainted_operations = []

                # Simple taint propagation: track user inputs
                for node in function.nodes:
                    expr_str = str(node.expression) if node.expression else ''
                    if 'msg.sender' in expr_str or 'msg.value' in expr_str:
                        tainted_vars.add(expr_str)

                    # Propagate through assignments
                    if '=' in expr_str and any(var in expr_str for var in tainted_vars):
                        left_side = expr_str.split('=')[0].strip()
                        tainted_vars.add(left_side)

                    # Detect taint to sensitive ops
                    if isinstance(node.expression, (LibraryCall, InternalCall)):
                        expr_str = str(node.expression)
                        sensitive_keywords = ['transfer', 'send', 'call', 'delegatecall']
                        if any(kw in expr_str for kw in sensitive_keywords) and any(var in expr_str for var in tainted_vars):
                            tainted_operations.append({
                                'node_id': node.node_id,
                                'operation': expr_str,
                                'tainted_from': list(tainted_vars)
                            })

                taint_results[func_name] = tainted_operations

        return taint_results

    @staticmethod
    def get_contract_features(slither_instance) -> Dict[str, Any]:
        """
        Extract basic contract features for further analysis.
        :param slither_instance: Initialized Slither instance
        :return: Dictionary of contract-level features.
        """
        total_contracts = len(slither_instance.contracts)
        total_functions = sum(len(c.functions_declared) for c in slither_instance.contracts)
        features = {
            'total_contracts': total_contracts,
            'total_functions': total_functions,
            'contract_names': [c.name for c in slither_instance.contracts]
        }
        return features

    # Legacy run_detectors method kept for compatibility
    def run_detectors(self, slither_instance, detector_names: List[str] = None) -> Dict[str, Any]:
        """
        Run Slither detectors and return results.
        :param slither_instance: Initialized Slither instance
        :param detector_names: Optional list of specific detector names to run.
        :return: Slither analysis results.
        """
        try:
            analysis = slither_instance.register_analysis()
            if detector_names:
                for det in detector_names:
                    analysis.register_detector(det)
            else:
                # Run all detectors
                pass
            analysis.run()
            return analysis.get_results()
        except Exception as e:
            logger.error(f'Error running Slither detectors: {e}')
            return {'error': str(e)}

# Utility function for quick Slither initialization