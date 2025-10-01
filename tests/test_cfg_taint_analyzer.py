"""Pytest unit tests for CFGTAintAnalyzer with mocks for Slither integration."""

import pytest
import networkx as nx
from unittest.mock import MagicMock, patch
from pathlib import Path
import json
from zauriscore.analyzers.cfg_taint_analyzer import CFGTAintAnalyzer
from zauriscore.analyzers.slither_utils import SlitherUtils


class TestCFGTAintAnalyzer:
    @pytest.fixture
    def mock_slither(self):
        slither_mock = MagicMock()
        # Mock analysis result with sample detectors
        slither_mock.analysis = MagicMock()
        slither_mock.context = MagicMock()
        return slither_mock

    @pytest.fixture
    def analyzer(self, mock_slither):
        with patch('zauriscore.analyzers.slither_utils.SlitherUtils.init_slither', return_value=mock_slither):
            return CFGTAintAnalyzer('mock.sol', contract_path='dummy_contract_path.sol')

    def test_init_analyzer(self, analyzer):
        assert analyzer.slither is not None
        assert isinstance(analyzer, CFGTAintAnalyzer)

    @patch.object(SlitherUtils, 'extract_cfg')
    def test_extract_cfg(self, mock_extract_cfg, analyzer):
        # Setup mock graph using networkx
        mock_graph1 = MagicMock(spec=nx.DiGraph)
        mock_graph1.nodes.return_value = ['node1', 'node2']
        mock_graph1.edges.return_value = [('node1', 'node2')]
        mock_graph1.number_of_nodes.return_value = 2
        mock_graph1.number_of_edges.return_value = 1
        
        mock_extract_cfg.return_value = {
            'test_func': mock_graph1
        }
        
        result = analyzer.extract_cfg()
        
        assert isinstance(result, dict)
        assert 'test_func' in result
        assert isinstance(result['test_func'], nx.DiGraph)
        assert mock_extract_cfg.called_once()

    @patch.object(SlitherUtils, 'perform_basic_taint_analysis')
    def test_perform_taint_analysis(self, mock_taint_analysis, analyzer):
        mock_taint_analysis.return_value = {
            'test_func': [
                {'operation': 'transfer', 'tainted_from': 'msg.value', 'path': 'user_input -> transfer'}
            ]
        }
        
        taint_results = analyzer.perform_taint_analysis()
        
        assert isinstance(taint_results, dict)
        assert 'test_func' in taint_results
        assert isinstance(taint_results['test_func'], list)
        assert len(taint_results['test_func']) == 1
        assert mock_taint_analysis.called_once()

    def test_generate_features_for_ml(self, analyzer):
        mock_analysis = {
            'cfg': {'num_nodes': 5, 'num_edges': 4, 'longest_path': 3},
            'taint': {'taint_paths': 2, 'critical_taints': 1}
        }
        features = analyzer.generate_features_for_ml(mock_analysis)
        
        expected_keys = ['num_nodes', 'num_edges', 'longest_path', 'taint_ratio', 'critical_taints']
        for key in expected_keys:
            assert key in features
        assert 0 <= features['taint_ratio'] <= 1

    @patch.object(SlitherUtils, 'perform_basic_taint_analysis')
    @patch.object(SlitherUtils, 'extract_cfg')
    def test_analyze_contract(self, mock_extract_cfg, mock_taint_analysis, analyzer):
        analyzer.slither.contracts = [MagicMock()]
        
        mock_extract_cfg.return_value = {'functions': [{'nodes': [], 'edges': []}]}
        mock_taint_analysis.return_value = {'sources': [], 'sinks': []}
        
        source_code = 'contract Test { function test() {} }'
        contract_address = '0x123'
        result = analyzer.analyze_contract(contract_address, source_code)
        
        assert 'cfg_features' in result
        assert 'taint_analysis' in result
        assert 'ml_features' in result

    def test_save_analysis_results_handles_errors(self, analyzer):
        mock_data = {'error': 'test error'}
        with pytest.raises(ValueError):
            analyzer.save_analysis_results(mock_data, 'invalid_path')

    @patch.object(SlitherUtils, 'perform_basic_taint_analysis')
    @patch.object(SlitherUtils, 'extract_cfg')
    def test_full_workflow_integration(self, mock_extract_cfg, mock_taint_analysis, analyzer):
        analyzer.slither.get_relevant_detectors.return_value = []
        
        mock_extract_cfg.return_value = {'functions': []}
        mock_taint_analysis.return_value = {'sources': [], 'sinks': []}
        
        source_code = '// Sample Solidity'
        contract_address = '0xabc'
        result = analyzer.analyze_contract(contract_address, source_code)
        
        # Verify output structure
        assert isinstance(result, dict)
        assert 'vulnerability_score' in result

"""Run with: pytest tests/test_cfg_taint_analyzer.py -v --cov=src/zauriscore/analyzers/cfg_taint_analyzer --cov-report=html"""