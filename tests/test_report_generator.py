"""
Test suite for Consolidated Report Generator
"""

import os
import json
import tempfile
import unittest
import pandas as pd
from datetime import datetime
from pathlib import Path

from reporting.consolidated_report_generator import (
    ConsolidatedReportGenerator,
    create_report_generator,
    load_data_from_file,
    save_data_to_file
)


class TestConsolidatedReportGenerator(unittest.TestCase):
    """Test cases for ConsolidatedReportGenerator"""
    
    def setUp(self):
        """Set up test environment"""
        self.test_dir = tempfile.mkdtemp()
        self.generator = ConsolidatedReportGenerator(self.test_dir)
        
        # Sample test data
        self.sample_dict = {
            "name": "Test Report",
            "value": 42,
            "items": ["item1", "item2", "item3"],
            "metadata": {"created": "2024-01-01", "version": "1.0"}
        }
        
        self.sample_list = [
            {"id": 1, "name": "Item 1", "value": 100},
            {"id": 2, "name": "Item 2", "value": 200},
            {"id": 3, "name": "Item 3", "value": 300}
        ]
        
        self.sample_dataframe = pd.DataFrame({
            'Column1': [1, 2, 3],
            'Column2': ['A', 'B', 'C'],
            'Column3': [10.5, 20.3, 30.1]
        })
    
    def tearDown(self):
        """Clean up test files"""
        import shutil
        shutil.rmtree(self.test_dir)
    
    def test_initialization(self):
        """Test generator initialization"""
        self.assertEqual(self.generator.output_dir, self.test_dir)
        self.assertEqual(self.generator.reports_generated, 0)
        
        # Test with custom directory
        custom_dir = os.path.join(self.test_dir, "custom")
        custom_generator = ConsolidatedReportGenerator(custom_dir)
        self.assertEqual(custom_generator.output_dir, custom_dir)
    
    def test_generate_json_report(self):
        """Test JSON report generation"""
        filepath = self.generator.generate_report(self.sample_dict, "json")
        
        # Verify file exists
        self.assertTrue(os.path.exists(filepath))
        
        # Verify file content
        with open(filepath, 'r') as f:
            data = json.load(f)
        
        self.assertEqual(data, self.sample_dict)
        self.assertEqual(self.generator.reports_generated, 1)
    
    def test_generate_csv_report(self):
        """Test CSV report generation"""
        # Test with list data
        filepath = self.generator.generate_report(self.sample_list, "csv")
        self.assertTrue(os.path.exists(filepath))
        
        # Test with DataFrame
        df_filepath = self.generator.generate_report(self.sample_dataframe, "csv")
        self.assertTrue(os.path.exists(df_filepath))
        
        # Verify CSV content can be read back
        df = pd.read_csv(filepath)
        self.assertEqual(len(df), len(self.sample_list))
    
    def test_generate_excel_report(self):
        """Test Excel report generation"""
        filepath = self.generator.generate_report(self.sample_list, "excel")
        self.assertTrue(os.path.exists(filepath))
        
        # Verify Excel file can be read
        df = pd.read_excel(filepath)
        self.assertEqual(len(df), len(self.sample_list))
    
    def test_generate_text_report(self):
        """Test text report generation"""
        filepath = self.generator.generate_report(self.sample_dict, "txt")
        self.assertTrue(os.path.exists(filepath))
        
        # Verify text content
        with open(filepath, 'r') as f:
            content = f.read()
        
        self.assertIn("name: Test Report", content)
        self.assertIn("value: 42", content)
    
    def test_custom_filename(self):
        """Test report generation with custom filename"""
        custom_name = "custom_report.json"
        filepath = self.generator.generate_report(
            self.sample_dict, "json", custom_name
        )
        
        self.assertTrue(filepath.endswith(custom_name))
        self.assertTrue(os.path.exists(filepath))
    
    def test_generate_summary_report(self):
        """Test summary report generation"""
        reports_data = [
            {"report_id": 1, "status": "success", "items_processed": 100},
            {"report_id": 2, "status": "success", "items_processed": 200},
            {"report_id": 3, "status": "failed", "items_processed": 0}
        ]
        
        filepath = self.generator.generate_summary_report(reports_data)
        self.assertTrue(os.path.exists(filepath))
        
        # Verify summary content
        with open(filepath, 'r') as f:
            summary = json.load(f)
        
        self.assertEqual(summary["total_reports"], len(reports_data))
        self.assertEqual(summary["reports"], reports_data)
    
    def test_batch_generate_reports(self):
        """Test batch report generation"""
        data_list = [self.sample_dict, self.sample_list, self.sample_dataframe]
        report_types = ["json", "csv", "excel"]
        
        generated_files = self.generator.batch_generate_reports(data_list, report_types)
        
        self.assertEqual(len(generated_files), len(data_list))
        
        for filepath in generated_files:
            self.assertTrue(os.path.exists(filepath))
        
        self.assertEqual(self.generator.reports_generated, len(data_list))
    
    def test_get_stats(self):
        """Test statistics retrieval"""
        # Generate some reports first
        self.generator.generate_report(self.sample_dict, "json")
        self.generator.generate_report(self.sample_list, "csv")
        
        stats = self.generator.get_stats()
        
        self.assertEqual(stats["reports_generated"], 2)
        self.assertEqual(stats["output_directory"], self.test_dir)
        self.assertIn("last_updated", stats)
    
    def test_factory_function(self):
        """Test factory function"""
        generator = create_report_generator(self.test_dir)
        self.assertIsInstance(generator, ConsolidatedReportGenerator)
        self.assertEqual(generator.output_dir, self.test_dir)
    
    def test_utility_functions(self):
        """Test utility functions"""
        test_file = os.path.join(self.test_dir, "test_utility.json")
        
        # Test save and load
        save_data_to_file(self.sample_dict, test_file)
        loaded_data = load_data_from_file(test_file)
        
        self.assertEqual(loaded_data, self.sample_dict)
        self.assertTrue(os.path.exists(test_file))
    
    def test_error_handling(self):
        """Test error handling for unsupported report types"""
        with self.assertRaises(ValueError):
            self.generator.generate_report(self.sample_dict, "unsupported_type")
    
    def test_batch_mismatch_error(self):
        """Test error handling for mismatched batch data"""
        with self.assertRaises(ValueError):
            self.generator.batch_generate_reports(
                [self.sample_dict, self.sample_list], 
                ["json"]  # Only one report type for two data items
            )


class TestEdgeCases(unittest.TestCase):
    """Test edge cases and special scenarios"""
    
    def setUp(self):
        """Set up test environment"""
        self.test_dir = tempfile.mkdtemp()
        self.generator = ConsolidatedReportGenerator(self.test_dir)
    
    def tearDown(self):
        """Clean up test files"""
        import shutil
        shutil.rmtree(self.test_dir)
    
    def test_empty_data(self):
        """Test report generation with empty data"""
        empty_dict = {}
        empty_list = []
        
        # Test empty dictionary
        filepath1 = self.generator.generate_report(empty_dict, "json")
        with open(filepath1, 'r') as f:
            data = json.load(f)
        self.assertEqual(data, empty_dict)
        
        # Test empty list
        filepath2 = self.generator.generate_report(empty_list, "csv")
        self.assertTrue(os.path.exists(filepath2))
    
    def test_large_data(self):
        """Test report generation with large data"""
        large_data = {"items": [{"id": i, "value": i * 10} for i in range(1000)]}
        
        filepath = self.generator.generate_report(large_data, "json")
        self.assertTrue(os.path.exists(filepath))
        
        with open(filepath, 'r') as f:
            data = json.load(f)
        
        self.assertEqual(len(data["items"]), 1000)
    
    def test_special_characters(self):
        """Test report generation with special characters"""
        special_data = {
            "name": "Test with special chars: äöüß",
            "unicode": "中文测试",
            "symbols": "!@#$%^&*()_+-=[]{};':\",.<>/?"
        }
        
        filepath = self.generator.generate_report(special_data, "json")
        self.assertTrue(os.path.exists(filepath))
        
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        self.assertEqual(data, special_data)


if __name__ == "__main__":
    unittest.main()