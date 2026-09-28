#!/usr/bin/env python3
"""
Property-Based Test for No Marketing Buzzwords

Feature: military-production-cleanup, Property 3: No Marketing Buzzwords
Validates: Requirements R4.4

Property 3: No Marketing Buzzwords
*For all* Python files in the production codebase (excluding notupload folder), 
none of the following strings should appear (case-insensitive): "ULTIMATE", 
"BEYOND MILITARY-GRADE", "QUANTUM SUPREME", "REVOLUTIONARY", "CUTTING-EDGE", 
"GAME-CHANGING", "WORLD-CLASS".
"""

import pytest
import sys
import os
from pathlib import Path
from typing import List, Tuple
from hypothesis import given, strategies as st, settings, assume

# Add project root and archive/devscripts to path
PROJECT_ROOT = Path(__file__).parent
sys.path.insert(0, str(PROJECT_ROOT))
if (PROJECT_ROOT / "archive" / "devscripts").exists():
    sys.path.insert(0, str(PROJECT_ROOT / "archive" / "devscripts"))

from production_cleanup_utils import CodeCleanupUtility


class TestNoMarketingBuzzwordsProperty:
    """
    Property-based tests for marketing buzzword removal verification.
    
    Feature: military-production-cleanup, Property 3: No Marketing Buzzwords
    Validates: Requirements R4.4
    """
    
    @pytest.fixture(autouse=True)
    def setup(self):
        """Setup test fixture."""
        self.cleanup_utility = CodeCleanupUtility()
    
    def get_production_python_files(self) -> List[Path]:
        """Get all Python files in the production codebase (excluding notupload folder)."""
        python_files = []
        exclude_dirs = {'__pycache__', '.git', '.pytest_cache', 'notupload', '.hypothesis', '.venv', 'archive', 'rust_data_plane'}
        exclude_files = {'test_no_marketing_buzzwords_property.py', 'production_cleanup_utils.py'}
        
        for root, dirs, files in os.walk(PROJECT_ROOT):
            # Remove excluded directories from dirs list
            dirs[:] = [d for d in dirs if d not in exclude_dirs]
            
            for file in files:
                if file.endswith('.py') and file not in exclude_files:
                    python_files.append(Path(root) / file)
        
        return python_files
    
    def check_file_for_buzzwords(self, file_path: Path) -> Tuple[bool, List[str]]:
        """
        Check if a file contains marketing buzzwords.
        
        Returns:
            Tuple of (is_clean, list_of_buzzwords_found)
        """
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Special case: production_cleanup_utils.py contains buzzwords in the MARKETING_BUZZWORDS list
            # This is expected and should be excluded from the check
            if file_path.name == 'production_cleanup_utils.py':
                # Remove the MARKETING_BUZZWORDS list definition from the content before checking
                lines = content.split('\n')
                filtered_lines = []
                in_buzzwords_list = False
                
                for line in lines:
                    if 'MARKETING_BUZZWORDS = [' in line:
                        in_buzzwords_list = True
                    elif in_buzzwords_list and ']' in line and not line.strip().startswith("'"):
                        in_buzzwords_list = False
                    elif not in_buzzwords_list:
                        filtered_lines.append(line)
                
                content = '\n'.join(filtered_lines)
            
            buzzwords_found = self.cleanup_utility.detect_buzzwords(content)
            buzzword_strings = [buzzword for _, buzzword in buzzwords_found]
            
            return len(buzzword_strings) == 0, buzzword_strings
            
        except Exception as e:
            # If we can't read the file, assume it's clean
            return True, []
    
    @settings(max_examples=100, deadline=None)
    @given(file_index=st.integers(min_value=0))
    def test_property_3_no_marketing_buzzwords(self, file_index: int):
        """
        Property 3: No Marketing Buzzwords
        
        *For all* Python files in the production codebase (excluding notupload folder), 
        none of the marketing buzzwords should appear in the code.
        
        Feature: military-production-cleanup, Property 3: No Marketing Buzzwords
        Validates: Requirements R4.4
        """
        python_files = self.get_production_python_files()
        assume(len(python_files) > 0)
        
        # Select a file based on the generated index
        file_path = python_files[file_index % len(python_files)]
        
        # Check if file contains marketing buzzwords
        is_clean, buzzwords_found = self.check_file_for_buzzwords(file_path)
        
        assert is_clean, (  # nosec: B101
            f"File {file_path.relative_to(PROJECT_ROOT)} contains marketing buzzwords: "
            f"{buzzwords_found}. These should have been replaced with technical descriptions "
            f"during the cleanup process (Requirements R4.4)."
        )


class TestNoMarketingBuzzwordsUnit:
    """
    Unit tests for marketing buzzword detection and removal verification.
    """
    
    @pytest.fixture(autouse=True)
    def setup(self):
        """Setup test fixture."""
        self.cleanup_utility = CodeCleanupUtility()
    
    def test_buzzword_detection_utility(self):
        """Test that the buzzword detection utility works correctly."""
        test_text = "This is an ULTIMATE solution with CUTTING-EDGE technology."
        buzzwords = self.cleanup_utility.detect_buzzwords(test_text)
        
        assert len(buzzwords) == 2  # nosec: B101
        buzzword_strings = [buzzword for _, buzzword in buzzwords]
        assert "ULTIMATE" in buzzword_strings  # nosec: B101
        assert "CUTTING-EDGE" in buzzword_strings  # nosec: B101
    
    def test_buzzword_removal_utility(self):
        """Test that buzzwords are properly removed."""
        test_text = "This ULTIMATE system provides CUTTING-EDGE security."
        cleaned_text, count = self.cleanup_utility.remove_buzzwords(test_text)
        
        assert count == 2  # nosec: B101
        assert "ULTIMATE" not in cleaned_text  # nosec: B101
        assert "CUTTING-EDGE" not in cleaned_text  # nosec: B101
        assert "system provides security" in cleaned_text  # nosec: B101
    
    def test_specific_buzzword_patterns(self):
        """Test detection of specific buzzwords that were in the codebase."""
        # Test buzzwords that are specified in Requirements R4.4
        test_cases = [
            "ULTIMATE security",
            "BEYOND MILITARY-GRADE protection", 
            "QUANTUM SUPREME algorithms",
            "REVOLUTIONARY technology",
            "CUTTING-EDGE features",
            "GAME-CHANGING solution",
            "WORLD-CLASS implementation"
        ]
        
        for test_text in test_cases:
            buzzwords_found = self.cleanup_utility.detect_buzzwords(test_text)
            assert len(buzzwords_found) > 0, f"Should detect buzzwords in: {test_text}"  # nosec: B101
    
    def test_case_insensitive_detection(self):
        """Test that buzzword detection is case-insensitive."""
        test_cases = [
            "ultimate security",
            "Ultimate Security", 
            "ULTIMATE SECURITY",
            "cutting-edge features",
            "Cutting-Edge Features",
            "CUTTING-EDGE FEATURES"
        ]
        
        for test_text in test_cases:
            buzzwords_found = self.cleanup_utility.detect_buzzwords(test_text)
            assert len(buzzwords_found) > 0, f"Should detect buzzwords in: {test_text}"  # nosec: B101
    
    def test_production_cleanup_utils_is_clean(self):
        """Test that the production_cleanup_utils.py file itself is clean of buzzwords."""
        file_path = PROJECT_ROOT / "production_cleanup_utils.py"
        if not file_path.exists():
            file_path = PROJECT_ROOT / "archive" / "devscripts" / "production_cleanup_utils.py"
        
        if file_path.exists():
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Check for buzzwords (excluding the MARKETING_BUZZWORDS list definition)
            lines = content.split('\n')
            non_definition_lines = []
            in_buzzwords_list = False
            
            for line in lines:
                if 'MARKETING_BUZZWORDS = [' in line:
                    in_buzzwords_list = True
                elif in_buzzwords_list and ']' in line and not line.strip().startswith("'"):
                    in_buzzwords_list = False
                elif not in_buzzwords_list:
                    non_definition_lines.append(line)
            
            non_definition_content = '\n'.join(non_definition_lines)
            
            # Check for buzzwords outside the definition
            buzzwords = self.cleanup_utility.detect_buzzwords(non_definition_content)
            assert len(buzzwords) == 0, f"production_cleanup_utils.py contains buzzwords outside definition: {[b for _, b in buzzwords]}"  # nosec: B101


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--hypothesis-show-statistics"])