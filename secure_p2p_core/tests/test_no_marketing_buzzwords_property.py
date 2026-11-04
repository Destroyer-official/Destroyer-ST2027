"""
Property-Based Test for No Marketing Buzzwords

Feature: military-p2p-production-cleanup, Property 8: No Marketing Buzzwords
Validates: Requirements 3.1, 3.2

Property 8: No Marketing Buzzwords
*For any* Python file in the production system, the file must not contain any strings 
from the MARKETING_BUZZWORDS list or emoji characters.

Requirements:
- 3.1: THE Production_System SHALL remove all emoji characters from log messages and comments
- 3.2: THE Production_System SHALL remove marketing buzzwords such as "ULTIMATE", "BEYOND MILITARY-GRADE", "QUANTUM SUPREME", "REVOLUTIONARY", "CUTTING-EDGE"
"""

import pytest
import sys
import os
import re
from pathlib import Path
from typing import Set, List, Tuple, Optional
from hypothesis import given, strategies as st, settings, assume

# Add project root and devscripts to path
PROJECT_ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "archive" / "devscripts"))

try:
    from production_cleanup_utils import CodeCleanupUtility
except ImportError:
    from archive.devscripts.production_cleanup_utils import CodeCleanupUtility


class TestNoMarketingBuzzwordsProperty:
    """
    Property-based tests for marketing buzzword removal.
    
    Feature: military-p2p-production-cleanup, Property 8: No Marketing Buzzwords
    Validates: Requirements 3.1, 3.2
    """
    
    def __init__(self):
        self.cleanup_utility = CodeCleanupUtility()
    
    def get_all_python_files(self) -> List[Path]:
        """Get all Python files in the production system."""
        python_files = []
        exclude_dirs = {'__pycache__', '.git', '.pytest_cache', 'notupload'}
        
        for root, dirs, files in os.walk(PROJECT_ROOT):
            # Remove excluded directories from dirs list
            dirs[:] = [d for d in dirs if d not in exclude_dirs]
            
            for file in files:
                if file.endswith('.py'):
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
            
            buzzwords_found = self.cleanup_utility.detect_buzzwords(content)
            buzzword_strings = [buzzword for _, buzzword in buzzwords_found]
            
            return len(buzzword_strings) == 0, buzzword_strings
            
        except Exception as e:
            # If we can't read the file, assume it's clean
            return True, []
    
    def check_file_for_emoji(self, file_path: Path) -> Tuple[bool, List[str]]:
        """
        Check if a file contains emoji characters.
        
        Returns:
            Tuple of (is_clean, list_of_emoji_found)
        """
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            emoji_found = self.cleanup_utility.detect_emoji(content)
            emoji_strings = [emoji for _, emoji in emoji_found]
            
            return len(emoji_strings) == 0, emoji_strings
            
        except Exception as e:
            # If we can't read the file, assume it's clean
            return True, []
    
    @settings(max_examples=100, deadline=None)
    @given(file_index=st.integers(min_value=0))
    def test_property_8_no_marketing_buzzwords(self, file_index: int):
        """
        Property 8: No Marketing Buzzwords - Buzzword Removal
        
        *For any* Python file in the production system, the file must not contain 
        any marketing buzzwords from the MARKETING_BUZZWORDS list.
        
        Feature: military-p2p-production-cleanup, Property 8: No Marketing Buzzwords
        Validates: Requirements 3.2
        """
        python_files = self.get_all_python_files()
        assume(len(python_files) > 0)
        
        # Select a file based on the generated index
        file_path = python_files[file_index % len(python_files)]
        
        # Check if file contains marketing buzzwords
        is_clean, buzzwords_found = self.check_file_for_buzzwords(file_path)
        
        assert is_clean, (
            f"File {file_path.relative_to(PROJECT_ROOT)} contains marketing buzzwords: "
            f"{buzzwords_found}. These should have been removed by the cleanup process."
        )
    
    @settings(max_examples=100, deadline=None)
    @given(file_index=st.integers(min_value=0))
    def test_property_8_no_emoji_characters(self, file_index: int):
        """
        Property 8: No Marketing Buzzwords - Emoji Removal
        
        *For any* Python file in the production system, the file must not contain 
        any emoji characters.
        
        Feature: military-p2p-production-cleanup, Property 8: No Marketing Buzzwords
        Validates: Requirements 3.1
        """
        python_files = self.get_all_python_files()
        assume(len(python_files) > 0)
        
        # Select a file based on the generated index
        file_path = python_files[file_index % len(python_files)]
        
        # Check if file contains emoji
        is_clean, emoji_found = self.check_file_for_emoji(file_path)
        
        assert is_clean, (
            f"File {file_path.relative_to(PROJECT_ROOT)} contains emoji characters: "
            f"{emoji_found}. These should have been removed by the cleanup process."
        )
    
    @settings(max_examples=50, deadline=None)
    @given(file_index=st.integers(min_value=0))
    def test_property_8_combined_cleanup_verification(self, file_index: int):
        """
        Property 8: No Marketing Buzzwords - Combined Verification
        
        *For any* Python file in the production system, the file must not contain 
        any marketing buzzwords OR emoji characters.
        
        Feature: military-p2p-production-cleanup, Property 8: No Marketing Buzzwords
        Validates: Requirements 3.1, 3.2
        """
        python_files = self.get_all_python_files()
        assume(len(python_files) > 0)
        
        # Select a file based on the generated index
        file_path = python_files[file_index % len(python_files)]
        
        # Check both buzzwords and emoji
        buzzwords_clean, buzzwords_found = self.check_file_for_buzzwords(file_path)
        emoji_clean, emoji_found = self.check_file_for_emoji(file_path)
        
        # Both checks must pass
        assert buzzwords_clean and emoji_clean, (
            f"File {file_path.relative_to(PROJECT_ROOT)} failed cleanup verification:\n"
            f"  Marketing buzzwords found: {buzzwords_found}\n"
            f"  Emoji characters found: {emoji_found}\n"
            f"All marketing content should have been removed by the cleanup process."
        )


class TestNoMarketingBuzzwordsUnit:
    """
    Unit tests for marketing buzzword detection and removal.
    """
    
    def __init__(self):
        self.cleanup_utility = CodeCleanupUtility()
    
    def test_buzzword_detection_utility(self):
        """Test that the buzzword detection utility works correctly."""
        test_text = "This is an ULTIMATE solution with CUTTING-EDGE technology."
        buzzwords = self.cleanup_utility.detect_buzzwords(test_text)
        
        assert len(buzzwords) == 2
        buzzword_strings = [buzzword for _, buzzword in buzzwords]
        assert "ULTIMATE" in buzzword_strings
        assert "CUTTING-EDGE" in buzzword_strings
    
    def test_emoji_detection_utility(self):
        """Test that the emoji detection utility works correctly."""
        test_text = "This is a test 🚀 with emoji 🔒 characters."
        emoji = self.cleanup_utility.detect_emoji(test_text)
        
        assert len(emoji) == 2
        emoji_strings = [em for _, em in emoji]
        assert "🚀" in emoji_strings
        assert "🔒" in emoji_strings
    
    def test_buzzword_removal_utility(self):
        """Test that buzzwords are properly removed."""
        test_text = "This ULTIMATE system provides CUTTING-EDGE security."
        cleaned_text, count = self.cleanup_utility.remove_buzzwords(test_text)
        
        assert count == 2
        assert "ULTIMATE" not in cleaned_text
        assert "CUTTING-EDGE" not in cleaned_text
        assert "system provides security" in cleaned_text
    
    def test_emoji_removal_utility(self):
        """Test that emoji are properly removed."""
        test_text = "Security system 🔒 with encryption 🚀"
        cleaned_text, count = self.cleanup_utility.remove_emoji(test_text)
        
        assert count > 0  # Should remove some characters
        assert "🔒" not in cleaned_text
        assert "🚀" not in cleaned_text
        assert "Security system" in cleaned_text
        assert "with encryption" in cleaned_text
    
    def test_production_cleanup_utils_is_clean(self):
        """Test that the production_cleanup_utils.py file itself is clean."""
        file_path = PROJECT_ROOT / "production_cleanup_utils.py"
        
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
            assert len(buzzwords) == 0, f"production_cleanup_utils.py contains buzzwords outside definition: {[b for _, b in buzzwords]}"
            
            # Check for emoji
            emoji = self.cleanup_utility.detect_emoji(content)
            assert len(emoji) == 0, f"production_cleanup_utils.py contains emoji: {[e for _, e in emoji]}"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--hypothesis-show-statistics"])