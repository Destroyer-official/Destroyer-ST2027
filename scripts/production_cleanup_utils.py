#!/usr/bin/env python3
"""
Production Cleanup Utilities

Utilities for detecting and removing marketing buzzwords and emoji characters
from production code as part of the military production cleanup process.

Feature: military-production-cleanup
Validates: Requirements R4.4
"""

import re
from typing import List, Tuple, Set

# Marketing buzzwords that should be removed from production code
# These match exactly the buzzwords specified in Requirements R4.4
MARKETING_BUZZWORDS = [
    'ULTIMATE',
    'BEYOND MILITARY-GRADE', 
    'QUANTUM SUPREME',
    'REVOLUTIONARY',
    'CUTTING-EDGE',
    'GAME-CHANGING',
    'WORLD-CLASS'
]

# Emoji Unicode ranges
EMOJI_PATTERNS = [
    r'[\U0001F600-\U0001F64F]',  # Emoticons
    r'[\U0001F300-\U0001F5FF]',  # Misc Symbols and Pictographs
    r'[\U0001F680-\U0001F6FF]',  # Transport and Map Symbols
    r'[\U0001F900-\U0001F9FF]',  # Supplemental Symbols and Pictographs (e.g. handshake)
    r'[\U0001F100-\U0001F251]',  # Enclosed Ideographic / Alphanumeric Supplement (e.g. ID, NEW)
    r'[\U0001F1E0-\U0001F1FF]',  # Flags (iOS)
    r'[\U00002600-\U000026FF]',  # Misc symbols
    r'[\U00002700-\U000027BF]',  # Dingbats
]

class CodeCleanupUtility:
    """Utility class for detecting and removing marketing content from code."""
    
    def __init__(self):
        self.buzzword_pattern = self._compile_buzzword_pattern()
        self.emoji_pattern = self._compile_emoji_pattern()
    
    def _compile_buzzword_pattern(self) -> re.Pattern:
        """Compile regex pattern for detecting marketing buzzwords."""
        # Create case-insensitive pattern for all buzzwords
        escaped_buzzwords = [re.escape(word) for word in MARKETING_BUZZWORDS]
        pattern = r'\b(?:' + '|'.join(escaped_buzzwords) + r')\b'
        return re.compile(pattern, re.IGNORECASE)
    
    def _compile_emoji_pattern(self) -> re.Pattern:
        """Compile regex pattern for detecting emoji characters."""
        # Detect full Unicode ranges plus supplemental military/UI symbols
        extra_chars = [
            '\u2713', '\u2717', '\u26a0', '\U0001f6a8', '\U0001f53a', '\U0001f6d1', '\U0001f50d', 
            '\u2705', '\u274c', '\u26a0\ufe0f', '\U0001f510', '\U0001f4e1', '\U0001f512',
            '\u2753', '\u2139', '\u23f3', '\u2714', '\u270d'
        ]
        escaped_extra = [re.escape(char) for char in extra_chars]
        all_patterns = EMOJI_PATTERNS + escaped_extra
        pattern = '|'.join(all_patterns)
        return re.compile(pattern)
    
    def detect_buzzwords(self, text: str) -> List[Tuple[int, str]]:
        """
        Detect marketing buzzwords in text.
        
        Args:
            text: Text to analyze
            
        Returns:
            List of (position, buzzword) tuples
        """
        matches = []
        for match in self.buzzword_pattern.finditer(text):
            matches.append((match.start(), match.group()))
        return matches
    
    def detect_emoji(self, text: str) -> List[Tuple[int, str]]:
        """
        Detect emoji characters in text.
        
        Args:
            text: Text to analyze
            
        Returns:
            List of (position, emoji) tuples
        """
        matches = []
        for match in self.emoji_pattern.finditer(text):
            matches.append((match.start(), match.group()))
        return matches
    
    def remove_buzzwords(self, text: str) -> Tuple[str, int]:
        """
        Remove marketing buzzwords from text.
        
        Args:
            text: Text to clean
            
        Returns:
            Tuple of (cleaned_text, count_removed)
        """
        original_count = len(self.buzzword_pattern.findall(text))
        cleaned_text = self.buzzword_pattern.sub('', text)
        
        # Clean up extra whitespace
        cleaned_text = re.sub(r'\s+', ' ', cleaned_text).strip()
        
        return cleaned_text, original_count
    
    def remove_emoji(self, text: str) -> Tuple[str, int]:
        """
        Remove emoji characters from text.
        
        Args:
            text: Text to clean
            
        Returns:
            Tuple of (cleaned_text, count_removed)
        """
        original_length = len(text)
        cleaned_text = self.emoji_pattern.sub('', text)
        count_removed = original_length - len(cleaned_text)
        
        return cleaned_text, count_removed
    
    def is_text_clean(self, text: str) -> Tuple[bool, List[str], List[str]]:
        """
        Check if text is clean of both buzzwords and emoji.
        
        Args:
            text: Text to check
            
        Returns:
            Tuple of (is_clean, buzzwords_found, emoji_found)
        """
        buzzwords = [buzzword for _, buzzword in self.detect_buzzwords(text)]
        emoji = [emoji for _, emoji in self.detect_emoji(text)]
        
        is_clean = len(buzzwords) == 0 and len(emoji) == 0
        
        return is_clean, buzzwords, emoji