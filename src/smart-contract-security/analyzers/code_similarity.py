import hashlib
from typing import Dict, List, Tuple
import re
from dataclasses import dataclass
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

@dataclass
class CodeSimilarityResult:
    similarity_score: float
    similar_functions: List[Tuple[str, str, float]]  # (func1, func2, score)

class CodeSimilarityAnalyzer:
    def __init__(self):
        self.vectorizer = TfidfVectorizer(analyzer='char_wb', ngram_range=(3, 5))
        self.known_contracts = {}
        
    def _normalize_code(self, code: str) -> str:
        """Normalize code by removing comments and extra whitespace"""
        # Remove single and multi-line comments
        code = re.sub(r'//.*?\n|/\*.*?\*/', '', code, flags=re.DOTALL)
        # Normalize whitespace
        code = ' '.join(code.split())
        return code
    
    def _get_function_hashes(self, code: str) -> List[str]:
        """Extract function signatures and create hashes"""
        # This is a simplified version - in production you'd use a proper Solidity parser
        functions = []
        pattern = r'function\s+([a-zA-Z0-9_]+)\s*\('
        matches = re.finditer(pattern, code)
        for match in matches:
            func_start = match.start()
            func_end = code.find('{', func_start)
            if func_end != -1:
                func_sig = code[func_start:func_end].strip()
                func_hash = hashlib.md5(func_sig.encode()).hexdigest()
                functions.append((func_sig, func_hash))
        return functions
    
    def calculate_similarity(self, code1: str, code2: str) -> CodeSimilarityResult:
        """Calculate similarity between two code snippets"""
        # Normalize code
        norm1 = self._normalize_code(code1)
        norm2 = self._normalize_code(code2)
        
        # Calculate text similarity
        tfidf_matrix = self.vectorizer.fit_transform([norm1, norm2])
        similarity = cosine_similarity(tfidf_matrix[0:1], tfidf_matrix[1:2])[0][0]
        
        # Get function-level similarities
        funcs1 = self._get_function_hashes(code1)
        funcs2 = self._get_function_hashes(code2)
        
        similar_funcs = []
        for sig1, hash1 in funcs1:
            for sig2, hash2 in funcs2:
                if hash1 == hash2:
                    similar_funcs.append((sig1, sig2, 1.0))
        
        return CodeSimilarityResult(
            similarity_score=similarity,
            similar_functions=similar_funcs
        )
    
    def compare_with_known_contracts(self, code: str, threshold: float = 0.7) -> Dict[str, float]:
        """Compare code with known contracts in the database"""
        results = {}
        for contract_name, contract_code in self.known_contracts.items():
            similarity = self.calculate_similarity(code, contract_code).similarity_score
            if similarity >= threshold:
                results[contract_name] = similarity
        return results
