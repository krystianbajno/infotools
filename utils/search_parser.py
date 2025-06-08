#!/usr/bin/env python3

import re
from typing import List, Tuple, Union
from enum import Enum

class SearchOperator(Enum):
    AND = "AND"
    OR = "OR"
    SIMPLE = "SIMPLE"

class SearchQuery:
    """Represents a parsed search query with logical operators"""
    
    def __init__(self, search_term: str):
        self.original_term = search_term
        self.operator = SearchOperator.SIMPLE
        self.terms = []
        self._parse_search_term()
    
    def _parse_search_term(self):
        """Parse search term for logical operators"""
        # Check for mixed operators (not supported)
        if '|' in self.original_term and '&' in self.original_term:
            raise ValueError("Cannot mix AND (&) and OR (|) operators in the same query")
        
        # Parse OR operator (|)
        if '|' in self.original_term:
            self.operator = SearchOperator.OR
            self.terms = [term.strip() for term in self.original_term.split('|') if term.strip()]
        
        # Parse AND operator (&)
        elif '&' in self.original_term:
            self.operator = SearchOperator.AND
            self.terms = [term.strip() for term in self.original_term.split('&') if term.strip()]
        
        # Simple search (no operators)
        else:
            self.operator = SearchOperator.SIMPLE
            self.terms = [self.original_term.strip()]
    
    def is_simple(self) -> bool:
        """Check if this is a simple search (no logical operators)"""
        return self.operator == SearchOperator.SIMPLE
    
    def is_or(self) -> bool:
        """Check if this is an OR search"""
        return self.operator == SearchOperator.OR
    
    def is_and(self) -> bool:
        """Check if this is an AND search"""
        return self.operator == SearchOperator.AND
    
    def get_terms(self) -> List[str]:
        """Get list of search terms"""
        return self.terms
    
    def get_sql_like_pattern(self) -> str:
        """Generate SQL LIKE pattern for database searches"""
        if self.is_simple():
            return f"%{self.terms[0]}%"
        elif self.is_or():
            # For OR, we'll need to handle this differently in SQL
            return f"%{self.terms[0]}%"  # Return first term, caller should handle OR logic
        elif self.is_and():
            # For AND, we'll need to handle this differently in SQL  
            return f"%{self.terms[0]}%"  # Return first term, caller should handle AND logic
    
    def matches_text(self, text: str, case_sensitive: bool = False) -> bool:
        """Check if text matches this search query"""
        if not text:
            return False
        
        search_text = text if case_sensitive else text.lower()
        
        if self.is_simple():
            search_term = self.terms[0] if case_sensitive else self.terms[0].lower()
            return search_term in search_text
        
        elif self.is_or():
            # OR logic: any term matches
            for term in self.terms:
                search_term = term if case_sensitive else term.lower()
                if search_term in search_text:
                    return True
            return False
        
        elif self.is_and():
            # AND logic: all terms must match
            for term in self.terms:
                search_term = term if case_sensitive else term.lower()
                if search_term not in search_text:
                    return False
            return True
        
        return False
    
    def __str__(self) -> str:
        """String representation of the search query"""
        if self.is_simple():
            return f"'{self.terms[0]}'"
        elif self.is_or():
            return f"({' OR '.join(self.terms)})"
        elif self.is_and():
            return f"({' AND '.join(self.terms)})"
        return self.original_term

def parse_search_term(search_term: str) -> SearchQuery:
    """Parse a search term into a SearchQuery object"""
    return SearchQuery(search_term)

def filter_results_by_query(results: List[dict], query: SearchQuery, text_fields: List[str]) -> List[dict]:
    """
    Filter a list of results based on a search query
    
    Args:
        results: List of dictionaries containing search results
        query: SearchQuery object with the parsed search logic
        text_fields: List of field names to search in each result dict
        
    Returns:
        Filtered list of results matching the query
    """
    if query.is_simple():
        return results  # No additional filtering needed for simple queries
    
    filtered_results = []
    
    for result in results:
        # Combine all searchable text fields
        combined_text = ""
        for field in text_fields:
            if field in result and result[field]:
                combined_text += f" {result[field]}"
        
        # Check if this result matches the query
        if query.matches_text(combined_text):
            filtered_results.append(result)
    
    return filtered_results

def build_sql_where_clause(query: SearchQuery, column_names: List[str]) -> Tuple[str, List[str]]:
    """
    Build SQL WHERE clause for database queries
    
    Args:
        query: SearchQuery object
        column_names: List of column names to search in
        
    Returns:
        Tuple of (where_clause, parameters)
    """
    if query.is_simple():
        # Simple search across all columns
        conditions = []
        params = []
        for col in column_names:
            conditions.append(f"{col} LIKE ?")
            params.append(f"%{query.terms[0]}%")
        
        where_clause = f"({' OR '.join(conditions)})"
        return where_clause, params
    
    elif query.is_or():
        # OR search: any term in any column
        conditions = []
        params = []
        for term in query.terms:
            term_conditions = []
            for col in column_names:
                term_conditions.append(f"{col} LIKE ?")
                params.append(f"%{term}%")
            conditions.append(f"({' OR '.join(term_conditions)})")
        
        where_clause = f"({' OR '.join(conditions)})"
        return where_clause, params
    
    elif query.is_and():
        # AND search: all terms must appear (in any columns)
        conditions = []
        params = []
        for term in query.terms:
            term_conditions = []
            for col in column_names:
                term_conditions.append(f"{col} LIKE ?")
                params.append(f"%{term}%")
            conditions.append(f"({' OR '.join(term_conditions)})")
        
        where_clause = f"({' AND '.join(conditions)})"
        return where_clause, params
    
    return "1=1", []  # Fallback: return all results 