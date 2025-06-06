#!/usr/bin/env python3

from abc import ABC, abstractmethod
from typing import List, Any

class Source(ABC):
    """Base class for all enumeration sources"""
    
    @abstractmethod
    async def get(self, target: str) -> List[Any]:
        """
        Abstract method to retrieve data from the source
        
        Args:
            target: The target to search for (domain, IP, etc.)
            
        Returns:
            List of results from the source
        """
        pass
    
    def get_name(self) -> str:
        """Get the name of this source"""
        return self.__class__.__name__
    
    def get_description(self) -> str:
        """Get description of this source"""
        return f"Data source: {self.get_name()}" 