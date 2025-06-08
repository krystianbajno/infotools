#!/usr/bin/env python3

import os
import json
from pathlib import Path
from typing import Dict, Any, Set

class Config:
    """Configuration manager for infotools"""
    
    def __init__(self):
        self.config_file = Path(__file__).parent / 'config' / 'config.json'
        self.default_config = {
            'sources': {
                'malpedia': {'enabled': True},
                'otx': {'enabled': True},
                'rss': {'enabled': True},
                'threatfox': {'enabled': True},
                'shodan': {'enabled': True},
                'ipgeo': {'enabled': True},
                'crtsh': {'enabled': True},
        
            }
        }
        self._config = None
        
    def load_config(self) -> Dict[str, Any]:
        """Load configuration from file, create default if not exists"""
        if self._config is not None:
            return self._config
            
        try:
            if self.config_file.exists():
                with open(self.config_file, 'r') as f:
                    self._config = json.load(f)
                    # Ensure all sources exist in config with default enabled state
                    for source in self.default_config['sources']:
                        if source not in self._config.get('sources', {}):
                            if 'sources' not in self._config:
                                self._config['sources'] = {}
                            self._config['sources'][source] = {'enabled': True}
            else:
                self._config = self.default_config.copy()
                self.save_config()
        except Exception as e:
            print(f"Warning: Could not load config file: {e}")
            self._config = self.default_config.copy()
            
        return self._config
    
    def save_config(self):
        """Save current configuration to file"""
        try:
            with open(self.config_file, 'w') as f:
                json.dump(self._config, f, indent=2)
        except Exception as e:
            print(f"Warning: Could not save config file: {e}")
    
    def is_source_enabled(self, source_name: str) -> bool:
        """Check if a source is enabled in configuration"""
        config = self.load_config()
        return config.get('sources', {}).get(source_name, {}).get('enabled', True)
    
    def get_enabled_sources(self) -> Set[str]:
        """Get set of all enabled source names"""
        config = self.load_config()
        enabled = set()
        for source, settings in config.get('sources', {}).items():
            if settings.get('enabled', True):
                enabled.add(source)
        return enabled
    
    def enable_source(self, source_name: str):
        """Enable a source"""
        config = self.load_config()
        if 'sources' not in config:
            config['sources'] = {}
        if source_name not in config['sources']:
            config['sources'][source_name] = {}
        config['sources'][source_name]['enabled'] = True
        self.save_config()
    
    def disable_source(self, source_name: str):
        """Disable a source"""
        config = self.load_config()
        if 'sources' not in config:
            config['sources'] = {}
        if source_name not in config['sources']:
            config['sources'][source_name] = {}
        config['sources'][source_name]['enabled'] = False
        self.save_config()

# Global config instance
_config_instance = None

def get_config() -> Config:
    """Get the global configuration instance"""
    global _config_instance
    if _config_instance is None:
        _config_instance = Config()
    return _config_instance 