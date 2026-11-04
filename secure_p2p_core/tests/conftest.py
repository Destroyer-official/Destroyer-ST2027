"""
Pytest configuration for secure_p2p_core tests

This configuration file sets up the test environment to prevent
background threads and external dependencies from interfering with tests.
"""

import sys
import pytest
from unittest.mock import MagicMock, patch


# Mock problematic modules that start background threads
MOCK_MODULES = [
    'Neon_PostgreSQL',
    'Neon_PostgreSQL.core',
    'Neon_PostgreSQL.core.sync_functions',
    'Neon_PostgreSQL.core.api_client',
]


@pytest.fixture(scope='session', autouse=True)
def mock_external_modules():
    """Mock external modules that cause issues during testing"""
    mocks = {}
    
    for module_name in MOCK_MODULES:
        mock_module = MagicMock()
        mocks[module_name] = mock_module
        sys.modules[module_name] = mock_module
    
    # Mock the create_or_register_user function specifically
    if 'Neon_PostgreSQL.core' in sys.modules:
        sys.modules['Neon_PostgreSQL.core'].create_or_register_user = MagicMock(
            return_value={
                'user_id': 'test_user_id',
                'display_name': 'test_user',
                'public_ip': '127.0.0.1',
                'port': 8000
            }
        )
    
    yield mocks
    
    # Cleanup
    for module_name in MOCK_MODULES:
        if module_name in sys.modules:
            del sys.modules[module_name]


@pytest.fixture(scope='session', autouse=True)
def disable_background_threads():
    """Disable background threads that interfere with tests"""
    # This will be applied at session scope to prevent thread issues
    yield


@pytest.fixture(autouse=True)
def reset_singletons():
    """Reset any singleton instances between tests"""
    yield
    # Add cleanup code here if needed


@pytest.fixture
def temp_profile_dir(tmp_path):
    """Temporary directory fixture for profile testing."""
    return str(tmp_path)


# Configure pytest to not capture output for better debugging
def pytest_configure(config):
    """Configure pytest settings"""
    config.option.capture = 'no'  # Don't capture output
    config.option.verbose = 2  # Verbose output


def pytest_pyfunc_call(pyfuncitem):
    """Support async test execution without requiring pytest-asyncio plugin."""
    import inspect
    import asyncio
    if inspect.iscoroutinefunction(pyfuncitem.obj):
        testargs = {arg: pyfuncitem.funcargs[arg] for arg in pyfuncitem._fixtureinfo.argnames}
        asyncio.run(pyfuncitem.obj(**testargs))
        return True

