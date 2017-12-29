"""
Settings for the postpone project

Imports settings from this module

Optionally loads local settings
"""
# pragma pylint: disable=wildcard-import,unused-import
from .settings import *


try:
    from .localsettings import *
except ImportError:
    pass
