"""
The nginx feature catalog.

Every setting the GUI offers is described here once.  Forms, help popups,
validation and the rendered config all read from this single definition, so
they cannot drift apart.

Each feature also records:

  module   the nginx module it needs.  Build flags are read with nginx -V and
           features whose module is missing are not offered.

  edition  oss or plus.  Plus-only features are never offered; the help text
           points to an open source alternative where one exists.
"""

from app.catalog.registry import (
    CATEGORIES,
    Feature,
    HelpText,
    all_features,
    features_for_context,
    features_in_category,
    get_feature,
    plus_only_features,
    validate_value,
)

__all__ = [
    "CATEGORIES",
    "Feature",
    "HelpText",
    "all_features",
    "features_for_context",
    "features_in_category",
    "get_feature",
    "plus_only_features",
    "validate_value",
]
