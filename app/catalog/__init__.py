"""
The nginx feature catalog.

Everything the GUI lets you turn on is described in here, once.  The forms, the
help popups, the input checking, and the config we write all read from the same
place.  That is on purpose.  The usual way these tools rot is that somebody adds
a checkbox and forgets to update the renderer, or updates the renderer and the
help text now describes something the box does not do.  Here there is nothing
to keep in sync, because there is only one copy.

Two things every feature carries that matter a lot:

  module   which nginx module it needs.  We read the actual build flags off the
           box with nginx -V, so if your nginx was not built with, say, the
           image filter module, that whole section just is not there.  You never
           get to save a config that will not load.

  edition  oss or plus.  Plenty of nice nginx features are only in the paid
           version.  Those are not offered at all, since these are not licensed
           servers.  Where there is a free way to get close, the help text says
           what it is instead of leaving you wondering.
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
