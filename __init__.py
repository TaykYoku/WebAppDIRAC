""" WebAppDIRAC
"""

from __future__ import print_function
from __future__ import absolute_import
from __future__ import division

__RCSID__ = "$Id$"

import os

# Define Version

majorVersion = 4
minorVersion = 2
<<<<<<< HEAD
patchLevel = 0
<<<<<<< HEAD
preVersion = 1
=======
preVersion = 5
>>>>>>> 2f932d2 (v4r2-pre5 notes and tags)
=======
patchLevel = 1
preVersion = 0
>>>>>>> eed55b1 (v4r2p1 tag, notes)

version = "v%sr%s" % (majorVersion, minorVersion)
buildVersion = "v%dr%d" % (majorVersion, minorVersion)
if patchLevel:
  version = "%sp%s" % (version, patchLevel)
  buildVersion = "%s build %s" % (buildVersion, patchLevel)
if preVersion:
  version = "%s-pre%s" % (version, preVersion)
  buildVersion = "%s pre %s" % (buildVersion, preVersion)

# Check of python version

rootPath = os.path.realpath(os.path.dirname(__file__))
