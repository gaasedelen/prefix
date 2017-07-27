import idaapi

#------------------------------------------------------------------------------
# Compatability File
#------------------------------------------------------------------------------
#
#    This file is used to reduce the number of compatibility checks made
#    throughout the plugin for varying versions of IDA.
#

# get the IDA version number
major, minor = map(int, idaapi.get_kernel_version().split("."))

#------------------------------------------------------------------------------
# IDA 7 API - COMPAT
#------------------------------------------------------------------------------
#
#    We use the 'using_ida7api' global throughout the code to determine if
#    the IDA 7 API is available, and should be used.
#

using_ida7api = (major > 6)

#------------------------------------------------------------------------------
# Pyside --> PyQt5 - COMPAT
#------------------------------------------------------------------------------
#
#    As of IDA 6.9, Hex-Rays has started using PyQt5 versus PySide on Qt4.
#

using_pyqt5 = using_ida7api or (major == 6 and minor >= 9)

#
# From Qt4 --> Qt5, the organization of some of the code / objects has
# changed. We use this file to shim/re-alias a few of these to reduce the
# number of compatibility checks / code churn in the code that consumes them.
#

if using_pyqt5:
    import PyQt5.QtGui as QtGui
    import PyQt5.QtCore as QtCore
    import PyQt5.QtWidgets as QtWidgets

else:
    import PySide.QtGui as QtGui
    import PySide.QtCore as QtCore
    QtWidgets = QtGui
    QtCore.pyqtSignal = QtCore.Signal
    QtCore.pyqtSlot = QtCore.Slot

