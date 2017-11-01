import os

import idc
import idaapi
import idautils

from prefix.shims import *

#------------------------------------------------------------------------------
# IDA Plugin
#------------------------------------------------------------------------------

VERSION = "v1.1.2"
AUTHORS = ['Andrew Marumoto', 'Markus Gaasedelen']

def PLUGIN_ENTRY():
    """
    Required plugin entry point for IDAPython Plugins.
    """
    return prefix_t()

class prefix_t(idaapi.plugin_t):
    """
    The IDA Plugin for Prefix.
    """

    flags = idaapi.PLUGIN_PROC | idaapi.PLUGIN_HIDE
    help = ""
    comment = "A plugin for easy function prefixing"
    wanted_name = "prefix"
    wanted_hotkey = ""

    #--------------------------------------------------------------------------
    # Plugin Overloads
    #--------------------------------------------------------------------------

    def init(self):
        """
        This is called by IDA when it is loading the plugin.
        """

        # initialize the menu actions our plugin will inject
        self._init_action_bulk()
        self._init_action_clear()
        self._init_action_recursive()

        # initialize plugin hooks
        self._init_hooks()

        # done
        idaapi.msg("%s %s initialized...\n" % (self.wanted_name, VERSION))
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        """
        This is called by IDA when this file is loaded as a script.
        """
        idaapi.msg("%s cannot be run as a script.\n" % self.wanted_name)

    def term(self):
        """
        This is called by IDA when it is unloading the plugin.
        """

        # unhook our plugin hooks
        self._hooks.unhook()

        # unregister our actions & free their resources
        self._del_action_bulk()
        self._del_action_clear()
        self._del_action_recursive()

        # done
        idaapi.msg("%s terminated...\n" % self.wanted_name)

    #--------------------------------------------------------------------------
    # Plugin Hooks
    #--------------------------------------------------------------------------

    def _init_hooks(self):
        """
        Install plugin hooks into IDA.
        """
        self._hooks = Hooks()
        self._hooks.ready_to_run = self._init_hexrays_hooks
        self._hooks.hook()

    def _init_hexrays_hooks(self):
        """
        Install Hex-Rrays hooks (when available).

        NOTE: This is called when the ui_ready_to_run event fires.
        """
        if idaapi.init_hexrays_plugin():
            idaapi.install_hexrays_callback(self._hooks.hxe_callback)

    #--------------------------------------------------------------------------
    # IDA Actions
    #--------------------------------------------------------------------------

    ACTION_BULK      = "prefix:bulk"
    ACTION_CLEAR     = "prefix:clear"
    ACTION_RECURSIVE = "prefix:recursive"

    def _init_action_bulk(self):
        """
        Register the bulk prefix action with IDA.
        """

        # load the icon for this action
        self._bulk_icon_id = idaapi.load_custom_icon(plugin_resource("bulk.png"))

        # describe the action
        action_desc = idaapi.action_desc_t(
            self.ACTION_BULK,                        # The action name.
            "Prefix selected functions",             # The action text.
            IDACtxEntry(bulk_prefix),                # The action handler.
            None,                                    # Optional: action shortcut
            "Assign a user prefix to the selected functions", # Optional: tooltip
            self._bulk_icon_id                       # Optional: the action icon
        )

        # register the action with IDA
        assert idaapi.register_action(action_desc), "Action registration failed"

    def _init_action_clear(self):
        """
        Register the clear prefix action with IDA.
        """

        # load the icon for this action
        self._clear_icon_id = idaapi.load_custom_icon(plugin_resource("clear.png"))

        # describe the action
        action_desc = idaapi.action_desc_t(
            self.ACTION_CLEAR,                       # The action name.
            "Clear prefixes",                        # The action text.
            IDACtxEntry(clear_prefix),               # The action handler.
            None,                                    # Optional: action shortcut
            "Clear user prefixes from the selected functions", # Optional: tooltip
            self._clear_icon_id                      # Optional: the action icon
        )

        # register the action with IDA
        assert idaapi.register_action(action_desc), "Action registration failed"

    def _init_action_recursive(self):
        """
        Register the recursive rename action with IDA.
        """

        # load the icon for this action
        self._recursive_icon_id = idaapi.load_custom_icon(plugin_resource("recursive.png"))

        # describe the action
        action_desc = idaapi.action_desc_t(
            self.ACTION_RECURSIVE,                   # The action name.
            "Recursive function prefix",             # The action text.
            IDACtxEntry(recursive_prefix_cursor),    # The action handler.
            None,                                    # Optional: action shortcut
            "Recursively prefix callees of this function", # Optional: tooltip
            self._recursive_icon_id                  # Optional: the action icon
        )

        # register the action with IDA
        assert idaapi.register_action(action_desc), "Action registration failed"

    def _del_action_bulk(self):
        """
        Delete the bulk prefix action from IDA.
        """
        idaapi.unregister_action(self.ACTION_BULK)
        idaapi.free_custom_icon(self._bulk_icon_id)
        self._bulk_icon_id = idaapi.BADADDR

    def _del_action_clear(self):
        """
        Delete the clear prefix action from IDA.
        """
        idaapi.unregister_action(self.ACTION_CLEAR)
        idaapi.free_custom_icon(self._clear_icon_id)
        self._clear_icon_id = idaapi.BADADDR

    def _del_action_recursive(self):
        """
        Delete the recursive rename action from IDA.
        """
        idaapi.unregister_action(self.ACTION_RECURSIVE)
        idaapi.free_custom_icon(self._recursive_icon_id)
        self._recursive_icon_id = idaapi.BADADDR

#------------------------------------------------------------------------------
# Plugin Hooks
#------------------------------------------------------------------------------

class Hooks(idaapi.UI_Hooks):

    def finish_populating_widget_popup(self, widget, popup):
        """
        A right click menu is about to be shown. (IDA 7)
        """
        inject_prefix_actions(widget, popup, idaapi.get_widget_type(widget))
        return 0

    def finish_populating_tform_popup(self, form, popup):
        """
        A right click menu is about to be shown. (IDA 6.x)
        """
        inject_prefix_actions(form, popup, idaapi.get_tform_type(form))
        return 0

    def hxe_callback(self, event, *args):
        """
        HexRays event callback.

        We lump this under the (UI) Hooks class for organizational reasons.
        """

        #
        # if the event callback indicates that this is a popup menu event
        # (in the hexrays window), we may want to install our prefix menu
        # actions depending on what the cursor right clicked.
        #

        if event == idaapi.hxe_populating_popup:
            form, popup, vu = args

            #
            # if the user cursor isn't hovering over a function ref, there
            # is nothing for us to do
            #

            if get_cursor_func_ref() == idaapi.BADADDR:
                return 0

            #
            # the user cursor is hovering over a valid target for a recursive
            # function prefix. insert the prefix action entry into the menu
            #

            idaapi.attach_action_to_popup(
                form,
                popup,
                prefix_t.ACTION_RECURSIVE,
                "Rename global item",
                idaapi.SETMENU_APP
            )

        # done
        return 0

#------------------------------------------------------------------------------
# Prefix Wrappers
#------------------------------------------------------------------------------

def recursive_prefix_cursor():
    """
    Recursive prefix under the user cursor.
    """

    # get the function reference under the user cursor (if there is one)
    target = get_cursor_func_ref()
    if target == idaapi.BADADDR:
        return

    # execute the recursive prefix
    recursive_prefix(target)

def inject_prefix_actions(form, popup, form_type):
    """
    Inject prefix actions to popup menu(s) based on context.
    """

    #
    # disassembly window
    #

    if form_type == idaapi.BWN_DISASMS:

        #
        # if the user cursor isn't hovering over a function ref, there
        # is nothing for us to do
        #

        if get_cursor_func_ref() == idaapi.BADADDR:
            return

        #
        # the user cursor is hovering over a valid target for a recursive
        # function prefix. insert the prefix action entry into the menu
        #

        idaapi.attach_action_to_popup(
            form,
            popup,
            prefix_t.ACTION_RECURSIVE,
            "Rename",
            idaapi.SETMENU_APP
        )

    #
    # functions window
    #

    elif form_type == idaapi.BWN_FUNCS:

        # inject the 'Bulk' function prefix action
        idaapi.attach_action_to_popup(
            form,
            popup,
            prefix_t.ACTION_BULK,
            "Delete function(s)...",
            idaapi.SETMENU_INS
        )

        # inject the 'Clear prefix' action
        idaapi.attach_action_to_popup(
            form,
            popup,
            prefix_t.ACTION_CLEAR,
            "Delete function(s)...",
            idaapi.SETMENU_INS
        )

        # inject a menu separator
        idaapi.attach_action_to_popup(
            form,
            popup,
            None,
            "Delete function(s)...",
            idaapi.SETMENU_INS
        )

    # done
    return 0

#------------------------------------------------------------------------------
# Prefix API
#------------------------------------------------------------------------------

PREFIX_DEFAULT = "MyPrefix"
PREFIX_SEPARATOR = '%'

def recursive_prefix(addr):
    """
    Recursively prefix a function tree with a user defined string.
    """
    func_addr = idaapi.get_name_ea(idaapi.BADADDR, idaapi.get_func_name(addr))
    if func_addr == idaapi.BADADDR:
        idaapi.msg("Prefix: 0x%08X does not belong to a defined function\n" % addr)
        return

    # NOTE / COMPAT:
    # prompt the user for a prefix to apply to the selected functions
    if using_ida7api:
        tag = idaapi.ask_str(PREFIX_DEFAULT, 0, "Function Tag")
    else:
        tag = idaapi.askstr(0, PREFIX_DEFAULT, "Function Tag")

    # the user closed the window... ignore
    if tag == None:
        return

    # the user put a blank string and hit 'okay'... notify & ignore
    elif tag == '':
        idaapi.warning("[ERROR] Tag cannot be empty [ERROR]")
        return

    # recursively collect all the functions called by this function
    nodes_xref_down = graph_down(func_addr, path=set([]))

    # graph_down returns the int address needs to be converted
    tmp  = []
    tmp1 = ''
    for func_addr in nodes_xref_down:
        tmp1 = idaapi.get_func_name(func_addr)
        if tmp1:
            tmp.append(tmp1)
    nodes_xref_down = tmp

    # prefix the tree of functions
    for rename in nodes_xref_down:
        func_addr = idaapi.get_name_ea(idaapi.BADADDR, rename)
        if tag not in rename:
            idaapi.set_name(func_addr,'%s%s%s' % (str(tag), PREFIX_SEPARATOR, rename), idaapi.SN_NOWARN)

    # refresh the IDA views
    refresh_views()

def bulk_prefix():
    """
    Prefix the Functions window selection with a user defined string.
    """

    # NOTE / COMPAT:
    # prompt the user for a prefix to apply to the selected functions
    if using_ida7api:
        tag = idaapi.ask_str(PREFIX_DEFAULT, 0, "Function Tag")
    else:
        tag = idaapi.askstr(0, PREFIX_DEFAULT, "Function Tag")

    # the user closed the window... ignore
    if tag == None:
        return

    # the user put a blank string and hit 'okay'... notify & ignore
    elif tag == '':
        idaapi.warning("[ERROR] Tag cannot be empty [ERROR]")
        return

    #
    # loop through all the functions selected in the 'Functions window' and
    # apply the user defined prefix tag to each one.
    #

    for func_name in get_selected_funcs():

        # ignore functions that already have the specified prefix applied
        if func_name.startswith(tag):
            continue

        # apply the user defined prefix to the function (rename it)
        new_name  = '%s%s%s' % (str(tag), PREFIX_SEPARATOR, func_name)
        func_addr = idaapi.get_name_ea(idaapi.BADADDR, func_name)
        idaapi.set_name(func_addr, new_name, idaapi.SN_NOWARN)

    # refresh the IDA views
    refresh_views()

def clear_prefix():
    """
    Clear user defined prefixes from the selected functions in the Functions window.
    """

    #
    # loop through all the functions selected in the 'Functions window' and
    # clear any user defined prefixes applied to them.
    #

    for func_name in get_selected_funcs():

        #
        # locate the last (rfind) prefix separator in the function name as
        # we will want to keep everything that comes after it
        #

        i = func_name.rfind(PREFIX_SEPARATOR)

        # if there is no prefix (separator), there is nothing to trim
        if i == -1:
            continue

        # trim the prefix off the original function name and discard it
        new_name  = func_name[i+1:]
        func_addr = idaapi.get_name_ea(idaapi.BADADDR, func_name)
        idaapi.set_name(func_addr, new_name, idaapi.SN_NOWARN)

    # refresh the IDA views
    refresh_views()

#------------------------------------------------------------------------------
# IDA Util
#------------------------------------------------------------------------------

def refresh_views():
    """
    Refresh the IDA views.
    """

    # refresh IDA views
    idaapi.refresh_idaview_anyway()

    # NOTE/COMPAT: refresh hexrays view, if active
    if using_ida7api:
        current_widget = idaapi.get_current_widget()
        vu = idaapi.get_widget_vdui(current_widget)
    else:
        current_tform = idaapi.get_current_tform()
        vu = idaapi.get_tform_vdui(current_tform)

    if vu:
        vu.refresh_ctext()

def get_all_funcs():
    """
    Enumerate all function names defined in the IDB.
    """
    return set(idaapi.get_func_name(ea) for ea in idautils.Functions())

def get_cursor_func_ref():
    """
    Get the function reference under the user cursor.

    Returns BADADDR or a valid function address.
    """

    # NOTE / COMPAT:
    if using_ida7api:
        current_widget = idaapi.get_current_widget()
        form_type      = idaapi.get_widget_type(current_widget)
        vu = idaapi.get_widget_vdui(current_widget)
    else:
        current_tform = idaapi.get_current_tform()
        form_type    = idaapi.get_tform_type(current_tform)
        vu = idaapi.get_tform_vdui(current_tform)

    #
    # hexrays view is active
    #

    if vu:
        cursor_addr = vu.item.get_ea()

    #
    # disassembly view is active
    #

    elif form_type == idaapi.BWN_DISASM:
        cursor_addr = idaapi.get_screen_ea()
        opnum = idaapi.get_opnum()

        if opnum != -1:

            #
            # if the cursor is over an operand value that has a function ref,
            # use that as a valid rename target
            #

            # NOTE/COMPAT:
            if using_ida7api:
                op_addr = idc.get_operand_value(cursor_addr, opnum)
            else:
                op_addr = idc.GetOperandValue(cursor_addr, opnum)

            op_func = idaapi.get_func(op_addr)

            # NOTE/COMPAT:
            if using_ida7api:
                if op_func and op_func.start_ea == op_addr:
                    return op_addr
            else:
                if op_func and op_func.startEA == op_addr:
                    return op_addr

    # unsupported/unknown view is active
    else:
        return idaapi.BADADDR

    #
    # if the cursor is over a function definition or other reference, use that
    # as a valid rename target
    #

    cursor_func = idaapi.get_func(cursor_addr)

    # NOTE/COMPAT:
    if using_ida7api:
        if cursor_func and cursor_func.start_ea == cursor_addr:
            return cursor_addr
    else:
        if cursor_func and cursor_func.startEA == cursor_addr:
            return cursor_addr

    # fail
    return idaapi.BADADDR

def get_selected_funcs():
    """
    Return the list of function names selected in the Functions window.
    """

    # NOTE / COMPAT:
    if using_ida7api:
        import sip
        twidget = idaapi.find_widget("Functions window")
        widget  = sip.wrapinstance(long(twidget), QtWidgets.QWidget) # NOTE: LOL
    else:
        tform = idaapi.find_tform("Functions window")
        if using_pyqt5:
            widget = idaapi.PluginForm.FormToPyQtWidget(tform)
        else:
            widget = idaapi.PluginForm.FormToPySideWidget(tform)

    # TODO: test this
    if not widget:
        idaapi.warning("Unable to find 'Functions window'")
        return

    #
    # locate the table widget within the Functions window that actually holds
    # all the visible function metadata
    #

    table = widget.findChild(QtWidgets.QTableView)

    #
    # scrape the selected function names from the Functions window table
    #

    selected_funcs = [str(s.data()) for s in table.selectionModel().selectedRows()]

    #
    # re-map the scraped names as they appear in the function table, to their true
    # names as they are saved in the IDB. See the match_funcs(...) function
    # comment for more details
    #

    return match_funcs(selected_funcs)

def match_funcs(qt_funcs):
    """
    Convert function names scraped from Qt to their *actual* representation.

    The function names we scrape from the Functions window Qt table actually
    use the underscore character ('_') as a substitute for a variety of
    different characters.

    For example, a function named foo%bar in the IDB will appears as foo_bar
    in the Functions window table.

    This function takes a list of names as they appear in the Functions window
    table such as the following:

        ['foo_bar']

    And applies a best effort lookup to return a list of the 'true' function
    names as they are stored in the IDB.

       ['foo%bar']

    TODO: rewrite this to be more efficient for larger idbs
    TODO: takes first matching function, may want to change it to make the requirements more strict
    """
    res = set()
    ida_funcs = get_all_funcs()
    for f in qt_funcs:
        for f2 in ida_funcs:
            if len(f) == len(f2):
                i = 0
                while i < len(f) and (f[i] == f2[i] or f[i] == '_'):
                    i += 1

                if i == len(f):
                    res.add(f2)
                    break

    return list(res)

def graph_down(ea, path=set()):
    """
    Recursively collect all function calls.

    Copied with minor modifications from
    http://hooked-on-mnemonics.blogspot.com/2012/07/renaming-subroutine-blocks-and.html
    """
    path.add(ea)

    #
    # extract all the call instructions from the current function
    #

    call_instructions = []
    instruction_info = idaapi.insn_t()
    for address in idautils.FuncItems(ea):

        # NOTE / COMPAT:
        if using_ida7api:

            # decode the instruction
            if not idaapi.decode_insn(instruction_info, address):
                continue

            # check if this instruction is a call
            if not idaapi.is_call_insn(instruction_info):
                continue

        else:
            if not idaapi.is_call_insn(address):
                continue

        # save this address as a call instruction
        call_instructions.append(address)

    #
    # iterate through all the instructions in the target function (ea) and
    # inspect all the call instructions
    #

    for x in call_instructions:

        #  TODO
        for r in idautils.XrefsFrom(x, idaapi.XREF_FAR):
            #print "0x%08X" % h, "--calls-->", "0x%08X" % r.to
            if not r.iscode:
                    continue

            # get the function pointed at by this call
            func = idaapi.get_func(r.to)
            if not func:
                continue

            # ignore calls to imports / library calls / thunks
            if (func.flags & (idaapi.FUNC_THUNK | idaapi.FUNC_LIB)) != 0:
                continue

            #
            # if we have not traversed to the destination function that this
            # call references, recurse down to it to continue our traversal
            #

            if r.to not in path:
                graph_down(r.to, path)

    return path

class IDACtxEntry(idaapi.action_handler_t):
    """
    A basic Context Menu class to utilize IDA's action handlers.
    """

    def __init__(self, action_function):
        idaapi.action_handler_t.__init__(self)
        self.action_function = action_function

    def activate(self, ctx):
        """
        Execute the embedded action_function when this context menu is invoked.
        """
        self.action_function()
        return 1

    def update(self, ctx):
        """
        Ensure the context menu is always available in IDA.
        """
        return idaapi.AST_ENABLE_ALWAYS

#------------------------------------------------------------------------------
# Plugin Util
#------------------------------------------------------------------------------

PLUGIN_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), prefix_t.wanted_name))

def plugin_resource(resource_name):
    """
    Return the full path for a given plugin resource file.
    """
    return os.path.join(
        PLUGIN_PATH,
        "resources",
        resource_name
    )

