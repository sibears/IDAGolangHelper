# -----------------------------------------------------------------------
# This is an example illustrating how to use the Form class
# (c) Hex-Rays
#
import GO_Utils
idaapi.require("GO_Utils")
idaapi.require("GO_Utils.Gopclntab")
idaapi.require("GO_Utils.Utils")
idaapi.require("GO_Utils.Firstmoduledata")
idaapi.require("GO_Utils.Types")
idaapi.require("GO_Utils.GoStrings")

from idaapi import Form

GO_SETTINGS = GO_Utils.GoSettings()

#<pycode(ex_askusingform)>
# --------------------------------------------------------------------------
class MyForm(Form):
    def __init__(self):
        self.invert = False
        Form.__init__(self, r"""STARTITEM {id:cGoVers}
GoLoader

{FormChangeCb}
<##Try to detemine go version based on moduledata:{iButton1}>
<##Try to detemine go version based on version string:{iButton2}>
<##Rename functions:{iButton3}>
Go version:
<Go1.2:{r2}>
<Go1.4:{r4}>
<Go1.5:{r5}>
<Go1.6:{r6}>
<Go1.7:{r7}>
<Go1.8:{r8}>
<Go1.9:{r9}>
<Go1.10:{r10}>{cGoVers}>
<##Add standard go types:{iButton4}>
<##Parse types by moduledata:{iButton5}>
""", {
            'iButton1': Form.ButtonInput(self.OnButton1),
            'iButton2': Form.ButtonInput(self.OnButton2),
            'iButton3': Form.ButtonInput(self.OnButton3),
            'iButton4': Form.ButtonInput(self.OnButton4),
            'iButton5': Form.ButtonInput(self.OnButton5),
            'cGoVers': Form.RadGroupControl(("r2", "r3","r4","r5","r6","r7", "r8", "r9", "r10")),
            'FormChangeCb': Form.FormChangeCb(self.OnFormChange),
        })


    def OnButton1(self, code=0):
        GO_SETTINGS.findModuleData()
        print GO_SETTINGS.tryFindGoVersion()


    def OnButton3(self, code=0):
        GO_SETTINGS.renameFunctions()

    def OnButton2(self, code=0):
        print GO_SETTINGS.getVersionByString()

    def OnButton4(self, code=0):
        typ =  self.GetControlValue(self.cGoVers)
        GO_SETTINGS.createTyper(typ)

    def OnButton5(self, code=0):
        typ =  self.GetControlValue(self.cGoVers)
        GO_SETTINGS.typesModuleData(typ)


    def OnFormChange(self, fid):
        return 1



# --------------------------------------------------------------------------

# --------------------------------------------------------------------------
def ida_main():
    # Create form
    global f
    idaapi.add_hotkey("Shift-S", GO_Utils.GoStrings.stringify)
    f = MyForm()

    # Compile (in order to populate the controls)
    f.Compile()

    # Execute the form
    ok = f.Execute()

    # Dispose the form
    f.Free()

# --------------------------------------------------------------------------

#</pycode(ex_askusingform)>


# --------------------------------------------------------------------------
ida_main()