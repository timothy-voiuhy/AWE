from PySide6.QtWidgets import QMessageBox


class MessageBox(QMessageBox):
    """Wrapper class for a QMessageBox
    icon: can be either of [Information, Warning, Critical, Question]
    buttons: can be one or more of :
    ButtonMask, NoButton ,Default ,Escape ,FlagMask, FirstButton, Ok,
    Save, SaveAll, Open, Yes, YesAll, YesToAll, No, NoAll, NoToAll, Abort
    Retry ,Ignore, Close, Cancel, Discard, Help, Apply, Reset, LastButton
    RestoreDefaults"""

    def __init__(self, windowTitle: str = None, text: str = None, icon: str = None, button=None, buttons: list = None):
        super().__init__()
        self.windowTitle_ = windowTitle
        self.button = button
        self.text = text
        self.icon = icon
        self.buttons = buttons
        self.setWindowTitle(self.windowTitle_)
        self.setText(self.text)
        _icon_map = {
            "Information": QMessageBox.Icon.Information,
            "Warning":     QMessageBox.Icon.Warning,
            "Critical":    QMessageBox.Icon.Critical,
            "Question":    QMessageBox.Icon.Question,
        }
        if self.icon in _icon_map:
            self.setIcon(_icon_map[self.icon])
        _btn_map = {
            "Ok":     QMessageBox.StandardButton.Ok,
            "Cancel": QMessageBox.StandardButton.Cancel,
            "Yes":    QMessageBox.StandardButton.Yes,
            "No":     QMessageBox.StandardButton.No,
        }
        if self.button in _btn_map:
            self.setStandardButtons(_btn_map[self.button])
        if self.buttons is not None:
            mapped = [_btn_map[b] for b in self.buttons if b in _btn_map]
            if mapped:
                combined = mapped[0]
                for b in mapped[1:]:
                    combined = combined | b
                self.setStandardButtons(combined)
