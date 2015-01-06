from PyQt4.QtGui import *
from PyQt4.QtCore import *
class Mrz_Dialog(QDialog):
    def __init__(self, parent=None):
        super(Mrz_Dialog,self).__init__(parent)
        self.setWindowTitle("Enter MRZ Information")

        lbl_glob = QLabel("Type in the MRZ as printed:")

        lbl_line1 = QLabel("Line 1")
        self.le_line1 = QLineEdit()
        lbl_line1.setBuddy(self.le_line1)

        lbl_line2 = QLabel("Line 2")
        self.le_line2 = QLineEdit()
        lbl_line2.setBuddy(self.le_line2)

        lbl_line3 = QLabel("Line 3 (if it exists)")
        self.le_line3 = QLineEdit()
        lbl_line3.setBuddy(self.le_line3)

        vbox = QVBoxLayout()
        vbox.addWidget(lbl_glob)
        vbox.addWidget(lbl_line1)
        vbox.addWidget(self.le_line1)
        vbox.addWidget(lbl_line2)
        vbox.addWidget(self.le_line2)
        vbox.addWidget(lbl_line3)
        vbox.addWidget(self.le_line3)

        buttonBox = QDialogButtonBox(QDialogButtonBox.Ok| QDialogButtonBox.Cancel)
        vbox.addWidget(buttonBox)

        self.connect(buttonBox, SIGNAL("accepted()"),self, SLOT("accept()"))
        self.connect(buttonBox, SIGNAL("rejected()"),self, SLOT("reject()"))

        self.setLayout(vbox)