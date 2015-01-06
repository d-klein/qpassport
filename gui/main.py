#!/usr/bin/python

import sys
from PyQt4 import Qt,QtGui,QtCore
from smartcard.CardType import AnyCardType
from smartcard.CardRequest import CardRequest
from smartcard.CardConnectionObserver import ConsoleCardConnectionObserver
from smartcard.sw.ErrorCheckingChain import ErrorCheckingChain
from smartcard.sw.ISO7816_4ErrorChecker import ISO7816_4ErrorChecker
from smartcard.util import toHexString
from smartcard.Exceptions import CardRequestTimeoutException
from card.des3 import TDES
from card.secure_messaging import SecureMessenger
from card.retail_mac import RMAC
from card.bac import run_bac
from card.efcom import EFCom
from card.dg1 import DG1
from card.dg2 import DG2
from mrz_dialog import Mrz_Dialog

class OutLog:
    def __init__(self, edit, out=None, color=None):
        """(edit, out=None, color=None) -> can write stdout, stderr to a
        QTextEdit.
        edit = QTextEdit
        out = alternate stream ( can be the original sys.stdout )
        color = alternate color (i.e. color stderr a different color)
        """
        self.edit = edit
        self.out = None
        self.color = color

    def write(self, m):
        if self.color:
            tc = self.edit.textColor()
            self.edit.setTextColor(self.color)

        self.edit.moveCursor(QtGui.QTextCursor.End)
        self.edit.insertPlainText( m )

        if self.color:
            self.edit.setTextColor(tc)

        if self.out:
            self.out.write(m)

class MWindow(QtGui.QMainWindow):

    def __init__(self):
        super(MWindow, self).__init__()
        # sys.stdout = EmittingStream(textWritten=self.normalOutputWritten)
        self.initUI()

    def __del__(self):
        # Restore sys.stdout
        sys.stdout = sys.__stdout__

    def initUI(self):
        self.resize(800, 470)
        self.setWindowTitle('QPassport Reader')

        font = Qt.QFont("Monospace");
        font.setStyleHint(Qt.QFont.TypeWriter)

        mainWidget = Qt.QWidget()

        portrait = Qt.QPixmap("./head.png").scaled(300,400)
        self.lbl_portrait = Qt.QLabel()
        self.lbl_portrait.setPixmap(portrait)

        self.edit_right = Qt.QTextEdit()
        self.edit_right.setText("PERSONAL DATA: \n\n")
        self.edit_right.setReadOnly(True)
        self.edit_mrz = Qt.QTextEdit()
        self.edit_mrz.setText("MRZ:")
        self.edit_mrz.setFont(font)
        self.edit_mrz.setReadOnly(True)
        self.edit_log = Qt.QTextEdit()
        self.edit_log.setText("LOG:\n")
        self.edit_log.setMinimumHeight(200)
        self.edit_log.setFont(font)
        self.edit_log.setReadOnly(True)

        sys.stdout = OutLog( self.edit_log, sys.stdout)
        sys.stderr = OutLog( self.edit_log, sys.__stderr__)


        self.go = Qt.QPushButton("Read Passport")
        self.go.setFont(font)

        self.go.clicked.connect(self.read_pass)

        vbox = Qt.QVBoxLayout()
        hbox = Qt.QHBoxLayout()
        hbox.addWidget(self.lbl_portrait)
        hbox.addWidget(self.edit_right)
        vbox.addLayout(hbox)
        vbox.addWidget(self.edit_mrz)
        vbox.addWidget(self.edit_log)
        vbox.addWidget(self.go)

        mainWidget.setLayout(vbox)

        self.setCentralWidget(mainWidget)
        self.centerOnScreen()
        self.show()


    def normalOutputWritten(self, text):
        cursor = self.edit_log.textCursor()
        cursor.movePosition(QtGui.QTextCursor.End)
        cursor.insertText(text)
        self.edit_log.setTextCursor(cursor)
        self.edit_log.ensureCursorVisible()


    def centerOnScreen (self):
        '''
        centerOnScreen()
        Centers (vertically in the upper third) the window on the screen.
        '''
        resolution = QtGui.QDesktopWidget().screenGeometry()
        self.move((resolution.width() / 2) - (self.frameSize().width() / 2),
        (resolution.height() / 2) - (self.frameSize().height()*2 / 3))

    def format_date(self,date_string):
        year = int(date_string[0:2])
        if(year < 20):
            year = "20"+str(year)
        else:
            year = "19"+str(year)
        return date_string[4:6]+"."+date_string[2:4]+"."+year


    def read_pass(self):
        self.edit_log.append("... accessing passport ...\n")
        Qt.QApplication.processEvents()

        MRZ_DOC_NO = 'YV42109H95'
        MRZ_DOB    = '6305213'
        MRZ_EXP    = '1203314'
        #MRZ_DOC_NO = 'C4J6R0H111'
        #MRZ_DOB    = '8103206'
        #MRZ_EXP    = '1808074'

        dialog = Mrz_Dialog()
        if dialog.exec_() == Qt.QDialog.Accepted:
            if(str(dialog.le_line3.text()) != ""):
                MRZ_DOC_NO = str(dialog.le_line1.text()[5:15]).upper()
                MRZ_DOB    = str(dialog.le_line2.text()[0:7]).upper()
                MRZ_EXP    = str(dialog.le_line2.text()[8:15]).upper()
            else:
                MRZ_DOC_NO = str(dialog.le_line2.text()[0:10]).upper()
                MRZ_DOB    = str(dialog.le_line2.text()[13:20]).upper()
                MRZ_EXP    = str(dialog.le_line2.text()[21:28]).upper()

        print(MRZ_DOC_NO)#
        print(MRZ_DOB)
        print(MRZ_EXP)

        MRZ_INFO = MRZ_DOC_NO + MRZ_DOB + MRZ_EXP
        BAC_IV = "0000000000000000".decode('hex')

        # request any card
        cardtype = AnyCardType()
        cardrequest = CardRequest( timeout=10, cardType=cardtype )
        try:
            cardservice = cardrequest.waitforcard()

            # our error checking chain
            errorchain=[]
            errorchain=[ ErrorCheckingChain( errorchain, ISO7816_4ErrorChecker() ) ]
            cardservice.connection.setErrorCheckingChain( errorchain )

            # a console tracer
            observer=ConsoleCardConnectionObserver()
            cardservice.connection.addObserver( observer )

            # send a few apdus; exceptions will occur upon errors
            cardservice.connection.connect()

            # run Basic Access Control for secure messaging
            (ks_enc, ks_mac, ssc) = run_bac(cardservice.connection, MRZ_INFO)

            Qt.QApplication.processEvents()

            # setup secure messaging with derived keys
            des_sm = TDES(ks_enc)
            mac_sm = RMAC(ks_mac)
            ap = SecureMessenger(des_sm.enc, des_sm.dec, mac_sm.mac, ssc)
            ap.debug = True

            # read ef.com
            efcom = EFCom()
            efcom.read_ef_com(cardservice.connection, ap)
            print("lds_version: "+toHexString(efcom.lds_version))
            print("utf_version: "+toHexString(efcom.utf_version))
            print("stored files: "+toHexString(efcom.stored_info_tags))

            Qt.QApplication.processEvents()

            dg1 = DG1()
            dg1.read_dg1(cardservice.connection, ap)
            self.edit_mrz.setText(str(dg1))
            Qt.QApplication.processEvents()


            type = ""
            code = ""
            passport_no = ""
            name = ""
            gname = ""
            dob = ""
            sex = ""
            doi = ""
            eoi = ""
            if(not (dg1.mrz_line3) and dg1.mrz_line1 and dg1.mrz_line2):
                type = dg1.mrz_line1[0:2]
                code = dg1.mrz_line1[2:5]
                full_name = dg1.mrz_line1[5:]
                sur_g = full_name.split("<<")
                name = sur_g[0]
                gname = sur_g[1]
                passport_no = dg1.mrz_line2[0:9]
                dob = self.format_date(dg1.mrz_line2[13:19])
                eoi = self.format_date(dg1.mrz_line2[21:27])
                sex = dg1.mrz_line2[20]
            elif((dg1.mrz_line3) and dg1.mrz_line1 and dg1.mrz_line2):
                sur_g = dg1.mrz_line3.split("<<")
                name = sur_g[0]
                gname = sur_g[1]
                type = dg1.mrz_line1[0:2]
                code = dg1.mrz_line1[2:5]
                passport_no = dg1.mrz_line1[5:14]
                dob = self.format_date(dg1.mrz_line2[0:6])
                eoi = self.format_date(dg1.mrz_line2[8:14])
                sex = dg1.mrz_line2[7]

            s = "Type         Code        Passport No      \n" + \
                type + "            "+code + "          " + passport_no + "\n\n" + \
                "Given Name\n" + \
                gname + "\n\n" + \
                "Name\n" + \
                name + "\n\n" + \
                "Nationality        Date of Birth\n" + \
                code + "                    " + dob + "\n\n" + \
                "Sex        Date of Expiry\n" + \
                sex + "            " + eoi

            self.edit_right.setText(s)

            dg2 = DG2()
            dg2.read_dg2(cardservice.connection, ap)

            Qt.QApplication.processEvents()

            # write to file
            if(dg2.raw_image):
                img= open("temp.jp2",'wb+')
                img.write(bytearray(dg2.raw_image))
                img.flush()
                img.close()
                portrait = Qt.QPixmap("./temp.jp2").scaled(300,400)
                self.lbl_portrait.setPixmap(portrait)
                self.update()

        except CardRequestTimeoutException:
            self.edit_log.append('time-out: no card inserted during last 10s')

        #except:
        #    import sys
        #    self.edit_log.append("unknown error (see log)\n")


def main():

    app = QtGui.QApplication(sys.argv)
    ex = MWindow()
    sys.exit(app.exec_())

if __name__ == '__main__':
    main()