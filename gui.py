import sys

import rsa
from pgp import PrivateKeyRing
from pgp import PublicKeyRing
from pgp import serializeRsaPubKey
from pgp import serializeRsaPrivKey
from pgp import deserializeRsaPubKey
from pgp import deserializeRsaPrivKey
from pgp import serializePrivKeyRing
from pgp import serializePubKeyRing
from pgp import deserializePrivKeyRing
from pgp import deserializePubKeyRing
from pgp import importPrivKeyRing
from pgp import importPubKeyRing
from pgp import exportPubFromPriv
from pgp import exportPubKeyRing
from pgp import exportPrivKeyRing
from pgp import sendMessage
from pgp import recieveMessage
from pgp import generateRsaKeys
from pgp import privKeyDigest
from pgp import findKey

from pgp import generateDsaKeys, generateElgamalKeys, serializeDsaPubKey, serializeDsaPrivKey
from pgp import serializeElGamalPubKey, serializeElGamalPrivKey, deserializeDsaPrivKey, deserializeDsaPubKey
from pgp import deserializeElGamalPubKey, deserializeElGamalPrivKey

from PyQt5 import QtWidgets
from PyQt5.QtCore import Qt


class MainWindow(QtWidgets.QMainWindow):

    def __init__(self):
        super().__init__()
        w = QtWidgets.QWidget()
        self.setMenuWidget(w)
        self.setWindowTitle('PGP')
        buttonPrivKeyRing = QtWidgets.QPushButton("Manage Private Key Ring")
        buttonPubKeyRing = QtWidgets.QPushButton("Manage Public Key Ring")
        buttonGenerateKeys = QtWidgets.QPushButton("Generate Keys")
        buttonSendMessage = QtWidgets.QPushButton("Send message")
        buttonOpenMessage = QtWidgets.QPushButton("Open message")
        buttonPrivKeyRing.clicked.connect(self.eventShowPrivKeyRing)
        buttonPubKeyRing.clicked.connect(self.eventShowPublicKeyRing)
        buttonGenerateKeys.clicked.connect(self.eventShowGenerate)
        buttonSendMessage.clicked.connect(self.eventShowSend)
        buttonOpenMessage.clicked.connect(self.eventShowOpen)
        layout = QtWidgets.QGridLayout()
        layout.addWidget(buttonPrivKeyRing, 0, 0)
        layout.addWidget(buttonPubKeyRing, 0, 1)
        layout.addWidget(buttonGenerateKeys, 1, 0, 1, 2)
        layout.addWidget(buttonSendMessage, 2, 0)
        layout.addWidget(buttonOpenMessage, 2, 1)
        self.resize(300, 500)
        self.loadedKeyringsPriv = []
        self.loadedKeyringsPub = []
        w.setLayout(layout)
        self.show()

    def eventShowPrivKeyRing(self, checked):
        self.dialog = KeyRingWindow(False, self)
        self.dialog.show()

    def eventShowPublicKeyRing(self, checked):
        self.dialog = KeyRingWindow(True, self)
        self.dialog.show()

    def eventShowGenerate(self, checked):
        dialog = QtWidgets.QDialog(self)
        dialog.resize(300, 130)
        dialog.setWindowTitle("Generate Keys")
        dialog.setModal(True)
        inputUserId = QtWidgets.QLineEdit()
        inputUserName = QtWidgets.QLineEdit()
        inputPassword = QtWidgets.QLineEdit()
        inputAlgs = QtWidgets.QComboBox()
        inputAlgs.addItems(['RSA', 'DSA + ELGAMAL'])
        inputKeySize = QtWidgets.QComboBox()
        inputKeySize.addItems(['1024', '2048'])
        button = QtWidgets.QPushButton('Generate')

        button.clicked.connect(self.eventGenerate)
        layout = QtWidgets.QGridLayout()
        layout.addWidget(QtWidgets.QLabel('Mail:'), 0, 0)
        layout.addWidget(QtWidgets.QLabel('Name:'), 1, 0)
        layout.addWidget(QtWidgets.QLabel('Password:'), 2, 0)
        layout.addWidget(QtWidgets.QLabel('Algorithm:'), 3, 0)
        layout.addWidget(QtWidgets.QLabel('Key Size:'), 4, 0)
        layout.addWidget(inputUserId, 0, 1)
        layout.addWidget(inputUserName, 1, 1)
        layout.addWidget(inputPassword, 2, 1)
        layout.addWidget(inputAlgs, 3, 1)
        layout.addWidget(inputKeySize, 4, 1)
        layout.addWidget(button, 5, 0, 1, 2)

        self.inputUserId = inputUserId
        self.inputUserName = inputUserName
        self.inputPassword = inputPassword
        self.inputAlgs = inputAlgs
        self.inputKeySize = inputKeySize
        dialog.setLayout(layout)
        self.dialog = dialog

        dialog.show()

    def eventGenerate(self, checked):
        alg = self.inputAlgs.currentText()
        n = int(self.inputKeySize.currentText())
        pub, priv = None, None
        if alg == 'RSA':
            (pub, priv) = generateRsaKeys(n)
            pub = serializeRsaPubKey(pub)
            priv = serializeRsaPrivKey(priv)

            priv = privKeyDigest(priv, self.inputPassword.text())
        else:
            (pub1, priv1) = generateDsaKeys(n)
            pub1 = serializeDsaPubKey(pub1)
            priv1 = serializeDsaPrivKey(priv1)
            (pub2, priv2) = generateElgamalKeys(n)
            pub2 = serializeElGamalPubKey(pub2)
            priv2 = serializeElGamalPrivKey(priv2)
            len1 = len(pub1)
            len2 = len(pub2)
            pub = len1.to_bytes(4, 'big') + pub1 + len2.to_bytes(4, 'big') + pub2
            len1 = len(priv1)
            len2 = len(priv2)
            priv = len1.to_bytes(4, 'big') + priv1 + len2.to_bytes(4, 'big') + priv2

            priv = privKeyDigest(priv, self.inputPassword.text())

        privRing = PrivateKeyRing(alg, pub, priv, self.inputUserId.text(), self.inputUserName.text())
        pubRing = PublicKeyRing(alg, pub, self.inputUserId.text(), self.inputUserName.text())
        if findKey(self.loadedKeyringsPub, pubRing.keyID):
            print("VEC POSTOJI KEY ID U JAVNIM")
            return
        if findKey(self.loadedKeyringsPriv, pubRing.keyID):
            print("VEC POSTOJI KEY ID U PRIVATNIM")
            return
        self.loadedKeyringsPriv.append(privRing)

    def eventShowSend(self, checked):
        dialog = QtWidgets.QDialog(self)
        dialog.setModal(True)
        dialog.setWindowTitle('Send a message')
        checkboxSenderPrivKey = QtWidgets.QComboBox()
        items = []
        for ring in self.loadedKeyringsPriv:
            items.append(hex(int.from_bytes(ring.keyID, 'big')))
        checkboxSenderPrivKey.addItems(items)

        checkboxRecieverPubKey = QtWidgets.QComboBox()
        boxSymAlg = QtWidgets.QComboBox()
        items = []
        for ring in self.loadedKeyringsPub:
            items.append(hex(int.from_bytes(ring.keyID, 'big')))
        checkboxRecieverPubKey.addItems(items)
        boxSymAlg.addItems(['AES128', 'CAST5'])

        inputMessage = QtWidgets.QPlainTextEdit()
        inputPath = QtWidgets.QLineEdit()
        inputPath.setText('Path')
        inputPassword = QtWidgets.QLineEdit()
        inputPassword.setText('Password')
        button = QtWidgets.QPushButton('Send')

        button.clicked.connect(self.eventSend)
        layout = QtWidgets.QVBoxLayout()
        layout.addWidget(checkboxSenderPrivKey)
        layout.addWidget(checkboxRecieverPubKey)
        layout.addWidget(boxSymAlg)
        layout.addWidget(inputPath)
        layout.addWidget(inputPassword)
        layout.addWidget(inputMessage)
        layout.addWidget(button)
        self.checkboxSenderPrivKey = checkboxSenderPrivKey
        self.checkboxRecieverPubKey = checkboxRecieverPubKey
        self.inputPath = inputPath
        self.inputPassword = inputPassword
        self.inputMessage = inputMessage
        self.boxSymAlg = boxSymAlg
        dialog.setLayout(layout)
        self.dialog = dialog

        dialog.show()

    def eventSend(self, checked):
        priv = findKey(self.loadedKeyringsPriv,
                       int(self.checkboxSenderPrivKey.currentText()[2:], 16).to_bytes(8, 'big'))
        pub = findKey(self.loadedKeyringsPub, int(self.checkboxRecieverPubKey.currentText()[2:], 16).to_bytes(8, 'big'))
        if priv.alg != pub.alg:
            print("Non compatibile keys")
            return
        if priv.userid == pub.userid:
            print('Keys belong to same user')
            return
        path = self.inputPath.text()
        password = self.inputPassword.text()
        msg = self.inputMessage.toPlainText()
        symAlg = self.boxSymAlg.currentText()
        sendMessage(symAlg, msg, password, path, pub, priv)

    def eventShowOpen(self, checked):
        dialog = QtWidgets.QDialog(self)
        dialog.setModal(True)
        dialog.setWindowTitle('Open a message')
        inputMessage = QtWidgets.QPlainTextEdit()
        inputMessage.setReadOnly(True)
        inputPath = QtWidgets.QLineEdit()
        inputPath.setText('Path')
        inputPassword = QtWidgets.QLineEdit()
        inputPassword.setText('Password')
        button = QtWidgets.QPushButton('Open')

        button.clicked.connect(self.eventOpen)
        layout = QtWidgets.QVBoxLayout()
        layout.addWidget(inputPath)
        layout.addWidget(inputPassword)
        layout.addWidget(inputMessage)
        layout.addWidget(button)
        self.inputPath = inputPath
        self.inputPassword = inputPassword
        self.inputMessage = inputMessage
        dialog.setLayout(layout)
        self.dialog = dialog

        dialog.show()

    def eventOpen(self, checked):
        path = self.inputPath.text()
        password = self.inputPassword.text()
        msg = recieveMessage(path, password, self.loadedKeyringsPriv, self.loadedKeyringsPub)
        self.inputMessage.setPlainText(msg)


class KeyRingWindow(QtWidgets.QDialog):
    def __init__(self, type: bool, window: MainWindow):
        super().__init__()
        self.setWindowTitle("PRIVATE key ring" if not type else "PUBLIC key ring")
        self.window = window
        self.type = type
        self.setModal(True)
        self.resize(900, 500)
        self.textbox = QtWidgets.QLineEdit()
        self.textbox.setText('a@mail.com-PRIVATE.pem' if not type else 'a@mail.com-PUBLIC.pem')
        self.combo = QtWidgets.QComboBox()
        self.combo.setFixedWidth(140)
        items = [hex(int.from_bytes(ring.keyID, 'big')) for ring in
                 (self.window.loadedKeyringsPriv if not self.type else self.window.loadedKeyringsPub)]
        self.combo.addItems(items)
        button = QtWidgets.QPushButton("Import from .pem file")
        button.clicked.connect(self.eventImport)
        button2 = QtWidgets.QPushButton("Delete")
        button2.clicked.connect(self.obrisi)

        if not type:
            tabela = QtWidgets.QTableWidget(len(self.window.loadedKeyringsPriv), 7)
            for i in range(len(self.window.loadedKeyringsPriv)):
                val = self.window.loadedKeyringsPriv[i].print().split('|')
                for j in range(7):
                    t = QtWidgets.QTableWidgetItem(val[j])
                    t.setFlags(t.flags() ^ Qt.ItemIsEditable)
                    tabela.setItem(i, j, t)
            tabela.setHorizontalHeaderItem(0, QtWidgets.QTableWidgetItem("Timestamp"))
            tabela.setHorizontalHeaderItem(1, QtWidgets.QTableWidgetItem("Key ID"))
            tabela.setHorizontalHeaderItem(2, QtWidgets.QTableWidgetItem("Public key"))
            tabela.setHorizontalHeaderItem(3, QtWidgets.QTableWidgetItem("Private key"))
            tabela.setHorizontalHeaderItem(4, QtWidgets.QTableWidgetItem("User ID"))
            tabela.setHorizontalHeaderItem(5, QtWidgets.QTableWidgetItem("Name"))
            tabela.setHorizontalHeaderItem(6, QtWidgets.QTableWidgetItem("Alg"))
            tabela.setColumnWidth(0, 115)
            tabela.setColumnWidth(1, 130)
            tabela.setColumnWidth(2, 200)
            tabela.setColumnWidth(3, 200)
            tabela.setColumnWidth(4, 100)
            tabela.setColumnWidth(5, 120)
        else:
            tabela = QtWidgets.QTableWidget(len(self.window.loadedKeyringsPub), 6)
            for i in range(len(self.window.loadedKeyringsPub)):
                val = self.window.loadedKeyringsPub[i].print().split('|')
                for j in range(6):
                    t = QtWidgets.QTableWidgetItem(val[j])
                    t.setFlags(t.flags() ^ Qt.ItemIsEditable)
                    tabela.setItem(i, j, t)
            tabela.setHorizontalHeaderItem(0, QtWidgets.QTableWidgetItem("Timestamp"))
            tabela.setHorizontalHeaderItem(1, QtWidgets.QTableWidgetItem("Key ID"))
            tabela.setHorizontalHeaderItem(2, QtWidgets.QTableWidgetItem("Public key"))
            tabela.setHorizontalHeaderItem(3, QtWidgets.QTableWidgetItem("User ID"))
            tabela.setHorizontalHeaderItem(4, QtWidgets.QTableWidgetItem("Name"))
            tabela.setHorizontalHeaderItem(4, QtWidgets.QTableWidgetItem("Alg"))
            tabela.setColumnWidth(0, 115)
            tabela.setColumnWidth(1, 120)
            tabela.setColumnWidth(2, 250)
            tabela.setColumnWidth(3, 120)
            tabela.setColumnWidth(4, 140)
        self.tabela = tabela

        button3 = QtWidgets.QPushButton('Export to .pem format') if type else QtWidgets.QPushButton(
            'Export private key to .pem format')
        button3.clicked.connect(self.eventExport)
        if not type:
            button4 = QtWidgets.QPushButton('Export public key to .pem format')
            button4.clicked.connect(self.eventExportPubFromPriv)
        l1 = QtWidgets.QHBoxLayout()
        l1.addWidget(self.textbox)
        l1.addWidget(button)
        l1.addWidget(self.combo)
        l1.addWidget(button2)
        l1.addWidget(button3)
        if not type:
            l1.addWidget(button4)

        layout = QtWidgets.QVBoxLayout()
        layout.addLayout(l1)
        layout.addWidget(tabela)

        self.setLayout(layout)

    def obrisi(self, checked):
        if self.type:
            pub = findKey(self.window.loadedKeyringsPub, int(self.combo.currentText()[2:], 16).to_bytes(8, 'big'))
            i = self.window.loadedKeyringsPub.index(pub)
            self.combo.removeItem(i)
            self.tabela.removeRow(i)
            ring = self.window.loadedKeyringsPub.pop(i)
            for j in range(len(self.window.loadedKeyringsPriv)):
                if self.window.loadedKeyringsPriv[j].keyID == ring.keyID:
                    self.window.loadedKeyringsPriv.pop(j)
                    break

        else:
            priv = findKey(self.window.loadedKeyringsPriv, int(self.combo.currentText()[2:], 16).to_bytes(8, 'big'))
            i = self.window.loadedKeyringsPriv.index(priv)
            self.combo.removeItem(i)
            self.tabela.removeRow(i)
            ring = self.window.loadedKeyringsPriv.pop(i)
            for j in range(len(self.window.loadedKeyringsPub)):
                if self.window.loadedKeyringsPub[j].keyID == ring.keyID:
                    self.window.loadedKeyringsPub.pop(j)
                    break

    def eventImport(self, checked):
        try:
            if self.type:
                keyring = importPubKeyRing(self.textbox.text())
                if findKey(self.window.loadedKeyringsPub, keyring.keyID):
                    print("Zauzet KEYID")
                    return
                ring = keyring.print().split('|')
                i = self.tabela.rowCount()
                self.combo.addItem(hex(int.from_bytes(keyring.keyID, 'big')))
                self.tabela.setRowCount(i + 1)
                for j in range(6):
                    t = QtWidgets.QTableWidgetItem(ring[j])
                    t.setFlags(t.flags() ^ Qt.ItemIsEditable)
                    self.tabela.setItem(i, j, t)

                self.window.loadedKeyringsPub.append(keyring)
            else:
                keyring = importPrivKeyRing(self.textbox.text())
                if findKey(self.window.loadedKeyringsPriv, keyring.keyID):
                    print("Zauzet KEYID")
                    return
                ring = keyring.print().split('|')
                i = self.tabela.rowCount()
                self.combo.addItem(hex(int.from_bytes(keyring.keyID, 'big')))
                self.tabela.setRowCount(i + 1)
                for j in range(7):
                    t = QtWidgets.QTableWidgetItem(ring[j])
                    t.setFlags(t.flags() ^ Qt.ItemIsEditable)
                    self.tabela.setItem(i, j, t)
                self.window.loadedKeyringsPriv.append(keyring)

        except ValueError:
            print('Greska pri ucitavanju')
        except OSError:
            print('Los fajl')
        except Exception as e:
            print(e.args)

    def eventExport(self, checked):
        if self.type:
            key = findKey(self.window.loadedKeyringsPub, int(self.combo.currentText()[2:], 16).to_bytes(8, 'big'))
            exportPubKeyRing(key)
        else:
            key = findKey(self.window.loadedKeyringsPriv, int(self.combo.currentText()[2:], 16).to_bytes(8, 'big'))
            exportPrivKeyRing(key)

    def eventExportPubFromPriv(self, checked):
        key = findKey(self.window.loadedKeyringsPriv, int(self.combo.currentText()[2:], 16).to_bytes(8, 'big'))
        exportPubFromPriv(key)


app = QtWidgets.QApplication([])
main = MainWindow()
sys.exit(app.exec_())
