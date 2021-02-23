from PyQt5.QtCore import Qt, QThreadPool
from PyQt5.QtWidgets import QWidget, QHBoxLayout, QVBoxLayout, QLabel, QPushButton, QListWidget, QMessageBox, QLineEdit, QTableWidget, QTableWidgetItem, QHeaderView
from PyQt5.QtGui import QIcon
from .ScanWorker import ScanWorker
import psutil, threading

TITLE = 'Panda3D Dephaser'

class MainWidget(QWidget):

    def __init__(self, base):
        QWidget.__init__(self)

        self.base = base

        self.setWindowIcon(QIcon('icon.ico'))
        self.setWindowTitle(TITLE)
        self.setBackgroundColor(Qt.white)

        self.processHeaderWidget = QWidget()
        self.processHeaderLayout = QHBoxLayout(self.processHeaderWidget)
        self.processHeaderLayout.setContentsMargins(0, 0, 0, 0)

        self.processLabel = QLabel('Available processes:')
        self.githubLabel = QLabel('<a href="https://github.com/darktohka/p3dephaser">GitHub</a>')
        self.githubLabel.setOpenExternalLinks(True)

        self.refreshButton = QPushButton('Refresh')
        self.refreshButton.clicked.connect(self.refreshProcesses)
        self.refreshButton.setFixedSize(100, 23)

        self.multifileWidget = QWidget()
        self.multifileLayout = QHBoxLayout(self.multifileWidget)
        self.multifileLayout.setContentsMargins(0, 0, 0, 0)
        self.multifileLabel = QLabel('Requested multifile names:')
        self.multifileBox = QLineEdit(self)
        self.multifileBox.returnPressed.connect(self.beginScan)

        self.multifileLayout.addWidget(self.multifileLabel)
        self.multifileLayout.addWidget(self.multifileBox)

        self.scanButton = QPushButton('Scan')
        self.scanButton.clicked.connect(self.beginScan)

        self.processListBox = QListWidget()

        self.processHeaderLayout.addWidget(self.processLabel)
        self.processHeaderLayout.addStretch(1)
        self.processHeaderLayout.addWidget(self.githubLabel)
        self.processHeaderLayout.addWidget(self.refreshButton)

        self.resultTable = QTableWidget()
        self.resultTable.setColumnCount(3)
        self.resultTable.horizontalHeader().setStretchLastSection(True)
        self.resultTable.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)

        for i, header in enumerate(('Process', 'Multifile', 'Password')):
            self.resultTable.setHorizontalHeaderItem(i, QTableWidgetItem(header))

        self.baseLayout = QVBoxLayout(self)
        self.baseLayout.setContentsMargins(15, 15, 15, 15)
        self.baseLayout.addWidget(self.processHeaderWidget)
        self.baseLayout.addWidget(self.processListBox)
        self.baseLayout.addWidget(self.multifileWidget)
        self.baseLayout.addWidget(self.scanButton)
        self.baseLayout.addWidget(self.resultTable)

        self.refreshProcesses()

        self.threadPool = QThreadPool()
        self.worker = None
        self.processName = None
        self.nextClick = 0
        self.stopEvent = threading.Event()

    def setBackgroundColor(self, color):
        self.setAutoFillBackground(True)
        palette = self.palette()
        palette.setColor(self.backgroundRole(), color)
        self.setPalette(palette)

    def getProcesses(self):
        processes = []

        for proc in psutil.process_iter():
            processes.append(proc.as_dict(attrs=['pid', 'name']))

        processes.sort(key=lambda process: (process['name'].lower(), process['pid']))
        return processes

    def refreshProcesses(self):
        self.processListBox.clear()
        processes = self.getProcesses()

        for process in processes:
            name = process['name']
            pid = process['pid']
            self.processListBox.addItem(f'{name} (PID {pid})')

    def beginScan(self):
        if self.worker:
            self.stopEvent.set()
            self.scanButton.setEnabled(False)
            return

        items = self.processListBox.selectedItems()

        if not items:
            QMessageBox.warning(self, TITLE, 'Please choose a process from the list!')
            return

        process = items[0].text()[:-1].split(' ')
        self.processName = ' '.join(process[:-2])
        pid = int(process[-1])
        multifiles = self.multifileBox.text().split()

        if not multifiles:
            QMessageBox.warning(self, TITLE, 'Please choose some multifiles to target!')
            return

        multifile_names = '\n'.join([f'- {multifile}' for multifile in multifiles])
        question = f'Do you really want to scan {self.processName} for the following multifiles?\n\n{multifile_names}'

        if QMessageBox.question(self, TITLE, question, QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No) != QMessageBox.Yes:
            return

        self.count = 0

        self.setWindowTitle(f'{TITLE} - Scanning...')
        self.scanButton.setText('Stop')

        self.worker = ScanWorker(self, pid, multifiles)
        self.worker.signals.finished.connect(self.scanOver)
        self.worker.signals.error.connect(self.errorOccurred)
        self.worker.signals.progress.connect(self.reportProgress)

        self.threadPool.start(self.worker)

    def scanOver(self):
        self.worker = None
        self.stopEvent.clear()

        self.scanButton.setText('Scan')
        self.scanButton.setEnabled(True)
        self.setWindowTitle(TITLE)
        QMessageBox.information(self, TITLE, f'Scan complete!\n\n{self.count} password{"s have" if self.count != 1 else " has"} been found.')

    def errorOccurred(self, error):
        exc, value, message = error
        QMessageBox.critical(self, TITLE, f'An error has occurred while trying to scan this process!\n\n{exc} {value}\n\n{message}')

    def reportProgress(self, multifile, password):
        self.count += 1
        index = self.resultTable.rowCount()

        self.resultTable.insertRow(index)

        for i, value in enumerate((self.processName, multifile, password)):
            self.resultTable.setItem(index, i, QTableWidgetItem(value))
