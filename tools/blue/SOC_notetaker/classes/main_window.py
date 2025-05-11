import os, re, subprocess, sys, pyperclip
from PyQt5 import QtWidgets
from PyQt5.QtCore import QThreadPool, QRunnable, pyqtSignal, QObject
from ui_elements.main_window import Ui_MainWindow
from classes.escalation_template_dialog import EscalationTemplateDialog
from bs4 import BeautifulSoup
import requests
#from PyQt5.QtGui import QStandardItemModel, QStandardItem

# Signals class for worker threads
class WorkerSignals(QObject):
    result = pyqtSignal(str)

# Worker class for scanning IPs asynchronously
class ScanIPWorker(QRunnable):
    def __init__(self, ip_address, lookup_function):
        super().__init__()
        self.ip_address = ip_address
        self.lookup_function = lookup_function
        self.signals = WorkerSignals()

    def run(self):
        scan_results = self.lookup_function(self.ip_address)
        for result in scan_results:
            self.signals.result.emit(result)

class MainWindow(QtWidgets.QMainWindow, Ui_MainWindow):
    def __init__(self):
        super().__init__()
        self.setupUi(self)
        self.setWindowTitle("SOC Notetaker")
        self.threadpool = QThreadPool()  # Initialize thread pool

        # Variables
        self.ip_addresses = []

        # Connect button actions
        self.scanIPButton.clicked.connect(self.scan_ip_addresses)
        #self.filterIPButton.clicked.connect(self.filter_ips)
        self.errorCodeBtn.clicked.connect(self.scan_error_code)
        self.hashScanButton.clicked.connect(self.scan_hash)
        self.SaveAndClearNotesButton.clicked.connect(self.save_and_close_notes)
        self.CopyNotesButton.clicked.connect(self.copy_notes)
        self.EscalationTemplatesList.itemClicked.connect(self.open_escalation_template)
        
        # Get the files from a directory (change path as needed)
        directory = "assets/escalation_templates"
        files = [f for f in os.listdir(directory) if os.path.isfile(os.path.join(directory, f))]
        #self.model = QStandardItemModel()
        # Populate the model with the files
        for file in files:
            self.EscalationTemplatesList.addItem(file) 
            
    def open_escalation_template(self, item):
        file_name = item.text()  # Get the selected file name
        file_path = os.path.join("assets/escalation_templates", file_name)  # Full path

        if os.path.exists(file_path):  # Ensure file exists
            # Open the EscalationTemplateDialog with the file name and path
            dialog = EscalationTemplateDialog(self, file_name, file_path)
            dialog.exec_()  # Show the dialog modally
        else:
            print(f"File not found: {file_path}")

    def scan_ip_addresses(self):
        from tools.ip_scanner import lookup
        
        self.filter_ips()
        self.ipAddressOutput.setText('')

        for ip_address in self.ip_addresses:
            worker = ScanIPWorker(ip_address, lookup)
            worker.signals.result.connect(self.update_scan_results)
            self.threadpool.start(worker)

    def update_scan_results(self, result):
        self.ipAddressOutput.append(result)

    def filter_ips(self):
        text = self.ipAddressInput.toPlainText()
        ipv4_regex = r"(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)"
        ipv6_regex = r"(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))"

        # Find all valid IPs
        ipv4_addresses = re.findall(ipv4_regex, text)
        ipv6_addresses = [match.group() for match in re.finditer(ipv6_regex, text)]
        
        self.ip_addresses = ipv4_addresses + ipv6_addresses

        # Update the output field with only the valid IPs
        if self.ip_addresses:
            self.ipAddressInput.setText("\n".join(self.ip_addresses))
        else:
            self.ipAddressOutput.setText("No valid IPs found.")

    def scan_error_code(self):
        error_code = self.errorCodeInput.text()
        if self.errorCodeDropdown.currentIndex() == 1:
            error_lookup_tool = 'tools/error_lookup.exe'
            result = subprocess.run([error_lookup_tool, error_code], capture_output=True, text=True)  # Use `text=True` for automatic decoding
            output = result.stdout 
            self.errorCodeOutput.setText(output)
        elif self.errorCodeDropdown.currentIndex() == 0:
            url = f"https://login.microsoftonline.com/error?code={error_code}"
            response = requests.get(url)

            soup = BeautifulSoup(response.content, "html.parser")

            # Find the first table on the page
            table = soup.find("table")
            formatted_text = []

            # Loop through rows in the table and print key-value pairs
            for row in table.find_all("tr"):
                cells = row.find_all("td")
                if len(cells) == 2:
                    key = cells[0].get_text(strip=True)
                    value = cells[1].get_text(strip=True)
                    formatted_text.append(f"{key}: {value}")
            self.errorCodeOutput.setText("\n".join(formatted_text))
            
        
    def scan_hash(self):
        self.hashOutput.setText("")
        from tools.hash_lookup import hash_lookup
        hash = self.hashInput.text()
        output = hash_lookup(hash)
        for string in output:
            print(string)
            self.hashOutput.append(string)
            
    def save_and_close_notes(self):
        os.makedirs("assets/case_notes", exist_ok=True)
        note_title = self.NoteTitleInput.text()
        note_body = self.NoteBodyInput.toPlainText()

        # Debugging: Print out the inputs
        print(f"Note Title: {note_title}")
        print(f"Note Body: {note_body}")
        
        if note_title:
            # Define regex for characters to remove
            dirty_chars = r"[^a-zA-Z0-9 £$¥.,!?-_]+" # in essence these are actually clean characters, it finds characters that are NOT in this string
            # Replace dirty characters with an empty string
            clean_filename = re.sub(dirty_chars, "", note_title)

            # Full path to the file for debugging
            file_path = f"assets/case_notes/{clean_filename}"

            # Write the file in write mode ("w")
            try:
                with open(file_path, "w", encoding="UTF-8") as note_file:
                    note_file.write(note_body)
            except Exception as e:
                print(f"Error saving file: {e}")

            
            # Clear the input fields
            self.NoteTitleInput.setText("")
            self.NoteBodyInput.setText("")
        else:
            print("Cannot Save File -- TITLE EMPTY")
    
    def copy_notes(self):
        pyperclip.copy(self.NoteBodyInput.toPlainText())