import os
from PyQt5 import QtWidgets
from ui_elements.escalation_template_dialog import Ui_EscalationTemplateDialog

class EscalationTemplateDialog(QtWidgets.QDialog, Ui_EscalationTemplateDialog):
    def __init__(self, parent, file_name, file_path):
        super().__init__(parent)
        self.setupUi(self)

        # Define Variables
        self.directory = "assets/escalation_templates/"
        self.file_name = file_name
        self.file_path = file_path

        # Load Template Title & Body
        self.EscalationTemplateTitle.setText(file_name)
        self.load_content()

        # Connect the Buttons
        self.CloseEscalationTemplateButton.clicked.connect(self.close)
        self.SaveEscalationTemplateButton.clicked.connect(self.save)
        self.SaveAndCloseEscalationTemplateButton.clicked.connect(self.save_and_close)

    def load_content(self):
        try:
            with open(self.file_path, "r", encoding="UTF-8") as file:
                content = file.read()
                self.EscalationTemplateBody.setText(content)
        except Exception as e:
            print(f"Error loading template content: {e}")

    def save(self):
        try:
            # Grab new values
            new_title = self.EscalationTemplateTitle.text()
            new_content = self.EscalationTemplateBody.toPlainText()
            
            # Delete old template
            os.remove(self.file_path)
            
            # Write changes as new file
            with open(self.directory + new_title, "w", encoding="UTF-8") as file:
                file.write(new_content)
                
        except Exception as e:
            print(f"Failed while saving template: {e}")
            
    def save_and_close(self):
        self.save()
        self.close()