import tkinter as tk
from tkinter import ttk
import re

### Sample Inputs ###

# JSON
# {"username1":"aBcDeFgH","ip1":"192.168.1.1","address":"Random St, Somewhere, 12345","age":"29","description":"A random string to simulate a text field.","ip2":"10.0.0.2","contact":"John Doe","email":"johndoe@example.com","ip3":"172.16.254.1","zipcode":"98765","city":"Sample City","country":"Neverland","active":true,"height":"6'1\"","ip4":"8.8.8.8","random_value1":"vLsZb88HxcKPlDoGsB9ctQG7ZoL4y1LXY46hFwFb","random_value2":"yNgPTg9A1vsXt5Wz4rKmUtTZ2OjHzDNitwFXvUkj","password":"qwerty12345","ip5":"192.0.2.0","status":"active","last_login":"2024-12-29T10:30:00Z","notes":"This is a note.","ip6":"203.0.113.76","temperature":"72°F","ip7":"192.168.100.5","ip8":"127.0.0.1","random_text1":"xT92g8Jg32S9I0Mw7bWf9D0OoVpYJ3tM8Dk","ip9":"64.233.160.0","country_code":"+1","random_text2":"aZn6qQUpK5S1Bc9t7PjU6X3rJ5h04Ve","ip10":"198.51.100.14","web_url":"https://example.com","phone_number":"+1-800-555-1212"}


class MultiTool:

    def __init__(self, root):

        # variables
        self.root = root
        self.ip_addresses = []

        # text widgets
        self.input_field = tk.Text(root)
        self.ip_scan_output = tk.Text(root)

        # buttons
        self.format_data_button = tk.Button(
            root, text="Format Input", command=self.format_data
        )
        self.scan_ips_button = tk.Button(
            root, text="Scan IPs", command=self.scan_ip_addresses
        )

        # tags
        self.highlight_tag = "highlight"
        self.input_field.tag_configure(self.highlight_tag, foreground="red")

        # display widgets (geometry manager)
        self.input_field.pack()  # use a geometry manager to display widgets
        self.format_data_button.pack()
        self.scan_ips_button.pack()
        self.ip_scan_output.pack()
        
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill="both", expand=True)

    def check_for_ip_addresses(self, text):

        ipv4_regex = r"(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)"
        ipv6_regex = ""

        ipv4_addresses = re.findall(ipv4_regex, text)
        ipv6_addresses = re.findall(ipv6_regex, text)

        self.ip_addresses = ipv4_addresses  # + ipv6_addresses
        self.highlight_ip_addresses()

    def highlight_ip_addresses(self):

        if self.ip_addresses:
            for ip in self.ip_addresses:
                start_pos = self.input_field.search(
                    ip, "1.0", stopindex=tk.END, nocase=True
                )
                if start_pos:
                    end_pos = f"{start_pos}+{len(ip)}c"
                    self.input_field.tag_add(self.highlight_tag, start_pos, end_pos)

    def scan_ip_addresses(self):
        # ip_addresses = check_for_ip_addresses(ip_scan_output.get("1.0", "end"))
        if self.ip_addresses:
            from ip_lookup import lookup

            for ip_address in self.ip_addresses:
                lookup(ip_address, self.ip_scan_output)
                self.ip_scan_output.insert(
                    "end", "\n"
                )  # new line padding after each scan

    def format_data(self):
        self.check_for_ip_addresses(self.input_field.get("1.0", "end"))
        pass


# Create the main window
root = tk.Tk()
root.title("Multitool")

# Start the Tkinter main loop
tool = MultiTool(root)
root.mainloop()
