import nmap
import tkinter as tk
from tkinter import ttk
from threading import Thread
from tkinter import filedialog
import datetime
import socket


class NetworkScanner(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Network and Port Scanner by Antonio Cufari ver. 1.0")
        self.geometry("700x700")

        self.label_ip = tk.Label(self, text="Inserisci l'indirizzo o intervallo IP/Dominio: (es. 192.168.1.1/24 o Dominio)")
        self.label_ip.pack(pady=5)

        self.ip_entry = tk.Entry(self)
        self.ip_entry.pack(pady=5)

        self.label_ports = tk.Label(self, text="Inserisci l'intervallo delle porte (es. 1-1024):")
        self.label_ports.pack(pady=5)

        self.ports_entry = tk.Entry(self)
        self.ports_entry.pack(pady=5)

        self.scan_button = tk.Button(self, text="Scansione", command=self.start_scan)
        self.scan_button.pack(pady=5)

        self.progress = ttk.Progressbar(self, length=600, mode='indeterminate')
        self.progress.pack(pady=5)

        self.save_button = tk.Button(self, text="Salva Risultati", command=self.save_results, state=tk.DISABLED)
        self.save_button.pack(pady=5)

        self.result_text = tk.Text(self, height=30, width=80)
        self.result_text.pack(pady=5)

        self.scanner = nmap.PortScanner()

    def start_scan(self):
        ip_or_domain = self.ip_entry.get()
        ports = self.ports_entry.get()
        if not ports:
            ports = '1-1024'  # Intervallo predefinito
        self.progress.start()
        self.result_text.delete(1.0, tk.END)
        self.save_button.config(state=tk.DISABLED)
        Thread(target=self.scan_network, args=(ip_or_domain, ports)).start()

    def scan_network(self, ip_or_domain, ports):
        try:
            self.scanner.scan(ip_or_domain, ports, arguments='-O')
            self.progress.stop()
            results = ""
            for host in self.scanner.all_hosts():
                results += f'\nHost: {host} ({self.scanner[host].hostname()})\n'
                results += f'Stato: {self.scanner[host].state()}\n'
                if 'osclass' in self.scanner[host]:
                    results += 'Sistema Operativo:\n'
                    for osclass in self.scanner[host]['osclass']:
                        results += f" - {osclass['osfamily']} {osclass['osgen']} ({osclass['accuracy']}% accurate)\n"
                if 'mac' in self.scanner[host]['addresses']:
                    results += f'MAC Address: {self.scanner[host]["addresses"]["mac"]}\n'
                for proto in self.scanner[host].all_protocols():
                    results += f'\nProtocollo: {proto}\n'
                    lport = self.scanner[host][proto].keys()
                    for port in lport:
                        results += f'Porta: {port}\tStato: {self.scanner[host][proto][port]["state"]}\n'
            self.result_text.insert(tk.END, results)
            self.save_button.config(state=tk.NORMAL)
            self.scan_results = results
            self.log_scan(ip_or_domain, ports, results)
        except Exception as e:
            self.progress.stop()
            self.result_text.insert(tk.END, f"Errore durante la scansione: {str(e)}\n")

    def save_results(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".txt",
                                                 filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if file_path:
            with open(file_path, 'w') as file:
                file.write(self.scan_results)

    def log_scan(self, ip_or_domain, ports, results):
        with open('scan_log.txt', 'a') as log_file:
            log_file.write(f"Scan date: {datetime.datetime.now()}\n")
            log_file.write(f"IP/Dominio: {ip_or_domain}\n")
            log_file.write(f"Ports: {ports}\n")
            log_file.write(f"Results:\n{results}\n")
            log_file.write("=" * 60 + "\n")


if __name__ == "__main__":
    app = NetworkScanner()
    app.mainloop()
