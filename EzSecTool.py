#iImport necessary libraries
import tkinter as tk
from tkinter import messagebox
from tkinter import filedialog
from tkinter import ttk
from tkinter import *
import nmap
from scapy.all import *
import subprocess
import sublist3r
import ipaddress


class EzSecGUI:
    def __init__(self):
        #Create GUI for main tool page.
        self.root = tk.Tk()
        self.root.title("EzSec Tool")
        self.root.geometry('500x200')

        self.lbl = tk.Label(self.root, text=" Please choose the tool you need to run.", font=('Arial', 18))
        self.lbl.pack(padx=20, pady=10)

        self.buttonFrame = tk.Frame(self.root)
        self.buttonFrame.columnconfigure(0, weight=1)
        self.buttonFrame.columnconfigure(1, weight=1)

        nmap_logo = tk.PhotoImage(file=r"C:\Python\Logos\nmap-logo.png")
        sublist3r_logo = tk.PhotoImage(file=r"C:\Python\Logos\sublist3r.png")
        hashcat_logo = tk.PhotoImage(file=r"C:\Python\Logos\hashcat-logo.png")
        scapy_logo = tk.PhotoImage(file=r"C:\Python\Logos\scapy-logo.png")
        # Creating buttons for the user to click.
        self.nmapButton = tk.Button(self.buttonFrame, text="NMAP", font=('Arial', 16), image=nmap_logo,
                                    compound=tk.LEFT, command=self.nmap_button)
        self.sublist3rButton = tk.Button(self.buttonFrame, text="Sublist3r", font=('Arial', 16),
                                          image=sublist3r_logo, compound=tk.LEFT, command=self.sublist3r_button)
        self.hashCatButton = tk.Button(self.buttonFrame, text="Hashcat", font=('Arial', 16), image=hashcat_logo,
                                       compound=tk.LEFT, command=self.hashcat_button)
        self.scapyButton = tk.Button(self.buttonFrame, text="Scapy", font=('Arial', 16), image=scapy_logo,
                                     compound=tk.LEFT, command=self.scapy_button)

        self.nmapButton.grid(row=0, column=0, sticky=tk.W+tk.E)
        self.sublist3rButton.grid(row=0, column=1, sticky=tk.W+tk.E)
        self.hashCatButton.grid(row=1, column=0, sticky=tk.W+tk.E)
        self.scapyButton.grid(row=1, column=1, sticky=tk.W+tk.E)

        self.buttonFrame.pack(fill='x')
        self.root.mainloop()

    def nmap_button(self):
        #Create variables that need to be passed to the nmap_Submit method.
        ip_var = tk.StringVar()
        ip = ip_var.get()
        ip_var.set("")
        #Create GUI window for nmap
        nmapwindow = tk.Toplevel()
        nmapwindow.title("NMAP Port Scanner")
        nmapwindow.geometry('500x100')
        nmaplblip = tk.Label(nmapwindow, text='Enter the target IP you want to scan:', font=('Arial', 14))
        nmaplblip.grid(row=0, column=0)
        nmapentryip = tk.Entry(nmapwindow, textvariable=ip_var, font=('Arial', 14))
        nmapentryip.grid(row=0, column=1)

        def nmap_submit(ip_var):
            target = ip_var.get()
            
            scanner = nmap.PortScanner()
            try:
                targets = scanner.scan(hosts=target, arguments='-P')
                port_result_dict = {}
                output_path = "C:\\EzSec\\Output\\Nmap"
                #Creates the output folder if it does not already exists
                os.makedirs(output_path, exist_ok=True)
                output_filename = 'nmap_output.txt'
                output_filepath = os.path.join(output_path, output_filename)

                #Writes results to the output file
                with open(output_filepath, 'w') as output_file:
                    output_file.write(f"Target IP/Range: {target}\n")
                    for target_ip, info in targets['scan'].items():
                        hostname = target_ip
                        port_results = []

                        if 'tcp' in info:
                            for port, data in info['tcp'].items():
                                state = data['state']
                                port_results.append(f'\tPort {port} is {state}.')

                            else:
                                port_results.append((f'\tNo TCP information available.'))

                        port_result_dict[hostname] = port_results

                    for hostname, post_results in port_result_dict.items():
                        output_file.write(f'On IP: {hostname}\n')
                        for port_result in port_results:
                            output_file.write(f'{port_result}\n')

                messagebox.showinfo("Info",
                                    "Results have been written to nmap_output.txt in C:\\EzSec\\Output\\Nmap")
            except nmap.PortScannerError as e:
                targets = target


        nmapsubmit = tk.Button(nmapwindow, text="Submit", font=('Arial', 14), compound=tk.LEFT,
                               command=lambda: nmap_submit(ip_var))
        nmapsubmit.grid(row=3, column=1)



    def scapy_button(self):
        #Create Scapy window GUI
        scapy_window = tk.Toplevel()
        scapy_window.title("Scapy Packet Sniffer")
        scapy_window.geometry('600x150')
        global lbl_file_explorer
        lbl_file_explorer = tk.Label(scapy_window,
                                     text="Chosen file path will show here.")
        lbl_choose_file = tk.Label(scapy_window,
                                   text="Please select a PCAP file to sniff.")
        button_browse = tk.Button(scapy_window,
                                  text="Browse Files",
                                  command=self.browse_files_scapy)
        lbl_sniff = tk.Label(scapy_window,
                             text="After file selection press this button: ")
        button_offline_sniff = tk.Button(scapy_window, text="Sniff PCAP", command=self.offline_sniff)

        lbl_choose_file.grid(row=1, column=1)
        button_browse.grid(row=1, column=2)
        lbl_file_explorer.grid(row=1, column=3)
        button_offline_sniff.grid(row=5, column=2)
        lbl_sniff.grid(row=5, column=1)

    #Method for browse file functionality in scapy.
    def browse_files_scapy(self):
        self.file_name = filedialog.askopenfilename(initialdir="/",
                                                   title="Select a File",
                                                   filetypes=(("Pcap files",
                                                               "*.pcap*"),
                                                              ("all files",
                                                               "*.*")))
        lbl_file_explorer.config(text=f'Selected file: {self.file_name}')

    def hashcat_button(self):
        global lbl_hashcat_hashfile
        global lbl_hashcat_wordfile
        global lbl_hashcat_folder

        #hashTypeEntry = tk.StringVar() Carlos I think we can remove this
        #Create GUI Window for hashcat
        selected_hash = tk.StringVar()
        hashcat_window = tk.Toplevel()
        hashcat_window.title("Hashcat ")
        hashcat_window.geometry('700x400')

        lbl_hashcat_type = tk.Label(hashcat_window,
                                    text="Please enter the hash type:")
        lbl_hashfile = tk.Label(hashcat_window,
                                text="Please select the file hash file.")
        lbl_hashfile_output = tk.Label(hashcat_window,
                                       text="Please select where you want the output to be stored.")
        lbl_word_list_file = tk.Label(hashcat_window,
                                      text="Please select the word list file to be used.")
        hashfile_button_browse = tk.Button(hashcat_window,
                                           text="Select Hash File",
                                           command=self.browse_files_hashcat_hashfile)
        hashfile_output_button_browse = tk.Button(hashcat_window,
                                                  text="Select Output Folder",
                                                  command=self.browse_folder)
        word_list_button_browse = tk.Button(hashcat_window,
                                            text="Select Word List File",
                                            command=self.browse_files_hashcat_wordfile)
        #radio_name = tk.StringVar(hashcat_window, "1") Carlos I think we can delete this too
        lbl_hashcat_folder = tk.Label(hashcat_window,
                                       text="Your chosen output folder path will show here.")
        lbl_hashcat_hashfile = tk.Label(hashcat_window,
                                     text="Your chosen hash file will show here.")
        lbl_hashcat_wordfile = tk.Label(hashcat_window,
                                      text="Your chosen word list file will show here.")
        combo = ttk.Combobox(hashcat_window, textvariable=selected_hash)
        combo['values'] = ('SHA256', 'SHA1', 'SHA512', 'MD5', 'NTLM')
        combo.set('SHA1')

        crack_button = tk.Button(hashcat_window, text="Crack hash", font=('Arial', 14), compound=tk.LEFT,
                                 command=lambda: hashcat_crack())

        lbl_hashcat_type.grid(row=0, column=1)
        #hashType.grid(row=0, column=2)
        combo.grid(row=0, column=2)
        lbl_hashfile.grid(row=2, column=1)
        lbl_hashfile_output.grid(row=3, column=1)
        lbl_word_list_file.grid(row=4, column=1)
        lbl_hashcat_folder.grid(row=3, column=3)
        lbl_hashcat_hashfile.grid(row=2, column=3)
        lbl_hashcat_wordfile.grid(row=4, column=3)
        hashfile_button_browse.grid(row=2, column=2)
        hashfile_output_button_browse.grid(row=3, column=2)
        word_list_button_browse.grid(row=4, column=2)
        crack_button.grid(row=5, column=1)
        hashfile_string = lbl_hashcat_hashfile

        #Dictionary to store vaslues for the hashes. These hash values correlate with the hash and are needed by Hashcat.
        hash_modes = {"SHA1": "100",
                      "SHA256": "1400",
                      "SHA512": "1700",
                      "MD5": "0",
                      "NTLM": "5"}

        def hashcat_crack():
            hashTypeEntry = selected_hash.get()
            hash_mode_value = hash_modes[hashTypeEntry]
            hashmode = hash_mode_value
            hashfile = hashfile_var
            hashfolder = folder_path_var + "/output.txt"
            hashwordfile = word_file_var

            print(f"The hashmode is: {hashmode}. The hash file is: {hashfile}. The hash folder is: {hashfolder}. "
                  f"The hash wordfile is: {hashwordfile}.")

            hashcat_run = (f"hashcat -m {hashmode} {hashfile} {hashwordfile} --outfile {hashfolder} --show ")

            try:
                output = subprocess.check_output(hashcat_run, shell=True)
                print(output.decode("utf-8"))
                messagebox.showinfo("Info", "Results have been written to output.txt in " + folder_path_var)

            except subprocess.CalledProcessError as e:
                print(f"Error running hashcat command: {e}")



    def browse_files_hashcat_hashfile(self):
        global hashfile_var
        self.hash_file_name = filedialog.askopenfilename(initialdir="/",
                                                    title="Select a File",
                                                    filetypes=(("All files",
                                                                "*.*"),
                                                                ("all files",
                                                                 "*.*")))
        lbl_hashcat_hashfile.config(text=f'Selected hash file: {self.hash_file_name}')
        hashfile_var = self.hash_file_name

    def browse_files_hashcat_wordfile(self):
        global word_file_var
        self.word_file_name = filedialog.askopenfilename(initialdir="/",
                                                    title="Select a File",
                                                    filetypes=(("All files",
                                                                "*.*"),
                                                                ("all files",
                                                                 "*.*")))
        lbl_hashcat_wordfile.config(text=f'Selected word file: {self.word_file_name}')
        word_file_var = self.word_file_name

    def offline_sniff(self):
        if hasattr(self, 'file_name') and self.file_name:
            #Error checking to confirm user picks a pcap file
            if not self.file_name.lower().endswith(".pcap"):
                messagebox.showerror("Error", "Selected file must be a .pcap file.")
                return
            #Denotes output path and creates folder if it does not exist
            output_path = "C:\\EzSec\\Output\\Scapy"
            os.makedirs(output_path, exist_ok=True)
            output_filename=os.path.join(output_path, f"{os.path.basename(self.file_name)}_results.txt")

            #Writes results to file
            original_stdout = sys.stdout
            try:
                with open(output_filename, 'w') as file:
                    sys.stdout=file
                    sniff(offline=self.file_name, prn=lambda x: x.summary())
            except Exception as e:
                print(f"Error: {e}")
            finally:
                sys.stdout = original_stdout

            messagebox.showinfo("Info", "The results file is located in: C:\EzSec\Output\Scapy.")
        else:
            messagebox.showerror("Error", "You must select a PCAP file first.")

    #Browse folder method used for hashcat.
    def browse_folder(self):
        global folder_path_var
        self.folder_name = filedialog.askdirectory(initialdir="/",
                                                   title="Select a Folder")
        lbl_hashcat_folder.config(text=f'Selected folder: {self.folder_name}')
        folder_path_var = self.folder_name



    def sublist3r_button(self):
        #Creates GUI for sublsit3r.
        sublistwindow = tk.Toplevel()
        sublistwindow.title("Sublist3r")
        sublistwindow.geometry('500x100')
        domain_var = tk.StringVar()
        domain = domain_var.get()
        domain_var.set("")

        domain_label = tk.Label(sublistwindow, text="Enter the domain you want to scan.", font=('Arial', 14))
        domain_label_input = tk.Entry(sublistwindow, textvariable=domain_var, font=('Arial', 14))
        domain_scan = tk.Button(sublistwindow, text="Scan", font=('Arial', 14), compound=tk.LEFT,
                                command=lambda: self.sublist3r_submit(domain_var))
        domain_label.grid(row=0, column=0)
        domain_label_input.grid(row=0, column=1)
        domain_scan.grid(row=1, column=1)

    def sublist3r_submit(self, domain_var):
        domain_name = domain_var.get()
        #Denotes output path.
        output_path = "C:\\EzSec\\Output\\Sublist3r"

        #Creates folder if it does not exist. Also creates variable that stores the full file path including the name that is passed to the sublist3r command.
        os.makedirs(output_path, exist_ok=True)
        output_filename = os.path.join(output_path, f"{domain_name}.txt")

        subdomains = sublist3r.main(domain_name, 40, output_filename, ports=None, silent=False, verbose=False,
                                    enable_bruteforce=False, engines=None)

        messagebox.showinfo("Info", "The output file is located in: C:\EzSec\Output\Sublist3r")


EzSecGUI()
