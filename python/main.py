try:
    # for Python2
    from Tkinter import *   ## notice capitalized T in Tkinter
except ImportError:
    # for Python3
    from tkinter import *   ## notice lowercase 't' in tkinter here

from netaddr import *
import tkMessageBox
from pyVim.connect import SmartConnect
import ssl
import os

from vcenter_stig_check import esxi_vcenter
from esxi_stig_checker import esxi_stig
    
class MyFirstGUI:
    def __init__(self, master):
        self.master = master
        master.geometry('350x300')
        master.resizable(False, False)
        master.title("VMWare ESXi STIG Checker")

        label_vcenter_ip = Label(master, text="vCenter IP:")         
        label_vcenter_ip.place(x=0, y=0)
        self.text_vcenter_ip = Entry(master, width=25)
        self.text_vcenter_ip.place(x=80, y=0)

        label_username = Label(master, text="Username:")
        label_username.place(x=0, y=25)
        self.text_username = Entry(master, width=25)
        self.text_username.place(x=80, y=25)

        label_password = Label(master, text="Password:")
        label_password.place(x=0, y=50)
        self.text_password = Entry(master, show="*", width=25)
        self.text_password.place(x=80, y=50)

        button_connect = Button(master, text="Connect", command=self.run_vsphere)
        button_connect.place(x=0, y=75)

        button_close = Button(master, text="Close", command=self.master.destroy)
        button_close.place(x=70, y=75)

        label_esxi_ip = Label(master, text="ESXi IP:")         
        label_esxi_ip.place(x=0, y=110)
        self.text_esxi_ip = Entry(master, width=25)
        self.text_esxi_ip.place(x=80, y=110)

        label_esxi_username = Label(master, text="Username:")
        label_esxi_username.place(x=0, y=135)
        self.text_esxi_username = Entry(master, width=25)
        self.text_esxi_username.place(x=80, y=135)

        label_esxi_password = Label(master, text="Password:")
        label_esxi_password.place(x=0, y=160)
        self.text_esxi_password = Entry(master, show="*", width=25)
        self.text_esxi_password.place(x=80, y=160)

        esxi_button_connect = Button(master, text="Connect", command=self.run_esxi)
        esxi_button_connect.place(x=0, y=185)

        esxi_button_close = Button(master, text="Close", command=self.master.destroy)
        esxi_button_close.place(x=70, y=185)

    def run_vsphere(self):
        if self.text_vcenter_ip.get() == "" or self.text_username.get() == "" or self.text_password.get() == "":
            tkMessageBox.showerror(title="error",message="Fill in all information.",parent=self.master)
        else:
            if valid_ipv4(self.text_vcenter_ip.get()):
                e = esxi_vcenter()
                e.vcenter_ip = self.text_vcenter_ip.get()
                e.vcenter_username = self.text_username.get()
                e.vcenter_password = self.text_password.get()
                e.vcenter_run()
            else:
                tkMessageBox.showerror(title="error",message="Invalid IP Address",parent=self.master)

    def run_esxi(self):
        if self.text_esxi_ip.get() == "" or self.text_esxi_username.get() == "" or self.text_esxi_password.get() == "":
            tkMessageBox.showerror(title="error",message="Fill in all information.",parent=self.master)
        else:
            if valid_ipv4(self.text_esxi_ip.get()):
                e = esxi_stig()
                e.esxi_server = self.text_esxi_ip.get()
                e.esxi_username = self.text_esxi_username.get()
                e.esxi_password = self.text_esxi_password.get()
                e.esxi_run()
            else:
                tkMessageBox.showerror(title="error",message="Invalid IP Address",parent=self.master)
        
print(os.path.dirname(os.path.abspath(__file__)))              
root = Tk()
my_gui = MyFirstGUI(root)
root.mainloop()
