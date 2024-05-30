import platform
import subprocess
import re
from datetime import datetime
import socket
import tkinter as tk
from tkinter import simpledialog, Toplevel, Listbox, Scrollbar, messagebox
from PIL import Image, ImageTk
from scapy.all import ARP, Ether, srp
import random
import xml.etree.ElementTree as ET

mac_addresses_full = {}
original_mac_addresses = {}

def load_mac_vendor_mappings(xml_file):
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()
        namespace = root.tag.split('}')[0] + '}'
        for mapping in root.findall(namespace + 'VendorMapping'):
            mac_prefix = mapping.attrib['mac_prefix']
            vendor_name = mapping.attrib['vendor_name']
            mac_addresses_full[mac_prefix] = vendor_name
    except Exception as e:
        print(f"Error loading MAC address vendor mappings: {e}")

def my_info_show():
    info = """
    Faizan Pervaz
    20i-0565
    CS B
    BS Computer Science
    ISB Campus
    Ethical Hacking
    Date and Time: {}
    """.format(datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
    tk.messagebox.showinfo("Developer Information", info)

def network_info_cmd():
    if 'ifconfig' in subprocess.getoutput('which ifconfig'):
        return 'ifconfig'
    elif 'ip' in subprocess.getoutput('which ip'):
        return 'ip addr'
    else:
        raise OSError("Neither 'ifconfig' nor 'ip' found on the system.")

def display_current_mac():
    try:
        command = network_info_cmd()
        output = subprocess.check_output(command.split()).decode('utf-8')
        if command == 'ifconfig':
            mac_address = re.search(r"ether (\S+)", output).group(1)
        else:  # 'ip addr' command output parsing
            mac_address = re.search(r"link/ether (\S+)", output).group(1)
        tk.messagebox.showinfo("MAC Address", f"MAC Address: {mac_address}")
    except subprocess.CalledProcessError as e:
        tk.messagebox.showerror("Error", f"An error occurred while trying to get MAC address: {e}")
    except Exception as e:
        tk.messagebox.showerror("Error", f"An unexpected error occurred: {e}")

def get_original_mac(interface):
    try:
        command = network_info_cmd()
        output = subprocess.check_output(command.split()).decode('utf-8')
        if command == 'ifconfig':
            match = re.search(r"ether (\S+)", output)
        else:  
            match = re.search(r"link/ether (\S+)", output)
        
        if match:
            return match.group(1)
        else:
            tk.messagebox.showerror("Error", "MAC address not found.")
    except subprocess.CalledProcessError as e:
        tk.messagebox.showerror("Error", f"An error occurred while trying to get original MAC address: {e}")
    except Exception as e:
        tk.messagebox.showerror("Error", f"An unexpected error occurred: {e}")

def change_mac_linux(interface, new_mac):
    try:
        if interface not in original_mac_addresses:
            original_mac_addresses[interface] = get_original_mac(interface)

        command_down = ["sudo", "ifconfig", interface, "down"]
        subprocess.run(command_down, check=True)
        
        command_change = ["sudo", "ifconfig", interface, "hw", "ether", new_mac]
        subprocess.run(command_change, check=True)
        
        command_up = ["sudo", "ifconfig", interface, "up"]
        subprocess.run(command_up, check=True)
        
        tk.messagebox.showinfo("Success", "MAC address has been changed successfully.")
    except subprocess.CalledProcessError as e:
        tk.messagebox.showerror("Error", f"An error occurred while trying to change MAC address: {e}")
    except Exception as e:
        tk.messagebox.showerror("Error", f"An unexpected error occurred: {e}")

def apply_random_mac_address():
    interface = simpledialog.askstring("Interface", "Enter the network interface name (e.g., wlan0):")
    if interface:
        random_mac = ':'.join(['{:02x}'.format(random.randint(0x00, 0xff)) for _ in range(6)])
        change_mac_linux(interface, random_mac)

def reset_to_original_mac():
    interface = simpledialog.askstring("Interface", "Enter the network interface name (e.g., wlan0):")
    if interface:
        if interface in original_mac_addresses:
            original_mac = original_mac_addresses[interface]
            change_mac_linux(interface, original_mac)
        else:
            tk.messagebox.showinfo("Info", "Original MAC address not found. No changes made.")

def select_and_change_mac():
    def on_select(evt):
        if not lb.curselection():
            tk.messagebox.showerror("Error", "No MAC address selected.")
            return

        index = int(lb.curselection()[0])
        selected_mac = list(filtered_mac_addresses.keys())[index]
        vendor_name = filtered_mac_addresses[selected_mac]
        interface = simpledialog.askstring("Interface", "Enter the network interface name (e.g., wlan0):")
        if interface:
            change_mac_linux(interface, selected_mac)
            tk.messagebox.showinfo("MAC Address Changed", f"MAC address has been changed to {selected_mac} ({vendor_name})")
            top.destroy()

    def on_search():
        search_text = search_entry.get().lower()
        filtered_mac_addresses.clear()
        for mac, vendor in mac_addresses_full.items():
            if search_text in vendor.lower():
                filtered_mac_addresses[mac] = vendor
        update_listbox()

    def update_listbox():
        lb.delete(0, tk.END)
        for mac, vendor in filtered_mac_addresses.items():
            lb.insert(tk.END, f"{mac} - {vendor}")

    top = Toplevel()
    top.title("Select MAC Address")

    search_frame = tk.Frame(top)
    search_frame.pack(fill=tk.X)
    search_label = tk.Label(search_frame, text="Search Vendor Name:")
    search_label.pack(side=tk.LEFT, padx=(5, 0))
    search_entry = tk.Entry(search_frame)
    search_entry.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
    search_button = tk.Button(search_frame, text="Search", command=on_search)
    search_button.pack(side=tk.LEFT, padx=(0, 5))

    lb = Listbox(top, width=50, height=20)
    lb.pack(padx=5, pady=5, fill=tk.BOTH, expand=True)
    scrollbar = Scrollbar(top, orient=tk.VERTICAL)
    scrollbar.config(command=lb.yview)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    filtered_mac_addresses = mac_addresses_full.copy()
    update_listbox()

    lb.bind('<<ListboxSelect>>', on_select)


def scan_network(network_cidr):
    """
    Scans the network for devices using ARP requests and attempts to resolve their hostnames.
    :param network_cidr: The network CIDR notation (e.g., '192.168.1.0/24') to scan.
    """
    packet = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=network_cidr)
    result, _ = srp(packet, timeout=3, verbose=0)
    
    mac_addresses = []

    for _, received in result:
        mac_addresses.append(received.hwsrc)

    return mac_addresses

def scan_network_and_display():
    try:
        local_ip = socket.gethostbyname(socket.gethostname())
        network_cidr = '.'.join(local_ip.split('.')[:3]) + '.0/24'
    except Exception:
        network_cidr = '192.168.1.0/24'  # Fallback CIDR, change as needed

    mac_addresses = scan_network(network_cidr)

    top = Toplevel()
    top.title("Scanned MAC Addresses")
    lb = Listbox(top, width=50, height=20)
    lb.pack(padx=5, pady=5, fill=tk.BOTH, expand=True)
    scrollbar = Scrollbar(top, orient=tk.VERTICAL)
    scrollbar.config(command=lb.yview)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    for mac in mac_addresses:
        lb.insert(tk.END, mac)
    lb.config(yscrollcommand=scrollbar.set)
    
def display_welcome_screen():
    welcome_root = tk.Tk()
    welcome_root.title("Welcome to MAC Address Spoofing Tool")
    welcome_root.geometry("800x600")  
    welcome_root.resizable(False, False)

    background_image = Image.open("hacker.jpeg")
    background_image = background_image.resize((800, 600))  
    background_photo = ImageTk.PhotoImage(background_image)
    
    background_label = tk.Label(welcome_root, image=background_photo)
    background_label.place(x=0, y=0, relwidth=1, relheight=1)
    
    welcome_frame = tk.Frame(welcome_root, bg="#ffffff", bd=5)
    welcome_frame.place(relx=0.5, rely=0.5, anchor='center')

    welcome_label = tk.Label(welcome_frame, text="Welcome to MAC Address Spoofing Tool", font=("Arial", 18), bg="#ffffff")
    welcome_label.pack(pady=(20, 30))

    continue_button = tk.Button(welcome_frame, text="Continue", command=welcome_root.destroy, font=('Arial', 14), padx=15, pady=8)
    continue_button.pack()

    welcome_root.mainloop()

def second_screen():
    display_welcome_screen()

    root = tk.Tk()
    root.title("MAC Address Spoofing Tool")
    root.geometry("800x600")  
    root.resizable(False, False)

    load_mac_vendor_mappings("vendorMacs.xml")
    
    background_image = Image.open("hacker.jpeg")
    background_image = background_image.resize((800, 600))  
    background_photo = ImageTk.PhotoImage(background_image)

    background_label = tk.Label(root, image=background_photo)
    background_label.place(x=0, y=0, relwidth=1, relheight=1)

    frame = tk.Frame(root, bg="#ffffff", bd=5)
    frame.place(relx=0.5, rely=0.5, anchor='center')

    title_label = tk.Label(frame, text="MAC Address Spoofing Tool", font=("Arial", 18), bg="#ffffff")
    title_label.pack(pady=(20, 30))

    button_font = ('Arial', 14)  

    left_buttons_frame = tk.Frame(frame, bg="#ffffff")
    left_buttons_frame.pack(side=tk.LEFT, padx=20)

    right_buttons_frame = tk.Frame(frame, bg="#ffffff")
    right_buttons_frame.pack(side=tk.RIGHT, padx=20)

    tk.Button(left_buttons_frame, text="Display Developer Info", command=my_info_show, font=button_font, padx=15, pady=8).pack(fill=tk.X, pady=10)
    tk.Button(left_buttons_frame, text="Display Current MAC", command=display_current_mac, font=button_font, padx=15, pady=8).pack(fill=tk.X, pady=10)
    tk.Button(left_buttons_frame, text="Change MAC From Manufacturer", command=select_and_change_mac, font=button_font, padx=15, pady=8).pack(fill=tk.X, pady=10)

    tk.Button(right_buttons_frame, text="Network Scanning", command=scan_network_and_display, font=button_font, padx=15, pady=8).pack(fill=tk.X, pady=10)
    tk.Button(right_buttons_frame, text="Assign Random MAC Address", command=apply_random_mac_address, font=button_font, padx=15, pady=8).pack(fill=tk.X, pady=10)
    tk.Button(right_buttons_frame, text="Reset to Original MAC Address", command=reset_to_original_mac, font=button_font, padx=15, pady=8).pack(fill=tk.X, pady=10)

    root.mainloop()
	

if __name__ == "__main__":
    second_screen()
