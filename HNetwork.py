#!/usr/bin/env python3

# Python script to automate hosted networks on Windows alongside with other functions

# KEY POINTS AND REPETITIVE COMMANDS
# (Check = True): Ensures that if the command issued by subprocess.run() fails, a subprocess.CalledProcessError will be raised.
# (Shell = True): Allows the subprocess command to run in the shell
#  (#----------------------------) represent the end of a function and the start of a new functn

import subprocess
import sys
import ctypes
import psutil
import re
from datetime import datetime
import pyfiglet
import socket




ascii_text= pyfiglet.figlet_format('PH4NT0M-404', )

######check if you're running as admin
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False
def admin_verify():
    if is_admin():
        print("Verification successful: Running as Administrator.")
    else:
        print("Verification failed: Not running as Administrator.")


#If the verification fails
def Admin_verify():
 command ='runas /user:Administrator "cmd.exe"'
 results =subprocess.run(command,check=True, shell=True, capture_output=True)

 if results==0:
     print("Verification successful")

 else:
     print('failed')

     return_to_menu()


def set_up(ssid, key):
    if len(key) < 8:
        print("Your key must be 8-68 ASCII characters.")
        return

    command = f"netsh wlan set hostednetwork mode=allow ssid={ssid} key={key}"
    try:
        # Run the command and capture the output
        result = subprocess.run(command, check=True, shell=True, capture_output=True, text=True)

        # Check if the command was successful
        if result.returncode == 0:
            print(f"Hosted network '{ssid}' is up and running successfully.")
            print(result.stdout)  # Print the command output
        else:
            print(f"Failed to set up hosted network '{ssid}'.")
            print(result.stderr)  # Print any error message

    except subprocess.CalledProcessError as e:
        print(f"Failed to set up hosted network. Error: {e.stderr}")  # Print the specific error message

    return_to_menu()  # Assuming you have this function defined somewhere
    print("\n" * 3)



def show_stats():
    try:
        results = subprocess.run('netsh wlan show hostednetwork', capture_output=True, check=True, shell=True, text=True)
        print(results.stdout)

        if results.returncode != 0:
            print(f'Failed showing hosted network status: {results.stderr}')
            return_to_menu()

    except subprocess.CalledProcessError as e:
        print(f"Failed to show hosted network status: {e}")

    choice= input("press q to return to Management menu.....: ").strip()
    if choice=="q":
        Manage_hosted_network()
    else:
        print("invalid")
        return_to_menu()
    print("\n" * 3)


def start(ssid):
    try:
        command = 'netsh wlan start hostednetwork'
        subprocess.run(command, check=True, shell=True,capture_output=True)
        if subprocess.run(command, check=True, shell=True,capture_output=True)==0:
         print(f"Hosted Network '{ssid}' started successfully.")

        else:
            print(f"Hosted Network '{ssid}' failed.")

    except subprocess.CalledProcessError as e:
        print(f"Starting hosted network '{ssid}' failed. Error: {e}")

    choice = input("press q to return to Management menu.....: ").strip()
    if choice == "q":
        Manage_hosted_network()
    else:
        print("invalid")
        return_to_menu()

    print("\n" * 3)


def check_stats_of_connection():
    IP= input('Enter your hosted network IP address: ').strip()
    is_valid_ip(IP)

    command= f'netstat -an |find "{IP}"'
    try:
      check = subprocess.run(command, check=True , shell=True, capture_output=True, text=True)
      print(check.stdout)

      if check==0:
         print("Netstat successful")

      elif check==1:
        print("Netstat failed")
    except subprocess.CalledProcessError as e:
        print(f"error {e}")

    choice= input("press q to return to Management menu.....: ").strip()
    if choice=="q":
        Manage_hosted_network()
    else:
        print("invalid")
        return_to_menu()


def start_listening(hosted_network_IP, port):
    listen= socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listen.bind((hosted_network_IP,port))
    listen.listen(50)
    print(f" '{hosted_network_IP}' listening on port'{port}")


    while True:
        client_traffic, address = listen.accept()

        print(f"connection established with'{address}'")

        client_traffic.sendall(b"Welcome to the hosted network server!\n")

        client_traffic.close()




#Enter custom CLI codes
def custom():
    command = input("Enter command: ").strip()

    try:
        # Run the command using subprocess
        Exec = subprocess.run(command, check=True, shell=True, capture_output=True, text=True)
        # Print the output of the command
        print(Exec.stdout)

        # Check if the command executed successfully
        if Exec.returncode == 0:
            print("Custom command successful")
        else:
            print("Custom command failed")

    except subprocess.CalledProcessError as e:
        # Handle the command failure case
        print("Error:", e)
        print("Command output:", e.output)
        print("Command stderr:", e.stderr)

    choice = input("Press 'q' to return to the Management menu.....: ").strip()
    if choice.lower() == "q":
        return_to_menu()
    else:
            print("Invalid choice")
            return
        # Prompt the user to return to the menu






# Fourth function: Stop the service
def stop_hostednetwork(ssid, key):
    password = input("Input your Network SSID key to verify: ")

    # Check if the provided password matches the key set from the set_up function
    if password == key:
        print("Password verified. Stopping hosted network.")

        try:
            subprocess.run('netsh wlan stop hostednetwork', check=True, shell=True)
            print(f"Stopped service '{ssid}'")

        except subprocess.CalledProcessError:
            print("Failed to stop the hosted network. Please check your command and try again.")
    else:
        print("Incorrect password. Hosted network not stopped.")

        choice = input("press q to return to Management menu.....: ").strip()
        if choice == "q":
            Manage_hosted_network()
        else:
            print("invalid")
            return_to_menu()
    print("\n" * 3)

# Function to check the validity(xxx.xxx.xxx.xxx format) of an IP address
def is_valid_ip(ip):
    # Regular expression to validate an IP address
    pattern = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
    return pattern.match(ip) is not None



# This function formats ARP table output
def format_arp_output(arp_output):
    lines = arp_output.strip().split('\n')
    formatted_lines = []
    current_interface = None

    for line in lines:
        if line.startswith("Interface:"):
            current_interface = line.split(":")[1].strip()
        elif line and current_interface:  # Ignore empty lines
            parts = line.split()
            if len(parts) >= 3:  # Ensure there are enough parts to unpack
                internet_address = parts[0]
                physical_address = parts[1]
                address_type = parts[2]
                formatted_lines.append(f"Interface: {current_interface}\n  Internet Address: {internet_address}\n  Physical Address: {physical_address}\n  Type: {address_type}\n")

    return "\n".join(formatted_lines)




# : Block a device
def block_device():
    # Use ARP table to find target device's IP
    command = 'arp -a'
    try:
        arp = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
        Vertical_format = format_arp_output(arp.stdout)
        print(Vertical_format)

    except subprocess.CalledProcessError as e:
        print(f"Couldn't print ARP table: {e} ")
        return

    # Input the IP of your target device
    ip = input("From the ARP table, enter the IP address of the corresponding MAC address to be blocked: ")

    # Validate the IP address
    if is_valid_ip(ip):
        print("Valid IP address.")
    else:
        print("Invalid address. Please try again.")
        block_device()  # Retry blocking device

    # Input the profile name for the blocked IP
    blocked_name = input("Enter the profile name of your choice for this blocked IP: ")

    # Attempt to block outgoing traffic
    outgoing_command = f"netsh advfirewall firewall add rule name='{blocked_name}' dir=OUT action=block remoteip={ip}"
    try:
        subprocess.run(outgoing_command, check=True, shell=True,capture_output=False)
        print(f"Successfully blocked outgoing traffic for {ip}.")
    except Exception as error:
        print(f"Failed to block outgoing traffic: {error}")

    # Attempt to block incoming traffic
    incoming_command = f"netsh advfirewall firewall add rule name='{blocked_name}' dir=IN action=block remoteip={ip}"
    try:
        subprocess.run(incoming_command, check=True, shell=True, capture_output=False)
        print(f"Successfully blocked incoming traffic for {ip}.")
    except Exception as error:
        print(f"Failed to block incoming traffic: {error}")

    return_to_menu()
    print("\n" * 3)


    #----------------------------------------------------------------

# Function for checking devices blocked
def show_blocked_rules():
    # Command to filter out firewall rules showing only the blocked ones
    command = (
        'netsh advfirewall firewall show rule name=all | '
        'findstr /C:"Rule Name" /C:"Enabled" /C:"Action" | '
        'findstr /C:"Block"'
    )

    result = subprocess.run(command, capture_output=True, text=True, shell=True)

    # Check if the command executed successfully
    if result.returncode == 0:
        lines = result.stdout.splitlines()
        rule_name = ""
        for line in lines:
            line = line.strip()  # Remove leading and trailing spaces
            if "Rule Name:" in line:
                rule_name = line  # Store current rule_name
            elif "Action:" in line:
                if rule_name:
                    # Format rule name and action with reduced spaces
                    Format_rule_name = rule_name.replace("Rule Name:", "Rule Name:").strip()
                    Format_action = line.replace("Action:", "Action:").strip()

                    # Print the formatted rule name and action
                    print("Blocked Firewall Rules:")
                    print(Format_rule_name)
                    print(Format_action)

                    rule_name = ""  # Reset rule name for the next rule

    else:
        print("Command failed to execute:", result.stderr)

    return_to_menu()
    print("\n" * 3)

#------------------------------------------------

def delete_rule():
    blocked_name = input("Type in the blocked name of the IP: ")

    command = f"netsh advfirewall firewall delete rule name={blocked_name}"

    try:
        results = subprocess.run(command, shell=True, check=True, capture_output=False)

        if results.returncode == 0:
            print("Device setting has been successfully removed.")
        else:
            print("Failed to remove device.")

    except Exception as e:
        print(f"An error occurred: {e}")



    #--------------------------------------------------------

# Function to allow a device
def allow_device():
    # Use ARP table to find target device's IP
    command = 'arp -a'
    try:
        arp = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
        Vertical_format = format_arp_output(arp.stdout)
        print(Vertical_format)

    except subprocess.CalledProcessError as e:
        print(f"Couldn't print ARP table: {e}")
        return

    # Input the IP of your target device
    ip = input("From the ARP table, enter the IP address of the corresponding MAC address to be allowed: ").strip()

    # Validate the IP address
    if is_valid_ip(ip):
        print("Valid IP address.")
    else:
        print("Invalid address. Please try again.")
        allow_device()  # Retry allowing device

    # Input the profile name for the corresponding IP of blocked device to allow
    blocked_name = input("Enter the profile name of the corresponding IP of blocked device to allow: ").strip()

    # Attempt to allow outgoing traffic
    outgoing_command = f"netsh advfirewall firewall delete rule name='{blocked_name}' dir=OUT remoteip={ip}"
    try:
        subprocess.run(outgoing_command, check=True, shell=True, capture_output=False)
        print(f"Successfully allowed outgoing traffic for {ip}.")
    except Exception as error:
        print(f"Failed to allow outgoing traffic: {error}")

    # Attempt to allow incoming traffic
    incoming_command = f"netsh advfirewall firewall delete rule name='{blocked_name}' dir=IN remoteip={ip}"
    try:
        subprocess.run(incoming_command, check=True , shell=True, capture_output=False)
        print(f"Successfully allowed incoming traffic for {ip}.")
    except Exception as error:
        print(f"Failed to allow incoming traffic: {error}")

    return_to_menu()
    print("\n" * 3)

#---------------------------------------------------

    # Setting up the logger
def log_network_activity():
    log_file = input(
        r"enter set location(eg:C:\\Users\Dh4\Documents\Hosted_Network_activity.txt): Kindly add the Name.txt: ").strip()
    current_connections = psutil.net_connections(kind='tcp')

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    for connection in current_connections:
        if connection.status == 'ESTABLISHED':
            log_entry = f"{timestamp} - Connection from {connection.laddr.ip}:{connection.laddr.port} to {connection.raddr.ip}:{connection.raddr.port}"
            with open(log_file, 'a') as f:
                f.write(log_entry + "\n")

                print(f"Network activity failed to logged at {timestamp}")

    print("\n" * 3)
    return_to_menu()

    # -------------------------------------------------------------------------------------
    # Function to return to the main menu
def return_to_menu():
        menu = input("Press q to return to the main menu.....")

        if menu == "q":
            hosted_network_menu()
        else:
            print("Wrong input")
            return_to_menu()
            print("\n" * 3)


#-------------------------------------------------------------------------------------


##Managing sub menu options
  ##Manage Hosted Network menu -option 2

def Manage_hosted_network():
    print("")
    print("----Manage_hosted_network---")
    print()
    print("1. Show Hosted Network status")
    print("2. Start Hosted Network")
    print("3. Stop Hosted Network")
    print("4. Check open ports and listening ports on Hosted network")
    print("5. Create a socket for incoming traffic ")
    print("0. Return to Main menu")
    print()
    choice = input("Enter your choice: ")

    if choice == "1":
        show_stats()

    if choice == "2":
            ssid = input("Enter the SSID of the hosted network you want to start: ")
            start(ssid)

    if choice == "3":
        ssid = input("Enter the SSID of the hosted network you want to stop: ").strip()
        key = input("Enter the password: ").strip()
        stop_hostednetwork(ssid, key)

    if choice=='4':
        check_stats_of_connection()

    if choice=="5":
        hosted_network_IP =input("input Hosted natwork Ip: ")
        is_valid_ip(hosted_network_IP)

        port = int(input("input prefered port: "))

        start_listening(hosted_network_IP, port)

    if choice == "0":
        hosted_network_menu()

    else:
        print("invalid choice")
        return


##device management option 3
def Device_Management():
    print()
    print("------ Device Management Menu------")
    print("1. Block a device")
    print("2. Show blocked device list")
    print("3. Allow a device")
    print("4. Delete (block/allowed) device settings")
    print("0. Return to Main menu")
    print()
    choice = input("Enter your choice: ").strip()

    if choice =="1":
        block_device()

    if choice == "2":
        show_blocked_rules()

    if choice=="3":
        allow_device()

    if choice =="4":
        delete_rule()

    if choice =="0":
        hosted_network_menu()

    else:
        print("invalid")
        Device_Management()

##Utility option 4
def utility():
    print("")
    print("----welcome to Utility-----")
    print("1. start logger")
    print("2. verify system Administrator Username and password")
    print("0. Return to Main menu")
    print()
    choice = input("Enter your choice: ").strip()

    if choice == "1":
        log_network_activity()

        # Monitoring interval (e.g., every 10 seconds)
        interval = 30

        # Infinite loop to keep logging connections
        while True:
            log_network_activity()
            time.sleep(interval)


    if choice == "2":
        print("1. Check if admin")
        print("2. Verify with admin username AND password")
        choice2 = input("Enter your choice: ").strip()

        if choice2 == "1":
            admin_verify()

        elif choice2 == "2":
            Admin_verify()

        else:
         print("Invalid choice")

        back= input("press q to go back to utiity........")
        if back=="q":
         utility()
        else:
            print("invalid")
            hosted_network_menu()

    if choice =="0":
        hosted_network_menu()

    else:
        print("invalid input")
        utility()


 # -----------------------------------------------------------------------


# FIFTH FUNCTION: To manage main the menu
def hosted_network_menu():
    print(ascii_text)
    print("")
    print("Hosted Network Automation Menu")
    print("1. Set Up Hosted Network")
    print("2. Manage Hosted Network")
    print("3. Network Devices Management")
    print("4. Utility ")
    print("5. Use custom command line")
    print("0. Exit")
    print()

    while True:
        choice = input("Choose an option (1-4 or 0 to exit): ")

        if choice == "1":
            ssid = input("Enter the SSID (Name of your network): ")
            key = input("Enter the Password (8-68 characters): ")
            set_up(ssid, key)

        elif choice == "2":
            Manage_hosted_network()


        elif choice == "3":
            Device_Management()


        elif choice == '4':
            utility()

        elif choice=='5':
            custom()

        elif choice == "0":
            print("Exiting...")
            sys.exit()
            break

        else:
            print("Invalid option, please choose again.")

# Run the menu function to start the script
if __name__ == "__main__":
    hosted_network_menu()
