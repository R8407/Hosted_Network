# Hosted_Network
Overall, this script automates network tasks and firewall management on Windows, providing flexibility for users to control hosted networks and device access.
I also compiled it into an exe file. but you can download the source code and then do the compiling later with pyinstaller 

Features:
+ Main-menu
   + set up hosted network
   + Manage hosted network
     - show hosted network status
     - start hosted netwok
     - stop hosted network
     - show listening ports on hosted network
     - create listening ports on hosted network
   + Network Device management
      - Block a device
      - Blocked device list
      - Allow a device
      - Delete block settings for devices
   + Utility
       - start logger
       + Privilages
          - Check if you're already logged in with administrative permission 
          - verification of Administrative privilages
  + custom space for running cmd and powershell commands
   + exit

  NB: Make sure you run the .exe file as an administrator. 

imported modules:
+subprocess
+sys
+psutil
+re
+datetime
+logging
+socket

