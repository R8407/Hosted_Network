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
          -Check if you're already logged in with administrative permission 
          - verification of Administrative privilages
  + custom space for running cmd and powershell commands
   + exit

  NB: Most of these features require administrative rights, make sure you know your Administrator password
  there is a validation process at the utility menu which will help you wth that
  NB: again, after entering the "Administrator", type your password once the cursor moves to the next blank line

imported modules:
+subprocess
+sys
+psutil
+re
+threading
+datetime
+logging
+socket

