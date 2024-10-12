# Hosted_Network
Overall, this script automates network tasks and firewall management on Windows, providing flexibility for users to control hosted networks and device access.

Features:
+ Main-menu
   + set up hosted network
   + Manage hosted network
     - show hosted network status
     - start hosted netwok
     - stop hosted network
   + Network Device management
      - Block a device
      - Blocked device list
      - Allow a device
      - Delete block settings for devices
   + Utility
       - start logger
       - verification of Administrative privilages
   + exit

  NB: Most of these features require administrative rights, make sure you know your Admin username and password
  there is a validation process at o the utility menu which will help you wth that

imported modules:
subprocess
sys
psutil
re
threading
datetime
logging

