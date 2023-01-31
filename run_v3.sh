name=$(uname -n);
TS=$(date +%s);
computer=$(echo $name.$TS);
keyboard=$(cat /proc/bus/input/devices | grep -i "leds" | awk '{print $4}')
sudo logkeys -s -o $computer.log -m logkeys/keymaps/en_US_ubuntu_1204.map  -d /\
var/input/$keyboard;
#recordmydesktop –fps 5                                                         
echo "started capturing keys"

