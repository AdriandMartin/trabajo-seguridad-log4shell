#!/bin/sh

# Parse commandline arguments
if [ ${#} -ne 2 ]; then
    echo "ERROR: use as '${0} VM IP'"
    echo "being...VM the name of the virtual machine to start"
    echo "     ...IP the last byte of the IPv4 address of the virtual machine"
fi
VM_NAME=${1}
VM_IP=${2}
VM_NET="192.168.56."
USER="user"

# Start virtual machine
VBoxManage startvm ${VM_NAME} --type headless

# Login using SSH
echo "Connect pasting 'ssh ${USER}@${VM_NET}${VM_IP}'"
