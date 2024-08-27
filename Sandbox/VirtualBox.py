import subprocess
import asyncio
from log import log 
from database import Database

class VirtualBoxManager:
    # Virtualization layer for VirtualBox.
    def configure(self):
        db = Database()
        self.VBOXMANAGE = db.get_value('configuration', 1, "vboxmanage_path")
        self.snapshot = db.get_value('configuration', 1, "snapshot")

    async def start_vm(self, label):
        # Start a virtual machine
        try:
            self.configure()
            await self.restore_vm(label)
            await asyncio.sleep(2)
            log(f'Starting VM {label}') 
            args = [self.VBOXMANAGE, 'startvm', label, '--type', 'gui']
            await asyncio.create_subprocess_exec(*args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except OSError as e:
            log(f"Error starting VM '{label}': {e}")

    async def stop_vm(self, label):
        # Stop a virtual machine
        try:
            self.configure()
            args = [self.VBOXMANAGE, 'controlvm', label, 'acpipowerbutton']
            await asyncio.create_subprocess_exec(*args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except OSError as e:
            log(f"Error stopping VM '{label}': {e}")

    async def status(self, label):
        # Get current status of a VM
        try:
            self.configure()
            args = [self.VBOXMANAGE, 'guestproperty', 'get', label, '/VirtualBox/GuestInfo/OS/LoggedInUsers']
            proc = await asyncio.create_subprocess_exec(*args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            output, _ = await proc.communicate()

            status = output.decode('utf-8')
            try:
                return status.split(' ')[1].split()[0]
            except:
                return None
        except OSError as e:
            log(f"Error getting VM status for '{label}': {e}")
            return None
    
    async def get_ip(self, label):
        # Get current status of a VM
        try:
            args = [self.VBOXMANAGE, 'guestproperty', 'get', label, '/VirtualBox/GuestInfo/Net/0/V4/IP']
            proc = await asyncio.create_subprocess_exec(*args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            output, _ = await proc.communicate()

            ip = output.decode('utf-8').split(' ')[1].split()[0]
            if ip:
                return ip
            else:
                return None
        except OSError as e:
            log(f"Error getting VM IP for '{label}': {e}")
            return None

    async def restore_vm(self, label):
        # Restore a virtual machine
        try:
            args = [self.VBOXMANAGE, 'snapshot', label, 'restore', self.snapshot]     
            log(f'Restoring VM {label} with snapshot {self.snapshot}') 
            await asyncio.create_subprocess_exec(*args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except OSError as e:
            log(f"Error restoring VM '{label}': {e}")

    async def take_snapshot(self, label):
        # Create post-execution snapshot of a virtual machine
        snapshot = 'postexec'
        try:
            args = [self.VBOXMANAGE, 'snapshot', label, 'take', snapshot]
            await asyncio.create_subprocess_exec(*args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except OSError as e:
            log(f"Error taking snapshot of VM '{label}': {e}")

    async def delete_snapshot(self, label):
        # Delete post-execution snapshot of a virtual machine
        snapshot = 'postexec'
        try:
            args = [self.VBOXMANAGE, 'snapshot', label, 'delete', snapshot]
            await asyncio.create_subprocess_exec(*args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except OSError as e:
            log(f"Error removing snapshot of VM '{label}': {e}")

    async def dump_memory(self, label):
        path = 'memdump/postexec'
        try:
            args = [self.VBOXMANAGE, 'debugvm', label, 'dumpvmcore', '--filename', path]
            await asyncio.create_subprocess_exec(*args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except OSError as e:
            log(f"Error dumping memory of VM '{label}': {e}")

    async def kill_vm(self, label):
        try:
            args = ['taskkill', '/F', '/IM', 'VirtualBoxVM.exe']
            await asyncio.create_subprocess_exec(*args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except OSError as e:
            log(f"Error killing VM '{label}': {e}")