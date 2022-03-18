# Hwid Manipulation

Hwid Check Bypass is an "Easy Hook" based HWID manipulation tool. Manipulates Win32 functions by hooking them.

### Hooked functions
- GetVolumeInformationW
- GetVolumeInformationA
- GetAdaptersInfo 
- GetCurrentHwProfileW
- GetCurrentHwProfileA
- RegGetValueW
- RegGetValueA

### Usage
- Run it and enter the pid of the application you want to hook.
- Follow hooked functions from console

### GetVolumeInformation
Retrieves the serial of all the partitions on the computer.

### GetAdaptersInfo
Retrieves the information of all adapters on the computer (Mac adress, Guid, name etc.)

### GetCurrentHwProfile
Retrieves the current user HW Profile Guid

### RegGetValue
Retrieves the any value from regedit. 
If the key is in the list below, it will be manipulated similarly to the structure of that key.
> - SusClientId => Guid
> - ProductId => 4x5 Key ( xxxxx-xxxxx-xxxxx-xxxxx ) 
> - InstallDate => timestamp
> - MachineGuid => Guid
> - Default (Others) => RandomString(15,45)  Warning :  This can cause crashes.