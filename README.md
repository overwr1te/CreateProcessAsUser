# CreateProcessAsUser
Create process at active user from Windows Service

#  How it works
Module read active windows desktop, change service token to active user and create process.

# Example usage
```c
DWORD pId = _CreateProcessAsUser("C:\\Windows\\system32\\cmd.exe", "/c route");
```