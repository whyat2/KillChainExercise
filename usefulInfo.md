| Event ID | Event Name                     | Description                                                                 |
|----------|--------------------------------|-----------------------------------------------------------------------------|
| 1        | Process Create                 | Logs when a process is created, including command line, parent process, and hashes. |
| 3         | Network Access                | Logs when a process accesses the network |
| 7        | Image Loaded                   | Logs when a module (DLL or executable image) is loaded by a process.      |
| 10       | Process Access                 | Logs when a process accesses another process (e.g., for injection or credential dumping). |
| 11       | File Create                    | Logs when a file is created or overwritten.                                |
| 13       | Registry Value Set             | Logs when a registry value is created or modified.                         |
| 17       | Pipe Created                   | Logs when a named pipe is created.                                          |
| 18       | Pipe Connected                 | Logs when a named pipe connection is made.                                  |
| 22       | DNS Query                      | Logs DNS queries made by a process.                                         |
| 23       | File Delete                    | Logs when a file is deleted.                                |

These are the logs from the sysmon