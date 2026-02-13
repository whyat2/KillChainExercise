Details

EDR missed agent telsa at 3:04:08PM

sourcetype="XmlWinEventLog" EventID=23 Image!=*winevtlog.exe AND Image!=*splunkd.exe AND Image!=*firefox.exe AND Image!=*svchost.exe AND TargetFilename!=*health*
| sort _time
Shows us that C:\Users\Administrator\Downloads\Rnwood.Smtp4dev.exe (Sinkhole used to avoid actually outsending data)

sourcetype="XmlWinEventLog" EventID=7 *agent_tesla-deob.exe*
| sort _time
| table ImageLoaded Description

15:08:16.583 (note 15 is same as 3 above since PM)
vaultcli.dll: The Windows Vault Client Library, used to access credentials stored in the Windows Credential Manager.
user32.dll: Can be used for keylogging
msctf.dll?
dhcp and networking stuff potentially to capture traffic