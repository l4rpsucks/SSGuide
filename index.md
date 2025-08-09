# Regexes

| **Regex** | **Explanation** | **Services** |
|---|---|---|
| `^TH[a-zA-Z0-9]{4}\.tmp$` | Hollow tools leave a file starting with `TH` and random numbers. This regex shows their presence. | Any service. Mainly DPS, Pcasvc, Explorer, Registry, CDPU, SearchIndexer or Run Winprefetchview and dump its memory. |
| `^[A-Z]:\\.+\.(dll)$` | Shows `.dll` files only | Mainly csrss and SearchIndexer but works with any service, replace `.dll` into any other extension to filter them only |
| `^([a-zA-Z]:\\.+)\\?$` | Displays full paths and files with paths only. | Any service |
| `^[A-Z]:\\.+\.(exe\|dll)$` | Filter `.exes` and `.dlls` only. Add | |
| `^[a-zA-Z0-9]{8}\.jar$` | Displays 8 letter `.jar` files. Usually detects Doomsday Client. Replace `.jar` with any other extension to display 8 letter files. | DComLaunch, PlugPlay, Explorer, Pcasvc, SearchIndexer |
| `^{"displaytext"((?!Exe).)*$` | Opened executables, filtering displaytext only in contains case-insensitive search will show more results, this is just a precise search. | Explorer, CDPU |

## Content

| **Content** | **Explanation** | **Service** |
|---|---|---|
| `file:///` | Shows visited or accessed files, folders, executables and other formats. Useful to analyze what the Player has done on the device. | SearchIndexer, Explorer, Registry, WinPrefetchView (if you execute it and dump the process using System Informer) |
| `Transaction` | Displays logs of potential file deletion, renaming or replacement. | SearchIndexer only. |
| `" "` | There is a space between `""-s`. Can often potentially display commands for process hollowing or java injections, as paths are mostly typed this way. | SearchIndexer, DiagTrack, Msmpeng, Nissrv, Memory Compression, Explorer, TextInputHost, Clipboardsvc, CDPU |
| `Visited:` | Shows visited archives | Explorer |
| `Registry` | Shows Registry entries or traces logged in regedit of file execution | Explorer |
| `iwr (or Invoke-Web)` | Displays downloads using Powershell. Even though it doesn't always include cheat samples, new bypasses rely on these types of methods often. | Registry, Eventlog, Scheduler, Clipboardsvc, Textinputhost, DiagTrack |
| `!0!` | Shows potentially replaced files | DPS |
| `[ or ] (then filter results for .exe)` | Displays executions by only executable names. Often shows files that couldn't be logged through paths. | SearchIndexer |
| `HardDiskVolume` | Displays harddiskvolume paths of file executions. Different volume numbers mean different drives/USBs | DPS, PCAsvc |
| `Trace,` | Extended pcaclient, copy all results and paste them into notepad to review. | Pcasvc only |
| `Command` | Displays powershell commands logged in event logs pwsh log | Eventlog |
| `[System.Reflection.Assembly]` | Potential detection of fileless malware that logged in event logs or other regions of memory | EventLog, Memory Compression, DiagTrack, SearchIndexer, Clipboardsvc, TextInputHost, Registry |

## Extended Regexes

1. `^([A-Za-z]:[\\/]|\\\\.+?\\).+[\\/]$` (This displays extended paths, including wsl and so on. Used in any process. May display paths that include Unicode characters but they will need to be checked.)
2. `^/.+/$` (Displays unusual file path formats)
3. `^[A-Z]:/[a-zA-Z0-9_\\-\\.]+/$` (Potential whitespace character detections that are mixed with ASCII letters)
4. `[a-zA-Z]:\\(?:[^\\:*?"&lt;&gt;|\r\n]+\\)*[^\\:*?"&lt;&gt;|\r\n]+(?:\.\w+)?` (Extended file paths and win directories search in SearchIndexer)
5. `\b[a-zA-Z0-9_.-]+\.exe\b` (Detect only executable names, SearchIndexer)
6. `\b[a-zA-Z0-9_.-]+\.exe\s+\/[a-zA-Z]+(?:\s+[a-zA-Z]+)*\b` (Detect potential commandline arguments, SearchIndexer / Scheduler services)
7. `",trusted\b` (Trusted executables, searchindexer)
8. `[\w`~!@#$%^&amp;*()-=+{}[\]:;&#39;"&lt;&gt;?/|\\]+\.exe(?:[^\x00-\x7F]+|[^\x20-\x7E])` (Unusual Patterns)
9. [`#%&amp;+-_~]*[a-zA-Z0-9_.-]+\.exe` (Extended Unicode path patterns, replace `.exe` with any other extension to look for them)

## Steps During a 1.19+ SS

### Win + R:
- `[1]` Check `C:\$Recycle.Bin` | 3 Dots, Options, View, Show Hidden Items, Show System Protected Files.
- `[2]` Check `shell:recent` | Good for non `.exe` cheats
- `[3]` Check `C:\ProgramData\Oracle\Java\.oracle_jre_usage` | For finding when a `.jar` was executed good for Prestige/Doomsday.
- `[4]` Check `%temp%` | Look for `imgui-java64` as it may show use of `imgui` used in clients (Do not ban of this it may be legit check what happened at that exact time in USN Journal or LastActivityViewer)

### Mod Analyzing:
- `[1]` Go to resource packs and click on open pack folder
- `[2]` go to `.minecraft` from resource pack folder
- `[3]` Search for the mods folder and copy the location 
- `[4]` run CMD (ADMIN) and paste in `powershell Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass && powershell Invoke-Expression (Invoke-RestMethod https://raw.githubusercontent.com/HadronCollision/PowershellScripts/refs/heads/main/HabibiModAnalyzer.ps1)` then paste in the location of the mods and wait till the scan finishes.

### System Informer: [https://systeminformer.com/canary](https://systeminformer.com/canary)
- Settings | System Column (top left) | Options | 1. Enable Kernel driver 2. Enable undecorated symbols 3. Check services and images for Digital Signatures 4. Include a usage of collapsed processes 5. Show advanced options 
NOTE: Under Tools, System > NTFS Reparse Points and Object Identifiers, we will be able to check a load of information regarding what files were /are present on the devices, which ones were executed, downloaded and so on.
All of this can be Copied by selecting and CTRL-C to run, for example, signature checkers against the list.

### Javaw.exe aka Minecraft:
NOTE: String Search Options For ALL! | Memory | Options | Uncheck Hide Free Pages and Reserved Pages | Strings | 5 | Private, Mapped, Image | Detect Unicode and Extended Unicode (Filter By Contains Case insensitive for all unless told otherwise)

- `[1]` Strings to search | Autototem | Auto crystal | Cw crystal | Anchor macro | Anchormacro (might flag in game names) | Auto anchor | TriggerBot | AutoDhand | SlientAim | AutoInventoryTotem | aimassist | AutoCrystal | prestige | argon | stop_cracking | self de | 
- `[2]` What we do next is open the javaw.exe process and go into its Threads and Handles, sort threads and start analyzing: Usually, the most top thread will present the latest created thread. Given that in System Informer DLL Injections are classified as Loading new Threads, it is logical to assume in this case that `.dlls` at the top are the most unusual. IMAGE: [https://i.imgur.com/B3fJIJQ.png](https://i.imgur.com/B3fJIJQ.png)
- `[3]` When injecting a custom file or a cheat script into javaw process directly, Handles will display everything that was ever loaded in its memory, for example here we see an ESP `.txt` log Example : [https://i.imgur.com/YUgqVtW.png](https://i.imgur.com/YUgqVtW.png)
- `[4]` In the end, double click the suspicious `.dll` in Threads section. In my case it will be `oracle.dll` to view its memory contents. You can search for things like `.pdb` or `.db` or application as well as many other identifiers that will immediately reveal the hidden cheat in a legitimate looking place:
( 2 - 4 ) Is needed.

### explorer.exe
NOTE: String Search Options For ALL! | Memory | Options | Uncheck Hide Free Pages and Reserved Pages | Strings | 5 | Private, Mapped, Image | Detect Unicode and Extended Unicode (Filter By Contains Case insensitive for all unless told otherwise)

- `[1]` String | `file:///` | 
- `[2]` String | `PcaClient` | (Mostly useless for 1.21+ but left in)
- `[2]` String | `{"displayText"` | 
- `[3]` String | `cpu usage` | 

### Pcasvc (svchost.exe)
NOTE: String Search Options For ALL! | Memory | Options | Uncheck Hide Free Pages and Reserved Pages | Strings | 5 | Private, Mapped, Image | Detect Unicode and Extended Unicode (Filter By Contains Case insensitive for all unless told otherwise)

- `[1]` String | `e,0a000000,Reason,00002100` | 

### PlugPlay (svchost.exe)
NOTE: String Search Options For ALL! | Memory | Options | Uncheck Hide Free Pages and Reserved Pages | Strings | 5 | Private, Mapped, Image | Detect Unicode and Extended Unicode (Filter By Contains Case insensitive for all unless told otherwise)

- `[1]` String | `jar | .jar | java -jar` | 

### dnscache (svchost.exe)
NOTE: String Search Options For ALL! | Memory | Options | Uncheck Hide Free Pages and Reserved Pages | Strings | 5 | Private, Mapped, Image | Detect Unicode and Extended Unicode (Filter By Contains Case insensitive for all unless told otherwise)

- `[1]` String | `vape|whiteout|.wtf|intent.store|neverlack|dreamclient|wise|slapp.in|echo.ac|paladin.ac|cpn.ac|entropy.club|dopp.in|porn` (Searches to see if users have gone to sites containing these strings | Ban if wiseFH shows up | Porn is a joke, but still use it xD)

### Diagtrack (svchost.exe)
NOTE: String Search Options For ALL! | Memory | Options | Uncheck Hide Free Pages and Reserved Pages | Strings | 5 | Private, Mapped, Image | Detect Unicode and Extended Unicode (Filter By Contains Case insensitive for all unless told otherwise)

- `[1]` String | `volume1|volume2|volume3|volume4|volume5|volume6|volume7|volume8|volume9|volume10|volume11|volume12|volume13|volume14|volume15|volume16|volume17|volume18|volume19|volume20|volume21|volume22|volume23` | (Regex)

## Powershell (Admin)

- `(Get-PSReadlineOption).HistorySavePath` (Powershell history) Win + R the dir shown to open
- `Get-WinEvent Microsoft-Windows-Kernel-PnP/Configuration | findstr 410 > usb.log` (Look for “USB”)

## Everything: [https://www.voidtools.com/downloads/](https://www.voidtools.com/downloads/)

- Search for “file attrib:h” and look through the files
- Search for `.dmp` and look through the names of the files for suspicious files
- Search for `appcrash` look through the names of the files for suspicious files

## BONUS: Jars, Detecting Java Archives: DUMP FROM ECHO CERT

[https://onedrive.live.com/view.aspx?resid=A2088A7D005E853A!sf5888e89d22d41eaa19b869d65c1d3d3&migratedtospo=true&redeem=aHR0cHM6Ly8xZHJ2Lm1zL3AvYy9hMjA4OGE3ZDAwNWU4NTNhL0lRU0pqb2oxTGRMcVFhR2JocDFsd2RQVEFSRlVHUnQ4ekFEdWExemhHenlNSnNRP2VtPTImYW1wO3dkQXI9MS43Nzc3Nzc3Nzc3Nzc3Nzc3&wdSlideId=263&wdModeSwitchTime=1746213527017](https://onedrive.live.com/view.aspx?resid=A2088A7D005E853A!sf5888e89d22d41eaa19b869d65c1d3d3&migratedtospo=true&redeem=aHR0cHM6Ly8xZHJ2Lm1zL3AvYy9hMjA4OGE3ZDAwNWU4NTNhL0lRU0pqb2oxTGRMcVFhR2JocDFsd2RQVEFSRlVHUnQ4ekFEdWExemhHenlNSnNRP2VtPTImYW1wO3dkQXI9MS.777777777777777777777777&wdSlideId=263&wdModeSwitchTime=1746213527017)


## MACROS ALL
NOTE: Detection by Mouse Brand (Software Config Files/Locations)

The precise location and format of macro configuration data vary significantly between manufacturers and even different software versions from the same manufacturer. Here are known or commonly suspected locations for several popular brands:

### Logitech:

- **Logitech Gaming Software (LGS - Older):** Check `%localappdata%\Logitech\Logitech Gaming Software\`. Look for files like `settings.json` or potentially `.xml` files containing profile and macro definitions.
- **Logitech G HUB (Newer):** Check `%localappdata%\LGHUB\`. The primary configuration is often within `settings.db` (an SQLite database, requires a DB browser to view) or related files/folders within this directory. Analyze modification times first.

### Razer:

- **Synapse 2 (Legacy):** Examine installation folders (C:\Program Files (x86)\Razer, etc.) and `%localappdata%\Razer` or `%programdata%\Razer` for profile/macro files (often `.xml`).
- **Synapse 3:** Configuration is more complex, potentially involving cloud sync. Check `C:\ProgramData\Razer\Synapse3\Accounts\` for account-specific data and `%localappdata%\Razer\Synapse3\Log\` for activity logs that might indicate macro usage or profile switches. Macro definitions might be within complex profile structures or potentially stored server-side, making direct file analysis difficult. Checking the software GUI is crucial.

### SteelSeries:

- **SteelSeries Engine / GG:** Check `%localappdata%\steelseries-engine-3-client\Local Storage\leveldb\` or similar paths within `%localappdata%` or `%programdata%`. SteelSeries often uses LevelDB databases, which require specialized tools (like LevelDB readers/editors) for reliable inspection. Also check associated `.json` or configuration files in nearby directories.

### Roccat:

- **Roccat Swarm:** Check `%appdata%\ROCCAT\SWARM\`. Look for subfolders like `macro` containing files such as `custom_macro_list.xml` or `macro_list.dat`. Analyze `.xml` files for macro definitions.

### Red Dragon:

- Paths can vary by model. Check `%homepath%\Documents\` for folders named like `M### Gaming Mouse` (where `###` might be model numbers). Inside, look for subfolders like `MacroDB` containing files such as `MacroData.db`.

### Glorious:

- Check `%appdata%\BY-COMBO2\` (path might vary slightly based on specific software/model). Look for `.json` or `.ini` configuration files. Examine subfolders, particularly any named `Mac` or `Macro`.

### Cooler Master:

- Check standard locations: `%localappdata%\CoolerMaster`, `%appdata%\CoolerMaster`, or `%programdata%\CoolerMaster` for software configuration files (`.json`, `.xml`, `.ini`, potentially `.db`).

### Bloody:

- Check the installation directory, e.g., `C:\Program Files (x86)\Bloody7\Bloody7\Data\Mouse\English\ScriptsMacros\GunLib\` for Bloody7 software. Also check AppData folders for related configuration files (`.ini`, `.amc2`).

### Mad Catz: 

- Check installation directory and common AppData locations for config files.

### Mars Gaming:

- Check installation directory and AppData for `.xml` or `.ini` config files.

### Ayax (Noganet):

- Check installation path, e.g., `C:\Program Files\AYAX GamingMouse\`. Look for files like `record.ini`.

### Krom (Kolt model):

- Check `%AppData%\Local\VirtualStore\Program Files (x86)\KROM KOLT\Config` (path reflects virtualization if software runs with non-standard permissions). Look for `sequence.dat`.

### BlackWeb:

- Check installation path, e.g., `C:\Blackweb Gaming AP\config\`. Look for files with unusual extensions like `.MA32AIY`.

### YanPol (Often similar hardware/software to Glorious/Ajazz):

- Check `%appdata%\BYCOMBO-2\` (or similar) and look for `Mac\` subfolders.

### MotoSpeed (V60 model example):

- Check installation path, e.g., `C:\Program Files (x86)\MotoSpeed Gaming Mouse\V60\modules`. Look within subfolders like `Settings` for `.bin` or config files.

### Asus (ROG Armoury):

- Check `C:\Users\%username%\Documents\ASUS\ROG\ROG Armoury\common\`. Look for a `Macro` subfolder.

### Corsair (iCUE):

- Check `C:\Users\%username%\AppData\Roaming\Corsair\CUE` (or `Local` instead of `Roaming`). Look within `Config.cuecfg` (or similar complex config files). Searching inside for strings like `RecMouseCLicksEnable` might reveal relevant settings. Process memory dumping of `iCUE.exe` and filtering for strings like `MemberFuncSlot` has also been suggested as an advanced technique.

## Analysis Steps for Software Macros:

### Identify Mouse:

- Determine the player's exact mouse brand and model. Ask the player or check Windows device settings if necessary.

### Check Software GUI:

- The most direct method is often to open the mouse's official software (e.g., G HUB, Synapse, Swarm, iCUE) and navigate to the macro definition and button assignment sections. Look for any macros bound to buttons, especially those involving rapid left/right clicks.

### Check Config File Locations:

- Navigate to the potential configuration paths listed above corresponding to the identified brand.

### Examine Modification Dates:

- Check the "Date modified" timestamps of relevant configuration files, databases, or folders. Recent modifications shortly before the screenshare are highly suspicious, suggesting potential setup or deletion of macros.

### Analyze File Contents:

- Open text-based config files (`.json`, `.xml`, `.ini`) in a text editor and search for keywords like `macro`, `click`, `delay`, `repeat`, or specific button bindings (e.g., `LeftMouseButton`, `Button 4`). Look for sequences defining rapid clicks with low delays.
- Open database files (`.db`) using an appropriate SQLite browser (like DB Browser for SQLite) and examine tables related to profiles, macros, or bindings.
- Analyze LevelDB or other formats using specialized tools if necessary (more advanced).
- Check logs: Examine any log files generated by the mouse software (e.g., Razer logs) for entries related to profile switching, macro execution, errors, or enabling specific performance modes (like `Turbo`).

## Detecting On-Board Macros
NOTE: On-board macros are stored directly within the mouse's internal memory, allowing them to function even if the manufacturer's software is not running or installed. Detecting these requires focusing on the mouse's real-time input behavior rather than just PC files.

### Identification of Mouse Model (Crucial First Step):

Knowing the exact mouse model is essential before testing. This allows the ScreenSharer to know the expected number and default function of all physical buttons on the mouse. Many gaming mice have extra buttons beyond the standard Left, Right, Middle, Forward, Back (e.g., "sniper" buttons, DPI shift buttons, profile switch buttons, sometimes marketed as "Fire Keys"). Failure to account for these extra buttons can lead to misinterpretations during testing. Methods to identify the model:

- Ask the player directly (if permitted by server policy).
- Check Windows Settings: Navigate to Bluetooth & Devices > Devices > Mouse (or similar paths depending on Windows version). The listed device name often includes the model.
- Device Manager: Look under "Mice and other pointing devices," check properties, and look up Hardware IDs online.
- USB Device History Tools: Tools like USBDeview (Nirsoft) or Echo's USBDeview alternative list connected devices and their names/IDs.
- Visual Confirmation (If Allowed/Practical): If server policy and player cooperation permit, requesting a photo or video of the mouse via Discord, Telegram, etc., can be definitive.

### Mouse Button Test Procedure:

- Use a Reliable Button Tester: Utilize a comprehensive online mouse button testing tool. Websites like `cpstest.org/mouse-test/` or `cps-check.com/mouse-buttons-test` are often recommended as they tend to detect a wider range of buttons (including extra side/top buttons) compared to simple in-game keybind menus or basic Windows settings.
- Instruct the Player: Clearly instruct the player to physically press each and every button on their mouse, one at a time. Ensure they press all side buttons, top buttons (excluding perhaps dedicated DPI cycle buttons unless suspect), and the standard buttons.
- Observe Carefully: Watch the output on the testing tool closely as the player presses each physical button.
- Identify Mismatches (Failure Condition / Red Flag): The key indicator of an on-board macro is a consistent mismatch between the physical button pressed and the button registered by the testing tool. For example:

  - Player presses the physical "Forward" side button, but the tester registers it as a "Left Click".
  - Player presses a dedicated extra top button (e.g., a "Fire Key"), but the tester registers it as a "Left Click".

This should happen multiple times consecutively when pressing that specific physical button.

### Rationale for Detection:

To store and trigger a macro using the mouse's on-board memory, one of the mouse's physical buttons must typically be reprogrammed within the mouse firmware/memory to execute the macro sequence instead of its default function (like "Forward" or "Back"). This "sacrificed" button then acts as the trigger for the often rapid-click macro, leading to the mismatch observed in the test.

## Common Bypass Techniques in Screen Sharing (FROM REDLOTUS)

### - Spoofed Extensions
**Description:** This common and relatively simple technique involves disguising an executable file (typically `.exe`, but could also apply to scripts like `.bat` or `.ps1`) by changing its file extension to something seemingly innocuous or unrelated. For example, `SuperClicker.exe` might be renamed to `important_notes.txt`, `config.dll`, `logo.png`, `tempdata.tmp`, or even just `mydata` (no extension).

**The bypass relies on the fact that while double-clicking a file typically relies on its extension for execution, Windows offers alternative methods to launch processes that do not solely depend on the `.exe` extension. Common methods include:**

- Using PowerShell commands like `Start-Process C:\path\to\renamed_file.tmp`.
- Using specific Windows Management Instrumentation (WMI) commands, particularly `wmic process class create "C:\path\to\renamed_file.dat"`.
- Utilizing scheduled tasks or other scripting methods that specify the exact file to run, regardless of extension.

**Detection:**

- **Prefetch Analysis:** As mentioned previously, Prefetch often still logs the execution but under the spoofed name (e.g., `LOGO.PNG-HASH.pf`). Finding non-`.exe` files in Prefetch is a major red flag.
- **Process Memory Analysis:** Tools like System Informer, when used to search service memory (especially `csrss.exe`, `dps`), can reveal the full paths of executed files, including those with spoofed extensions, using appropriate regex patterns (e.g., `^!.)*$` in `DPS`, or broad path searches in `csrss`).
- **Signature/Content Analysis:** Running signature checks (like BACA's Signature Checker script) on all suspicious files found (regardless of extension) can identify executables masquerading as other file types (they'll show as "NotSigned" or "HashMismatch" if a fake signature was attempted). Tools like Detect It Easy or searching file content for PE headers (content:"This program cannot be run in DOS mode.") in Search Everything can also expose disguised executables.
- **Execution Logs:** BAM, Activities Cache, and sometimes Event Logs might record the execution under the spoofed name.

### - Code Obfuscation
**Description:** This technique applies primarily to the cheat code itself, rather than just its filename or location. Developers intentionally make the source code or compiled bytecode difficult to read, understand, and reverse-engineer. While most common with cheats distributed as Minecraft mods (`.jar` files) or standalone Java applications, obfuscation techniques can also be applied to other compiled languages (C++, C#) or even scripts (using encoding, variable renaming, etc.).

**Mechanism:** Various techniques are used to scramble the code:

- **Renaming:** Replacing meaningful class, method, and variable names with short, meaningless, or random characters (e.g., `a.class`, `b()`, `zzXy_123`, `_a`, `_b`).
- **Control Flow Obfuscation:** Inserting junk code, opaque predicates (conditions that always evaluate the same way but look complex), or restructuring loops and conditional statements to make the logical flow hard to follow.
- **String Encryption:** Encrypting literal strings within the code (like GUI text, configuration keys, or even cheat feature names) so they don't appear in plain text during static analysis or memory scans.
- **Packing/Encryption:** Compressing or encrypting the main codebase and embedding it within a small loader stub. The loader unpacks/decrypts the real code into memory at runtime.

**Detection:**

- **Decompilation/Disassembly:** The primary detection method is attempting to analyze the code. If a decompiler or disassembler produces code that is largely unreadable, uses meaningless names extensively, or exhibits characteristics mentioned above, it's highly likely obfuscated.
- **Entropy Analysis:** Packed or encrypted files often have high file entropy (a measure of data randomness). Tools like Detect It Easy (DiE) or VirusTotal calculate entropy; high values (often >7.0 out of 8) suggest packing/encryption.
- **Packer Detection Tools:** Utilities like DiE include signatures to identify common packers (like UPX, Themida, VMProtect) used to obfuscate executables.
- **Server Rules:** Due to the difficulty in verifying obfuscated code quickly during a screenshare, many servers maintain a strict policy banning any mods or executables found to be significantly obfuscated. The inability to ascertain its function poses too great a risk.

## Identifying Alternate Accounts During ScreenShare (BASIC)

Linking a player currently being screenshared to a previously banned account requires careful examination of artifacts that store user identities, configurations, or machine identifiers.

### Username and Account Artifacts in Files:

- **Log Files:** Game client logs (latest.log, chat logs), launcher logs (e.g., Lunar Client, Badlion Client), and sometimes mod configuration logs can contain usernames or UUIDs associated with accounts used on the machine.
- **Launcher Configuration Files:** Many launchers store account information. For example, custom launchers might have `accounts.json` or similar files within their data directories (e.g., `.lunarclient/`, `.feather/` often in `%appdata%` or user home directories on Linux/macOS). Analyzing these files can reveal multiple accounts linked to the device.
- **General File Searches:** Players sometimes leave traces of usernames in unexpected places like `.txt` files, script files, or folder names within their user profile. Searching common user directories (`C:\Users\%username%`, Desktop, Downloads, Documents) and AppData folders (`%appdata%`, `%localappdata%`) for known banned usernames or UUIDs can sometimes yield results.

### PowerShell Scripting for Alts:

- **Specialized scripts can automate the search for usernames across common locations.** For instance, the `ADVANCE ALT CHECK` PowerShell script available at [https://pastebin.com/raw/LBGh2Cyb](https://pastebin.com/raw/LBGh2Cyb) is designed specifically for this. It recursively searches user directories for files with common log/text entries extensions (`.txt`, `.log`, `.json`, `.jar`) and looks for occurrences of a specified username (which could be a known banned alt), outputting a list of files where the name was found. This can significantly speed up the search process compared to manual browsing.

## Powershell Scripts: (Run in CMD AS ADMIN)

- `powershell Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass && powershell Invoke-Expression (Invoke-RestMethod https://raw.githubusercontent.com/bacanoicua/Screenshare/main/RedLotusSignatures.ps1)`

RL Signature Check (RedLotusSignatures.ps1): Takes a list of file paths (often from a paths.txt file generated by dumping process strings) and checks the Authenticode digital signature status of each file (Valid, NotSigned, HashMismatch, NotTrusted, UnknownError, or NotFound). Crucial for identifying unsigned or tampered executables/DLLs.

- `powershell Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass && powershell Invoke-Expression (Invoke-RestMethod https://raw.githubusercontent.com/bacanoicua/Screenshare/main/RedLotusPrefetchIntegrityAnalyzer.ps1)`

Prefetch Integrity Analyzer (RedLotusPrefetchIntegrityAnalyzer.ps1): Scans the `C:\Windows\Prefetch` directory for anomalies. It checks if files are read-only, if they have the correct "MAM" header, and identifies files with duplicate hashes (potentially indicating type or echo command manipulation).

- `powershell Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass && powershell Invoke-Expression (Invoke-RestMethod https://raw.githubusercontent.com/PureIntent/ScreenShare/main/RedLotusBam.ps1`)

# Artifact Parsing and Data Extraction:

- `powershell Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass && powershell Invoke-Expression (Invoke-RestMethod https://raw.githubusercontent.com/PureIntent/ScreenShare/main/RedLotusBam.ps1`)

RL BAM Script (RedLotusBam.ps1): Parses BAM registry keys, displays execution timestamps (UTC, User TimeZone), application path, attempts to resolve the user SID, and crucially, also performs a signature check (using the Get-Signature function) on the executable path, reporting its status or if the file was not found.

- `powershell Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass && powershell Invoke-Expression (Invoke-RestMethod https://raw.githubusercontent.com/spokwn/powershells/refs/heads/main/Streams.ps1)`

Streams Script (Streams.ps1): Scans a specified folder (optionally recursively) for files, retrieving details like path, name, hash (MD5), owner, timestamps, attributes, and importantly, lists Alternate Data Streams (ADS) including Zone.Identifier content. Helps find hidden data or trace file origins.

- `powershell Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass && powershell Invoke-Expression (Invoke-RestMethod https://raw.githubusercontent.com/spokwn/powershells/refs/heads/main/activitiescache.ps1)`

ActivitiesCache Parser (ActivitiesCache.ps1): Downloads and runs a dedicated `.exe` parser (ActivitiesCacheParser.exe) to extract and format data from the ActivitiesCache.db, filtering by the oldest logon time.

- `powershell -Command "Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass; Invoke-Expression (Invoke-RestMethod 'https://raw.githubusercontent.com/nolww/project-mohr/refs/heads/main/SuspiciousScheduler.ps1')"`

ManualTasks.ps1: Lists scheduled tasks created specifically by the current user.

- `powershell -Command "Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass; Invoke-Expression (Invoke-RestMethod 'https://raw.githubusercontent.com/nolww/project-mohr/refs/heads/main/SuspiciousScheduler.ps1')"`

SuspiciousScheduler.ps1: Lists scheduled tasks and flags actions involving potentially suspicious programs often used in bypasses (`cmd`, `powershell`, `rundll32`, etc.).

- `powershell -Command "Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass; Invoke-Expression (Invoke-RestMethod 'https://raw.githubusercontent.com/ObsessiveBf/Task-Scheduler-Parser/main/script.ps1')"`

Task-Scheduler-Parser/script.ps1 (Rio/ObsessiveBf): Parses XML task files in `C:\Windows\System32\Tasks`, extracts commands and arguments, saves them to text files, and flags tasks containing suspicious keywords.

- `powershell Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass && powershell Invoke-Expression (Invoke-RestMethod https://raw.githubusercontent.com/bacanoicua/Screenshare/main/RedLotusHardDiskVolumeConverter.ps1)`

HardDiskVolume Converter (RedLotusHardDiskVolumeConverter.ps1): Takes a list of paths starting with `\Device\HarddiskVolumeX` (often found in DPS logs) from a paths.txt file and converts them to standard drive letter paths (e.g., `C:\...`).

## Hinting at Detection: PowerShell scripts serve as automated assistants in the ScreenSharing process. They rapidly collect and pre-process data from numerous system artifacts, perform checks (like signature validation), and highlight potentially suspicious entries based on predefined logic, thereby accelerating the identification of evidence related to cheats or bypass attempts.


## TOOLS USED DURING SS:

- [https://github.com/spokwn?tab=repositories](https://github.com/spokwn?tab=repositories)

- [http://dl.echo.ac/tool/](http://dl.echo.ac/tool/) (example [http://dl.echo.ac/tool/journal](http://dl.echo.ac/tool/journal))

### Echo BAM (bam.exe): 

A graphical tool to view, filter, and reorder entries from the Background Activity Moderator (BAM) registry keys. It simplifies accessing BAM data, which logs program executions (primarily `.exe` files).

### Echo Journal Tool (journal-tool.exe):

A parser for the NTFS USN Journal (`$J`). It allows filtering for specific events like file deletions, creations, and renames. It's presented as a user-friendly alternative to using fsutil commands and is noted for parsing all NTFS drives simultaneously.

### Echo UserAssist View (userassist.exe):

A viewer for Windows UserAssist registry data. UserAssist tracks the execution of GUI applications. This tool reportedly shows if the target file still exists and allows quick navigation to it.

### Echo String Tool (strings-tool.exe):

Allows searching for multiple specific strings within a selected process's memory simultaneously. It's useful for quickly testing custom string detections or looking for known cheat indicators without needing to repeatedly use tools like System Informer's string search.

### Echo USBDEVIEW:

A tool similar to Nirsoft's USBDeview, designed to show the history of USB devices connected to the PC. It displays information like the last plug-in and unplug times and the type of USB device, aiming for a less cluttered interface than the original Nirsoft tool.

## BONUS: NoCheat Tools (Discord BOT MOD Scanner Better than HABIBI MOD Scanner)

- DM: `themasterkitty` / `discord.com/users/998301295834300427` to buy the tool
- Use code: `Nioki` to get 20% off
