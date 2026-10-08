; PurgeKit installer (Inno Setup 6).
;
;   iscc /DAppVersion=0.0.1 /DBinDir=<dir with purgekit.exe + purgekit-helper.exe> /DOutputDir=<out> purgekit.iss
;
; Per-machine install into Program Files. The elevated helper must live in a
; folder only administrators can write; a per-user folder would let any
; unelevated process replace the helper and ride the next UAC prompt.
; The app itself runs asInvoker; only purgekit-helper.exe elevates.

#ifndef AppVersion
  #error Pass /DAppVersion=<version>
#endif
#ifndef BinDir
  #define BinDir "..\..\target\release"
#endif
#ifndef OutputDir
  #define OutputDir "..\..\target\installer"
#endif

[Setup]
; Never change AppId: Windows uses it to find the installed app for upgrades.
AppId={{56D9D13D-CF8C-4990-BA36-AA36DE24F6B0}
AppName=PurgeKit
AppVersion={#AppVersion}
AppPublisher=PurgeKit
AppPublisherURL=https://github.com/garyilayev/PurgeKit
AppSupportURL=https://github.com/garyilayev/PurgeKit/issues
AppUpdatesURL=https://github.com/garyilayev/PurgeKit/releases
DefaultDirName={autopf}\PurgeKit
DisableProgramGroupPage=yes
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
; Windows 10 22H2 (build 19045) or later.
MinVersion=10.0.19045
LicenseFile=..\..\LICENSE
SetupIconFile=..\..\ui\purgekit.ico
UninstallDisplayIcon={app}\purgekit.exe
UninstallDisplayName=PurgeKit
OutputDir={#OutputDir}
OutputBaseFilename=PurgeKit-Setup-{#AppVersion}
VersionInfoVersion={#AppVersion}
VersionInfoProductName=PurgeKit
VersionInfoDescription=PurgeKit Setup
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
; Asks the user to close a running PurgeKit before files are replaced (the
; helper refuses to run against an app of another version). Never forced.
CloseApplications=yes
RestartApplications=no

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
Source: "{#BinDir}\purgekit.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#BinDir}\purgekit-helper.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\LICENSE"; DestDir: "{app}"; DestName: "LICENSE.txt"; Flags: ignoreversion

[Icons]
Name: "{autoprograms}\PurgeKit"; Filename: "{app}\purgekit.exe"
Name: "{autodesktop}\PurgeKit"; Filename: "{app}\purgekit.exe"; Tasks: desktopicon

[Run]
; runasoriginaluser: Setup runs elevated, the app must not.
Filename: "{app}\purgekit.exe"; Description: "{cm:LaunchProgram,PurgeKit}"; Flags: nowait postinstall skipifsilent runasoriginaluser

[Code]
// Spec "Uninstall": remove the app and ask before deleting %LOCALAPPDATA%\PurgeKit
// (settings, exclusions, history, logs). Default answer is No; a silent
// uninstall keeps the data. {localappdata} is the profile of the user who
// approved the uninstall; other users' profiles are never touched.
procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  DataDir: String;
begin
  if CurUninstallStep <> usPostUninstall then
    Exit;
  DataDir := ExpandConstant('{localappdata}\PurgeKit');
  if UninstallSilent or not DirExists(DataDir) then
    Exit;
  if MsgBox('Also delete your PurgeKit settings, exclusions, history and logs?' + #13#10 + #13#10 +
            DataDir + #13#10 + #13#10 +
            'Choose No to keep them for a later install.',
            mbConfirmation, MB_YESNO or MB_DEFBUTTON2) = IDYES then
    DelTree(DataDir, True, True, True);
end;
