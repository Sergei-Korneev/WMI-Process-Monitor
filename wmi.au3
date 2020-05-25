;WMI Process monitoring
;Sergei Korneev 2020
#RequireAdmin
#include<array.au3>
#include<date.au3>
#include <Crypt.au3>
#Include <string.au3>
#include <File.au3>
#include <GuiConstantsEx.au3>
#include <WindowsConstants.au3>
#include <GuiListView.au3>
#include <ListViewConstants.au3>
#include <TrayConstants.au3>







$refreshrate=90
Opt("TrayAutoPause", 1)
Opt("TrayIconHide", 0)
$learn=0
$timel=0
$begin = TimerInit()

;******************************************************************************
;~ Parse command line
If $CmdLine[0] == 2 Then

   If $CmdLine[1] == "learn" and StringIsDigit($CmdLine[2]) Then
      $timel=$CmdLine[2]
    	 $learn=1
   EndIf

EndIf

;******************************************************************************
;~ Timer
Func timer($begin=0,$Minutes=0)
Local $60Count = 0
    $dif = TimerDiff($begin)
    $dif2 = StringLeft($dif, StringInStr($dif, ".") -1)
    $Count = int($dif/1000)
    $60Count = Int($Count / 60)
	if $Minutes <= $60Count Then
	   return 1
	EndIf
	ConsoleWrite($Count&@CRLF)
	return 0
EndFunc

;******************************************************************************
;~ Create Gui
Opt("GuiOnEventMode", 1)
$hGUI = GUICreate("A new process raised!", 420, 420)
GUISetOnEvent($GUI_EVENT_CLOSE, "killall")
$ListView = GUICtrlCreateListView("Check to unlock|Path|Hash|Commandline|CompanyName", 10, 10, 400, 400, -1, BitOR($LVS_EX_CHECKBOXES,$WS_EX_CLIENTEDGE))

;******************************************************************************
;~ Show help
Func Help()
   ConsoleWrite("WMI Process Monitor (Sergei Korneev 2020)"&@CRLF&"Use: "&@CRLF&"program.exe or program.exe learn [time in minutes]"&@CRLF&@CRLF)
EndFunc

;******************************************************************************
;~ Find Child process
Func _ProcessGetChildren($i_pid) ; First level children processes only
    Local Const $TH32CS_SNAPPROCESS = 0x00000002

    Local $a_tool_help = DllCall("Kernel32.dll", "long", "CreateToolhelp32Snapshot", "int", $TH32CS_SNAPPROCESS, "int", 0)
    If IsArray($a_tool_help) = 0 Or $a_tool_help[0] = -1 Then Return SetError(1, 0, $i_pid)

    Local $tagPROCESSENTRY32 = _
    DllStructCreate _
    ( _
    "dword dwsize;" & _
    "dword cntUsage;" & _
    "dword th32ProcessID;" & _
    "uint th32DefaultHeapID;" & _
    "dword th32ModuleID;" & _
    "dword cntThreads;" & _
    "dword th32ParentProcessID;" & _
    "long pcPriClassBase;" & _
    "dword dwFlags;" & _
    "char szExeFile[260]" _
    )
    DllStructSetData($tagPROCESSENTRY32, 1, DllStructGetSize($tagPROCESSENTRY32))

    Local $p_PROCESSENTRY32 = DllStructGetPtr($tagPROCESSENTRY32)

    Local $a_pfirst = DllCall("Kernel32.dll", "int", "Process32First", "long", $a_tool_help[0], "ptr", $p_PROCESSENTRY32)
    If IsArray($a_pfirst) = 0 Then Return SetError(2, 0, $i_pid)

    Local $a_pnext, $a_children[11][2] = [[10]], $i_child_pid, $i_parent_pid, $i_add = 0
    $i_child_pid = DllStructGetData($tagPROCESSENTRY32, "th32ProcessID")
    If $i_child_pid <> $i_pid Then
    $i_parent_pid = DllStructGetData($tagPROCESSENTRY32, "th32ParentProcessID")
    If $i_parent_pid = $i_pid Then
    $i_add += 1
    $a_children[$i_add][0] = $i_child_pid
    $a_children[$i_add][1] = DllStructGetData($tagPROCESSENTRY32, "szExeFile")
    EndIf
    EndIf

    While 1
    $a_pnext = DLLCall("Kernel32.dll", "int", "Process32Next", "long", $a_tool_help[0], "ptr", $p_PROCESSENTRY32)
    If IsArray($a_pnext) And $a_pnext[0] = 0 Then ExitLoop
    $i_child_pid = DllStructGetData($tagPROCESSENTRY32, "th32ProcessID")
    If $i_child_pid <> $i_pid Then
    $i_parent_pid = DllStructGetData($tagPROCESSENTRY32, "th32ParentProcessID")
    If $i_parent_pid = $i_pid Then
    If $i_add = $a_children[0][0] Then
    ReDim $a_children[$a_children[0][0] + 11][2]
    $a_children[0][0] = $a_children[0][0] + 10
    EndIf
    $i_add += 1
    $a_children[$i_add][0] = $i_child_pid
    $a_children[$i_add][1] = DllStructGetData($tagPROCESSENTRY32, "szExeFile")
    EndIf
    EndIf
    WEnd

    If $i_add <> 0 Then
    ReDim $a_children[$i_add + 1][2]
    $a_children[0][0] = $i_add
    EndIf

    DllCall("Kernel32.dll", "int", "CloseHandle", "long", $a_tool_help[0])
    If $i_add Then Return $a_children
    Return SetError(3, 0, 0)
EndFunc
;******************************************************************************
;~ Check if file hash exists in the file
Func checkinfile($pattern="")
   local $file = FileOpen("./allow.txt", 0)
   $read = FileRead($file)
     If @error = -1 Then
		 ConsoleWrite("Cannot open the file ./allow.txt.")
          Return 1
     Else

       If StringRegExp($read, $pattern) Then
          return True
       Else
          return False
       EndIf
     EndIf
   FileClose($file)

EndFunc
;******************************************************************************
;~ Write file
Func file_write($line="",$file="")
 Local $hFileOpen = FileOpen($file, $FO_APPEND)
    If $hFileOpen = -1 Then
       ConsoleWrite("Cannot open the file "&$file)
        Return 1
    EndIf

       FileWrite($hFileOpen, $line)
FileClose($hFileOpen)
EndFunc
;******************************************************************************
;~ Resume Process and add to exclusions
Func _GetChecked()
    If GUICtrlRead(@GUI_CtrlId, 1) = 1 Then
        _ProcessNT(StringSplit(GUICtrlRead(@GUI_CtrlId), "|")[1],  False)
     	   file_write(StringSplit(GUICtrlRead(@GUI_CtrlId), "|")[2]&"  "&StringSplit(GUICtrlRead(@GUI_CtrlId), "|")[3]&@CRLF,"./allow.txt")
	         GUICtrlDelete ( @GUI_CtrlId )
			    if _GUICtrlListView_GetItemCount($ListView)==0 Then GUISetState(@SW_HIDE)
    EndIf
EndFunc

;******************************************************************************
;~ Close GUI and kill all processes in listview
Func killall()
For $k = 0 To _GUICtrlListView_GetItemCount($ListView)
   $aItem = _GUICtrlListView_GetItemTextArray($ListView, $k)

    local  $a_children = _ProcessGetChildren($aItem[1])


       For $l = 1 To UBound($a_children, 1)-1
             ProcessClose($a_children[$l][0])
		        Next

     ProcessClose($aItem[1])
      Next
        _GUICtrlListView_DeleteAllItems ( $ListView )
          GUISetState(@SW_HIDE)
EndFunc

;******************************************************************************
Func _Exit()
    Exit
EndFunc


;******************************************************************************
Dim $arrComputers= [@ComputerName], $strQuery, $SINK, $objContext, $objWMIService, $objAsyncContextItem, $return, $account

$strQuery = "SELECT * FROM __InstanceCreationEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_Process'"
$SINK = ObjCreate("WbemScripting.SWbemSink")
ObjEvent($SINK, "SINK_")
For $strComputer In $arrComputers
    $objContext = ObjCreate("WbemScripting.SWbemNamedValueSet")
    $objContext.Add ("hostname", $strComputer)
    $objContext.Add ("SinkName", "Process Monitor")
    $objWMIService = ObjGet("winmgmts:" _
             & "!\\" & $strComputer & "\root\cimv2")
    If Not @error Then
        $objWMIService.ExecNotificationQueryAsync ($SINK, $strQuery, Default, Default, Default, $objContext)
        ConsoleWrite("Waiting for processes to start on " & $strComputer & " ..." & @CRLF)
    EndIf
 Next
Help()
ConsoleWrite("In monitoring mode. (learning mode: "&$learn&" for "&$timel&" minutes.) " &"Press Ctrl+C to exit." & @CRLF)
While 1
    Sleep($refreshrate)
WEnd


;******************************************************************************
Func SINK_OnObjectReady($objLatestEvent, $objAsyncContext)
    ;Trap asynchronous events.
    local  $doiknow="Yes"
    $objAsyncContextItem = $objAsyncContext.Item ("hostname")
    ConsoleWrite(@CRLF & "Computer Name: " & $objAsyncContextItem.Value & @CRLF)
    ConsoleWrite("Sink Name: " & $objAsyncContext.Item ("sinkname").Value & @CRLF)
	$path=$objLatestEvent.TargetInstance.ExecutablePath
	if not FileExists($path) Then
	    $path = StringReplace($path, @WindowsDir&"\system32",@WindowsDir&"\Sysnative",0,0)
	    $path = StringReplace($path,  @WindowsDir&"\SysWOW64",@WindowsDir&"\Sysnative",0,0)
	 EndIf
         $hash=_Crypt_HashFile($path,  $CALG_MD5)
   if not checkinfile($hash) Then
        $doiknow="No"
	   if $learn==1 and not timer($begin,$timel) Then

		  file_write($path &" "&$hash& @CRLF,"./allow.txt")
       Else

	     GUICtrlCreateListViewItem($objLatestEvent.TargetInstance.ProcessID&  "|"&$path &" "&$objLatestEvent.TargetInstance.Name&  "|"&$hash&  "|"&$objLatestEvent.TargetInstance.CommandLine&  "|"&FileGetVersion ( $path,"CompanyName" ) , $ListView)
         GUICtrlSetOnEvent(-1, "_GetChecked")
	     GUISetState()
		 _ProcessNT($objLatestEvent.TargetInstance.ProcessID,  True)
		    local $a_children = _ProcessGetChildren($objLatestEvent.TargetInstance.ProcessID)
               For $l = 1 To UBound($a_children, 1)-1
                         _ProcessNT($a_children[$l][0])
		                    Next


	   EndIf
	EndIf

	$info=" Known process: "& $doiknow & @CRLF _
	&" Executable Path: " & $path & @CRLF _
	&" MD5 Hash: " &$hash& @CRLF _
	&" ID : " &$objLatestEvent.TargetInstance.ProcessID & @CRLF _
	&" Description : " &$objLatestEvent.TargetInstance.Description & @CRLF _
	&" SessionId : " &$objLatestEvent.TargetInstance.SessionId & @CRLF _
	&" CommandLine : " &$objLatestEvent.TargetInstance.CommandLine & @CRLF _
    &" Time: " & _NowDate() & @CRLF _
	&" ProductName: "&FileGetVersion ( $path,"ProductName" ) & @CRLF _
    &" CompanyName: "&FileGetVersion ( $path,"CompanyName" ) & @CRLF _
    &" FileVersion: "&FileGetVersion ( $path,"FileVersion" ) & @CRLF _
    &" FileDescription: "&FileGetVersion ( $path,"FileDescription")&@CRLF&@CRLF&@CRLF

	ConsoleWrite($info)
	if $doiknow=="No" Then
	  TrayTip("Unknown process: ", $info, 0, $TIP_ICONASTERISK)
    EndIf

	file_write($info,"./log.txt")
 EndFunc   ;==>SINK_OnObjectReady



;******************************************************************************
func sink_onprogress($iUpperBound,$iCurrent,$strMessage,$objWbemAsyncContext)
    ConsoleWrite("progress ... " & @crlf )
    ConsoleWrite($iUpperBound & @crlf & $iCurrent & @crlf & $strMessage & @crlf &$objWbemAsyncContext & @crlf )
 endfunc
;******************************************************************************

Func _ProcessNT($iPID, $iSuspend = True)
    If IsString($iPID) Then $iPID = ProcessExists($iPID)
    If Not $iPID Then Return SetError(2, 0, 0)
    Local $ai_Handle = DllCall("kernel32.dll", 'int', 'OpenProcess', 'int', 0x1f0fff, 'int', False, 'int', $iPID)
    If $iSuspend Then
        Local $i_sucess = DllCall("ntdll.dll","int","NtSuspendProcess","int",$ai_Handle[0])
    Else
        Local $i_sucess = DllCall("ntdll.dll","int","NtResumeProcess","int",$ai_Handle[0])
    EndIf
    DllCall('kernel32.dll', 'ptr', 'CloseHandle', 'ptr', $ai_Handle)
    If IsArray($i_sucess) Then Return 1
    Return SetError(1, 0, 0)
 EndFunc


exit