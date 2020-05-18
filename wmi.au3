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

$refreshrate=200
Opt("TrayAutoPause", 0)
Opt("TrayIconHide", 1)
;******************************************************************************
;~ Create Gui
Opt("GuiOnEventMode", 1)
$hGUI = GUICreate("A new process raised!", 420, 420)
GUISetOnEvent($GUI_EVENT_CLOSE, "killall")
$ListView = GUICtrlCreateListView("Check to unlock|Path|Hash", 10, 10, 400, 400, -1, BitOR($LVS_EX_CHECKBOXES,$WS_EX_CLIENTEDGE))

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
;~ Add Hash to the file
Func fileappend($line="")
 Local $hFileOpen = FileOpen("./allow.txt", $FO_APPEND)
    If $hFileOpen = -1 Then
       ConsoleWrite("Cannot open the file ./allow.txt.")
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
     	   fileappend(StringSplit(GUICtrlRead(@GUI_CtrlId), "|")[2]&"  "&StringSplit(GUICtrlRead(@GUI_CtrlId), "|")[3]&@CRLF)
	         GUICtrlDelete ( @GUI_CtrlId )
			    if _GUICtrlListView_GetItemCount($ListView)==0 Then GUISetState(@SW_HIDE)
    EndIf
EndFunc

;******************************************************************************
;~ Close GUI and kill all processes in listview
Func killall()
For $k = 0 To _GUICtrlListView_GetItemCount($ListView)
   $aItem = _GUICtrlListView_GetItemTextArray($ListView, $k)
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
ConsoleWrite("In monitoring mode. Press Ctrl+C to exit." & @CRLF)
While 1
    Sleep($refreshrate)
WEnd


;******************************************************************************
Func SINK_OnObjectReady($objLatestEvent, $objAsyncContext)
    ;Trap asynchronous events.

    $objAsyncContextItem = $objAsyncContext.Item ("hostname")
    ConsoleWrite(@CRLF & "Computer Name: " & $objAsyncContextItem.Value & @CRLF)
    ConsoleWrite("Sink Name: " & $objAsyncContext.Item ("sinkname").Value & @CRLF)
	$path=$objLatestEvent.TargetInstance.ExecutablePath
    $path = StringReplace($path, @WindowsDir&"\system32",@WindowsDir&"\Sysnative",0,0)
	$path = StringReplace($path,  @WindowsDir&"\SysWOW64",@WindowsDir&"\Sysnative",0,0)
	ConsoleWrite(" Executable Path: " & $path & @CRLF)
	$hash=_Crypt_HashFile($path,  $CALG_MD5)
	ConsoleWrite(" MD5 Hash: " &$hash& @CRLF)
	ConsoleWrite(" ID : " &$objLatestEvent.TargetInstance.ProcessID & @CRLF)
	ConsoleWrite(" Description : " &$objLatestEvent.TargetInstance.Description & @CRLF)
	ConsoleWrite(" SessionId : " &$objLatestEvent.TargetInstance.SessionId & @CRLF)
	ConsoleWrite(" CommandLine : " &$objLatestEvent.TargetInstance.CommandLine & @CRLF)
    ConsoleWrite(" Time: " & _NowDate() & @CRLF)
   if not checkinfile($hash) Then

	GUICtrlCreateListViewItem($objLatestEvent.TargetInstance.ProcessID&  "|"&$path &" "&$objLatestEvent.TargetInstance.Name&  "|"&$hash , $ListView)
    GUICtrlSetOnEvent(-1, "_GetChecked")
	GUISetState()
	_ProcessNT($objLatestEvent.TargetInstance.ProcessID,  True)
	EndIf
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