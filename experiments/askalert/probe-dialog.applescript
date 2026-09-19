use framework "AppKit"

property askOutcome : "timeout"

on run argv
	my performSelectorOnMainThread:"showAsk:" withObject:(item 1 of argv) waitUntilDone:true
	return askOutcome
end run

on showAsk:msg
	set ca to current application
	ca's NSApplication's sharedApplication()
	ca's NSApp's setActivationPolicy:1
	set alert to ca's NSAlert's alloc()'s init()
	alert's setAlertStyle:2
	alert's setMessageText:"처음 보는 SSH 서명 요청"
	alert's setInformativeText:msg
	alert's addButtonWithTitle:"거부"
	alert's addButtonWithTitle:"허용"
	set popup to ca's NSPopUpButton's alloc()'s initWithFrame:(ca's NSMakeRect(0, 0, 260, 26)) pullsDown:false
	popup's addItemsWithTitles:{"이번만", "로그아웃까지", "항상"}
	alert's setAccessoryView:popup
	ca's NSApp's activateIgnoringOtherApps:true
	set code to alert's runModal()
	if (code as integer) is 1000 then
		set my askOutcome to "deny"
	else
		set my askOutcome to (popup's titleOfSelectedItem()) as text
	end if
end showAsk:
