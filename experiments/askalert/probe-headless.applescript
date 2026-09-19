use framework "AppKit"

property probeOut : "none"

on run argv
	my performSelectorOnMainThread:"probe:" withObject:(item 1 of argv) waitUntilDone:true
	return probeOut
end run

on probe:msg
	set ca to current application
	ca's NSApplication's sharedApplication()
	set alert to ca's NSAlert's alloc()'s init()
	alert's setMessageText:"probe"
	alert's setInformativeText:msg
	alert's addButtonWithTitle:"거부"
	alert's addButtonWithTitle:"허용"
	set popup to ca's NSPopUpButton's alloc()'s initWithFrame:(ca's NSMakeRect(0, 0, 260, 26)) pullsDown:false
	popup's addItemsWithTitles:{"이번만", "로그아웃까지", "항상"}
	alert's setAccessoryView:popup
	set my probeOut to "buttons=" & ((alert's buttons()'s |count|()) as text) & " items=" & ((popup's numberOfItems()) as text) & " sel=" & ((popup's titleOfSelectedItem()) as text)
end probe:
