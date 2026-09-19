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
	alert's setMessageText:"pasu — 처음 보는 SSH 서명 요청"
	alert's setInformativeText:msg
	-- 첫 버튼이 오른쪽 끝·기본 버튼(Enter)·코드 1000, 이후 1001·1002.
	-- 긴 한글 버튼 3개는 macOS 표준대로 세로로 쌓인다.
	alert's addButtonWithTitle:"거부"
	alert's addButtonWithTitle:"이번만 허용"
	alert's addButtonWithTitle:"이 프로세스에 대해 항상 허용"
	ca's NSApp's activateIgnoringOtherApps:true
	set code to alert's runModal()
	set n to code as integer
	if n is 1000 then set my askOutcome to "deny"
	if n is 1001 then set my askOutcome to "이번만 허용"
	if n is 1002 then set my askOutcome to "이 프로세스에 대해 항상 허용"
end showAsk:
