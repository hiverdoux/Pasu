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
	alert's setMessageText:"처음 보는 SSH 서명 요청 (풀다운 예제)"
	alert's setInformativeText:msg
	alert's addButtonWithTitle:"거부"
	-- 메뉴 항목별 action 대신 NSPopUpButton의 action으로 선택을 처리한다.
	-- 메뉴 관리는 컨트롤에 맡기고 스크립트는 선택된 항목만 읽는다.
	set popup to ca's NSPopUpButton's alloc()'s initWithFrame:(ca's NSMakeRect(0, 0, 260, 26)) pullsDown:true
	popup's addItemsWithTitles:{"허용…", "이번만", "로그아웃까지", "항상"}
	popup's setTarget:me
	popup's setAction:"allowChosen:"
	alert's setAccessoryView:popup
	ca's NSApp's activateIgnoringOtherApps:true
	set code to alert's runModal()
	if (code as integer) is 1000 and (my askOutcome) is "timeout" then
		set my askOutcome to "deny"
	end if
end showAsk:

on allowChosen:sender
	set t to (sender's titleOfSelectedItem()) as text
	if t is "허용…" then return
	set my askOutcome to t
	set ca to current application
	-- 메뉴 추적 문맥에서는 stopModal이 삼켜질 수 있어 이중으로 닫는다:
	-- abortModal(추적 문맥용) + 모달 모드 지연 stopModal(그 외 문맥용)
	ca's NSApp's abortModal()
	ca's NSApp's performSelector:"stopModal" withObject:(missing value) afterDelay:0.1 inModes:{ca's NSModalPanelRunLoopMode}
end allowChosen:
