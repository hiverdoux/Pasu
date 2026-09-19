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
	-- 제목만 있는 패널(닫기 버튼 없음 — 판정은 버튼/시간 초과로만)
	set panel to ca's NSPanel's alloc()'s initWithContentRect:(ca's NSMakeRect(0, 0, 480, 190)) styleMask:1 backing:2 defer:false
	panel's setTitle:"pasu — SSH 서명 요청"
	set cv to panel's contentView()
	set titleLabel to ca's NSTextField's labelWithString:"처음 보는 SSH 서명 요청"
	titleLabel's setFont:(ca's NSFont's boldSystemFontOfSize:13)
	titleLabel's setFrame:(ca's NSMakeRect(20, 152, 440, 20))
	cv's addSubview:titleLabel
	set bodyLabel to ca's NSTextField's wrappingLabelWithString:msg
	bodyLabel's setFont:(ca's NSFont's systemFontOfSize:11)
	bodyLabel's setFrame:(ca's NSMakeRect(20, 62, 440, 82))
	cv's addSubview:bodyLabel
	-- 버튼 줄: [허용 ▾][거부] 같은 크기로 나란히, 거부가 기본(Enter)
	set denyBtn to ca's NSButton's buttonWithTitle:"거부" target:me action:"denyPressed:"
	denyBtn's setFrame:(ca's NSMakeRect(360, 16, 100, 32))
	denyBtn's setKeyEquivalent:(character id 13)
	cv's addSubview:denyBtn
	set popup to ca's NSPopUpButton's alloc()'s initWithFrame:(ca's NSMakeRect(252, 16, 100, 32)) pullsDown:true
	popup's addItemsWithTitles:{"허용", "이번만", "로그아웃까지", "항상"}
	popup's setTarget:me
	popup's setAction:"allowChosen:"
	cv's addSubview:popup
	panel's |center|()
	ca's NSApp's activateIgnoringOtherApps:true
	ca's NSApp's runModalForWindow:panel
	panel's orderOut:(missing value)
end showAsk:

on denyPressed:sender
	set my askOutcome to "deny"
	current application's NSApp's stopModal()
end denyPressed:

on allowChosen:sender
	set t to (sender's titleOfSelectedItem()) as text
	if t is "허용" then return
	set my askOutcome to t
	set ca to current application
	ca's NSApp's abortModal()
	ca's NSApp's performSelector:"stopModal" withObject:(missing value) afterDelay:0.1 inModes:{ca's NSModalPanelRunLoopMode}
end allowChosen:
