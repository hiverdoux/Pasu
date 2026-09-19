// sewrap — passphrase를 Secure Enclave 키로 래핑/해제하는 Swift 컴포넌트.
//
// SE 키의 파일 저장과 복원에는 CryptoKit의 dataRepresentation API를 사용한다.
// Security.framework의 내부 속성인 toid를 같은 형식으로 취급하지 않는다.
// API별 복원 동작을 비교하는 진단 코드는 experiments/keychain에 있다.
// build.sh가 이 파일을 정적 라이브러리(libpasuse.a)로 빌드해 cgo로 링크한다.
//
// 암호 구성(파일 형식 v1, Go 쪽 sewrap_darwin.go와 한 쌍):
//   SE P-256 키(비영구, privateKeyUsage+userPresence ACL) 생성 →
//   소프트웨어 임시 P-256 키와 ECDH → HKDF-SHA256 → AES-256-GCM으로 봉인.
//   봉인은 SE 공개키만 쓰므로 무인, 해제는 SE ECDH가 필요해 OS가 Touch ID
//   (또는 로그인 암호 — userPresence)를 강제한다. 이것이 이 기능의 보안 경계다.

import CryptoKit
import Foundation
import LocalAuthentication

private let hkdfSalt = Data("pasu-sewrap-v1".utf8)

// Swift Data를 C(malloc) 버퍼로 복사한다. 소유권은 호출자(Go)로 넘어가고
// Go 쪽이 C.free로 해제한다.
private func copyOut(
	_ data: Data,
	_ outPtr: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
	_ outLen: UnsafeMutablePointer<Int32>?
) -> Bool {
	guard let outPtr, let outLen else { return false }
	guard let buf = malloc(max(data.count, 1)) else { return false }
	data.withUnsafeBytes { raw in
		if let base = raw.baseAddress, raw.count > 0 {
			memcpy(buf, base, raw.count)
		}
	}
	outPtr.pointee = buf.assumingMemoryBound(to: UInt8.self)
	outLen.pointee = Int32(data.count)
	return true
}

private func fail(_ msg: String, _ errBuf: UnsafeMutablePointer<CChar>?, _ errLen: Int32) -> Int32 {
	if let errBuf, errLen > 0 {
		_ = msg.withCString { strlcpy(errBuf, $0, Int(errLen)) }
	}
	return 1
}

// 봉인·해제가 같은 유도 과정을 쓰도록 대칭키 유도를 한 곳에 둔다.
// sharedInfo에 양쪽 공개키를 묶어 컨텍스트를 고정한다.
private func deriveKey(
	_ shared: SharedSecret, ephPub: Data, sePub: Data
) -> SymmetricKey {
	shared.hkdfDerivedSymmetricKey(
		using: SHA256.self, salt: hkdfSalt,
		sharedInfo: ephPub + sePub, outputByteCount: 32)
}

// passphrase(secret)를 새 SE 키로 봉인한다. 반환 0=성공.
// out: SE 키 블롭(dataRepresentation), 임시 공개키, GCM combined 암호문.
@_cdecl("pasuSESeal")
public func pasuSESeal(
	_ secret: UnsafePointer<UInt8>?, _ secretLen: Int32,
	_ outBlob: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
	_ outBlobLen: UnsafeMutablePointer<Int32>?,
	_ outEph: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
	_ outEphLen: UnsafeMutablePointer<Int32>?,
	_ outCt: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
	_ outCtLen: UnsafeMutablePointer<Int32>?,
	_ errBuf: UnsafeMutablePointer<CChar>?, _ errLen: Int32
) -> Int32 {
	guard let secret, secretLen > 0 else {
		return fail("빈 secret", errBuf, errLen)
	}
	var cfErr: Unmanaged<CFError>?
	guard let ac = SecAccessControlCreateWithFlags(
		nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
		[.privateKeyUsage, .userPresence], &cfErr)
	else {
		let why = cfErr?.takeRetainedValue().localizedDescription ?? "?"
		return fail("SecAccessControl 생성 실패: \(why)", errBuf, errLen)
	}
	do {
		let seKey = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: ac)
		let eph = P256.KeyAgreement.PrivateKey()
		let shared = try eph.sharedSecretFromKeyAgreement(with: seKey.publicKey)
		let ephPub = eph.publicKey.rawRepresentation
		let sePub = seKey.publicKey.rawRepresentation
		let sym = deriveKey(shared, ephPub: ephPub, sePub: sePub)
		let box = try AES.GCM.seal(Data(bytes: secret, count: Int(secretLen)), using: sym)
		guard let combined = box.combined else {
			return fail("GCM combined 없음", errBuf, errLen)
		}
		guard copyOut(seKey.dataRepresentation, outBlob, outBlobLen),
			copyOut(ephPub, outEph, outEphLen),
			copyOut(combined, outCt, outCtLen)
		else {
			return fail("출력 버퍼 할당 실패", errBuf, errLen)
		}
		return 0
	} catch {
		return fail("SE 봉인 실패: \(error)", errBuf, errLen)
	}
}

// 봉인을 해제한다. SE ECDH 시점에 OS가 Touch ID/암호를 요구한다(reason 표시).
// 반환 0=성공, 1=오류(취소 포함 — 메시지에 사유).
@_cdecl("pasuSEOpen")
public func pasuSEOpen(
	_ blob: UnsafePointer<UInt8>?, _ blobLen: Int32,
	_ eph: UnsafePointer<UInt8>?, _ ephLen: Int32,
	_ ct: UnsafePointer<UInt8>?, _ ctLen: Int32,
	_ reason: UnsafePointer<CChar>?,
	_ outSecret: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
	_ outSecretLen: UnsafeMutablePointer<Int32>?,
	_ errBuf: UnsafeMutablePointer<CChar>?, _ errLen: Int32
) -> Int32 {
	guard let blob, blobLen > 0, let eph, ephLen > 0, let ct, ctLen > 0 else {
		return fail("빈 입력", errBuf, errLen)
	}
	let ctx = LAContext()
	if let reason {
		ctx.localizedReason = String(cString: reason)
	}
	do {
		let seKey = try SecureEnclave.P256.KeyAgreement.PrivateKey(
			dataRepresentation: Data(bytes: blob, count: Int(blobLen)),
			authenticationContext: ctx)
		let ephData = Data(bytes: eph, count: Int(ephLen))
		let ephPub = try P256.KeyAgreement.PublicKey(rawRepresentation: ephData)
		let shared = try seKey.sharedSecretFromKeyAgreement(with: ephPub)
		let sym = deriveKey(shared, ephPub: ephData, sePub: seKey.publicKey.rawRepresentation)
		let box = try AES.GCM.SealedBox(combined: Data(bytes: ct, count: Int(ctLen)))
		let pt = try AES.GCM.open(box, using: sym)
		guard copyOut(pt, outSecret, outSecretLen) else {
			return fail("출력 버퍼 할당 실패", errBuf, errLen)
		}
		return 0
	} catch {
		return fail("SE 해제 실패: \(error)", errBuf, errLen)
	}
}
