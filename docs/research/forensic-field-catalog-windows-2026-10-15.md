# 아티팩트 그리드 필드 카탈로그 — Windows 7계열 (조사 2026-10-15)

출처 표기: [V] = 웹 출처로 확인, [G] = 일반 지식(실제 이미지로 검증 필요). 이벤트 ID는 [V]만 확정으로 취급.
공통 규칙: 시각 열은 항상 종류(`ts_kind`: logged / first_seen / last_run / created / modified / mft_changed / accessed / deleted / key_lastwrite)와 시간대를 함께 표기. setupapi.dev.log는 로컬시간·TZ 미표기 [V].

## 1. 이벤트 로그 (Security/System/Application/PowerShell/Sysmon/RDP/TS)
핵심 열(순서): TimeCreated(logged, UTC) · Channel/Provider · EventID(+한글 요약) · Computer · Subject/TargetUserName(+SID) · LogonType(4624/4625) · IpAddress/WorkstationName · Image/NewProcessName + CommandLine(4688, Sysmon 1) · LogonId(4624↔4688↔Sysmon 1 상관키 [V]) · EventRecordID(갭 탐지).
보조 열: ProcessId/ParentImage, TargetLogonId, AuthenticationPackage, Status/SubStatus(4625), ServiceName/ImagePath(7045), TaskName/TaskContent(4698), ScriptBlockText(4104), Sysmon Hashes/DestinationIp/TargetFilename/TargetObject(13)/QueryName(22), ProviderGuid, Level/Opcode, evtx 경로, 원본 XML.
확인된 ID [V]: 4624/4625 로그온·실패, 4634/4647 로그오프, 4648 명시적 자격증명, 4672 특수권한, 4688 프로세스 생성, 4697 서비스 설치(Security), 4698/4699/4700/4701/4702 작업, 4720 계정 생성, 4722 활성화, 4724 암호 재설정, 4732 로컬 그룹 추가, 4738 계정 변경, 4740 잠금, 4768/4769 Kerberos, 4776 NTLM, 4778/4779 RDP 재연결/해제, 4798/4799 그룹 열거, 1102 Security 로그 삭제, 104 로그 삭제, System 7045 서비스 설치, PowerShell 4103/4104, Sysmon 1,2,3,7,8,9,10,11,12,13,14,22(255 오류).

| 지표 | 규칙 | 의미 | 오탐 |
|---|---|---|---|
| RDP_외부IP | 4624 LogonType=10 이고 IpAddress가 RFC1918/loopback/link-local 아님 | 인터넷 노출 RDP 침입 | VPN/점프호스트 NAT, IPv6 |
| 4625_폭주 | 같은 IpAddress/TargetUserName 4625가 N분 내 ≥N건 | 무차별 대입 | 만료 서비스 계정, 스캐너 |
| 폭주 후 성공 | 4625 폭주 뒤 같은 출처 4624 | 성공한 brute force | 오타 |
| 로그_삭제 | 1102/104 존재, RecordNumber 리셋/갭 | 안티포렌식 [V] | 에이전트 롤아웃, 골든이미지(Sigma [V]) |
| 신규_서비스 | 7045/4697, ImagePath에 Temp/AppData/UNC/cmd/powershell | 지속성/횡이동(PsExec류) | 정상 설치/드라이버(Subject=SYSTEM 흔함) |
| 인코딩_PS | 4688/Sysmon1 CommandLine에 -enc/-EncodedCommand/IEX/FromBase64String, 4104 난독화 | 은닉 실행 | 관리 스크립트 |
| 작업_생성 | 4698/4702 + 실행파일이 사용자 쓰기 경로 | 지속성 | 정상 업데이터 |
| 계정_조작 | 4720 후 4732(관리자) 근접, 4724 | 백도어 계정 | 정상 프로비저닝 |
| 명시적_자격증명 | 4648 TargetServer≠localhost, 비표준 프로세스 | 횡이동 | RunAs, 예약작업 |
| 업무외_시간 | 4624 시각이 계정 평소 분포 밖 | 이상 접근 | 교대근무 |
| Sysmon_주입 | Sysmon 8/10 비정상 소스 | 인젝션 | AV/EDR |
| 감사_공백 | 4688/4104 등 예상 이벤트 부재 | 감사정책 미설정 가능 | 정책 미활성 → "부재 ≠ 미발생" 배너 |
출처: learn.microsoft.com/sysinternals/downloads/sysmon · docs.logpoint.com/agentx/references/windows-event-ids-reference · detection.fyi (win_system_eventlog_cleared) · manageengine.com (7045)

## 1-b. RDP / 원격접속
핵심 열: ts(logged) · 방향(inbound/outbound) · Event(채널:ID) · User · SourceIP · SessionID · LogonType · 대상 호스트(outbound) · LogonId · 결과.
확인된 ID [V]: TS-RemoteConnectionManager 1149(인증 단계, 완전 로그온 아님), TS-LocalSessionManager 21/22/23/24/25/40, RdpCoreTS 131/98, 소스측 TS-RDPClient 1024, Security 4624/4625/4634/4647/4778/4779/4648.
보조 열: 소스 포트, 클라이언트 버전, `Terminal Server Client\Servers`·Default MRU [G], bitmap cache [G], mstsc Prefetch/Amcache, fDenyTSConnections 변경(Sysmon 13 [G]).

| 지표 | 규칙 | 의미 | 오탐 |
|---|---|---|---|
| 외부IP_RDP | 1149/131의 IP가 사설망 외 | 노출 RDP | VPN 게이트웨이 |
| 짝_불일치 | 1149 없는 21 / 21 없는 1149 | NLA 단계만 vs 실제 세션 구분 [V] | NLA 실패, 스캔 |
| 세션_하이재킹 | 4778/4779, 25 재연결이 이질적 IP·계정 | 세션 탈취 | 사용자 재접속 |
| 아웃바운드_RDP | 소스측 1024 + 4648 | 횡이동 소스 | 관리자 접속 |
| RDP_활성화 | fDenyTSConnections 변경 | 공격자 RDP 활성화 | 정상 구성 |
| 다중_호스트 | 같은 계정 단시간 다수 호스트 type 10 | 횡이동 | 점프 서버 |
출처: frsecure.com/blog/rdp-connection-event-logs · magnetforensics.com (rdp-artifacts) · andreafortuna.org (rdp event ids) · cybertriage.com/?p=26680

## 2. 레지스트리
핵심 열: ts(key LastWrite) · Hive(경로, 사용자/SID) · KeyPath · ValueName · ValueType · ValueData(디코딩) · 분류(Run/UserAssist/ShellBag/USB/MRU/Service) · 사용자 · 값 내부 시각(UserAssist last run 등 별도 ts_kind).
위치 [V]: UserAssist `…\Explorer\UserAssist`(ROT13, 마지막 실행·횟수·경로) · ShellBags `Shell\BagMRU`+`\Bags`(UsrClass.dat [G], 삭제 폴더 포함) · USBSTOR `SYSTEM\Enum\USBSTOR` · MountedDevices(드라이브 문자/볼륨GUID↔장치, 시리얼 평문) · MountPoints2(NTUSER: 볼륨GUID→사용자) · Windows Portable Devices · Run/RunOnce, Services, MRU(RecentDocs/OpenSavePidlMRU/RunMRU), TypedPaths [G].
보조 열: Run 키 전체(HKLM/HKCU Run·RunOnce, Winlogon Shell/Userinit, IFEO Debugger, AppInit_DLLs, Services Start=2), MRU 순서, 이진 hex, 트랜잭션 로그(.LOG1/.LOG2) 복구 여부, 삭제 키 플래그.

| 지표 | 규칙 | 의미 | 오탐 |
|---|---|---|---|
| Run_사용자경로 | Run/RunOnce 값이 Temp/AppData/Public/Downloads, 인코딩 PS/LOLBin | 지속성 | 자동업데이트 |
| 서비스_이상 | ImagePath 사용자 쓰기 경로/cmd /c/비서명, Start=2 | 악성 서비스 | 서드파티 |
| LastWrite_이상 | 지속성 키 LastWrite가 사건 시간대 | 변경 시점 | 설치/패치 |
| USB_시리얼_교차 | USBSTOR↔MountedDevices↔MountPoints2↔LNK VSN 일치 | 사용자-장치 연결 | 시리얼 없는 장치(UASP→Enum\SCSI [V]) |
| UserAssist_경로 | 실행 경로가 Temp/이동식/UNC | 의심 실행 | 포터블 앱 |
| ShellBag_이동식/네트워크 | 탐색 경로가 이동식·UNC·삭제 폴더 | 유출/접근 | 공유 사용 |
| TypedPaths_UNC | UNC/관리자 공유 입력 | 횡이동 [G] | 관리자 |
출처: cybertriage.com registry cheat sheet 2026 · sans.org (application execution) · forensics.wiki/usb_history_viewing · andreafortuna.org (program execution)

## 3. 실행 흔적 (Prefetch/Amcache/ShimCache/BAM·DAM/SRUM)
핵심 열: ts(종류별) · ExecutableName · FullPath · 아티팩트 종류 · RunCount · LastRun(최근 8회 Win8+ [V]) · FirstRun/Created · SHA1(Amcache) · 사용자(BAM SID/SRUM UserSID).
[V] Prefetch v30/v31(MAM 압축), 8개 실행시각, 볼륨 정보, 참조 파일; Amcache.hve 최초 실행·이동식 포함; ShimCache는 "존재" 증거(Win10+); BAM/DAM `Services\{bam|dam}\State\UserSettings\{SID}`; SRUM `sru\SRUDB.dat` ESE, 테이블 Network Data Usage {973F5D5C-…}, Application Resource Usage {D10CA2FE-…}, 필드 ApplicationName/UserSID/InterfaceLuid/BytesSent/BytesRecvd.
보조 열: Prefetch 로드 파일 목록, 볼륨 시리얼/생성시각, Amcache ProgramId/Publisher/Version/LinkDate, ShimCache 순서·ModifiedTime($SI, 실행시각 아님), SRUM 인터페이스/프로필.

| 지표 | 규칙 | 의미 | 오탐 |
|---|---|---|---|
| 의심경로_실행 | FullPath가 Temp/Downloads/AppData/Public/Recycle Bin/이동식 | 드롭/포터블 악성 | 설치 프로그램 |
| 실행횟수_급증 | 단기간 RunCount 증가, 1회 후 삭제 | 단발 도구 | 스케줄 작업 |
| 이름_불일치 | Prefetch 이름≠Amcache 경로, 시스템 바이너리 이름이 System32 외 | 마스커레이딩 | 동명 정상 복사본 |
| 삭제된_실행파일 | Prefetch/Amcache/BAM에 있으나 MFT에 없음 | 증거 인멸 | 삭제된 설치기 |
| 교차_불일치 | Shim에 있으나 Prefetch/Amcache 없음 | 프리페치 비활성/삭제 | Server는 기본 비활성 |
| SRUM_대량_송신 | 비정상 앱 BytesSent 급증 | 유출 | 백업/동기화 |
| 이중_출처 | 동일 exe가 Prefetch+Amcache+BAM | 실행 신뢰도 상승 | — |
출처: sans.org (application execution) · belkasoft.com/windows-prefetch-forensics · magnetforensics.com (SRUM) · docs.velociraptor.app (EvidenceOfExecution)

## 4. LNK / Jump Lists
핵심 열: ts 4종(Source Created≈최초 접근, Source Modified≈최근 접근, Target Created, Target Modified [V]) · LinkPath · TargetPath · DriveType(local/removable/network) · VolumeSerial · VolumeLabel · TargetSize · 사용자.
보조 열: MachineID(NetBIOS) · MAC · TrackerCreatedOn(UUIDv1) · Target MFT entry/seq · Arguments · WorkingDir · ShowWindow · 아이콘 · 공유명 · Jump List AppID/종류(Automatic/Custom)/DestList MRU 순서·횟수·마지막 사용·호스트명. 위치 [V]: `%APPDATA%\Microsoft\Windows\Recent\{AutomaticDestinations,CustomDestinations}`; AppID 매핑은 파서 DB 사용.

| 지표 | 규칙 | 의미 | 오탐 |
|---|---|---|---|
| 이동식_타깃 | DriveType=removable 또는 VSN이 USBSTOR/MountedDevices와 일치 | 이동식 매체 접근 | 정상 USB |
| 네트워크_타깃 | DriveType=network/UNC | 공유 접근/횡이동 | 정상 공유 |
| 대상_없음 | TargetPath가 MFT에 없음 | 접근 후 삭제 | 이동식 분리 |
| 사용자경로_실행 | Temp/Downloads 실행파일 | 사용자 실행 | — |
| 타_호스트_기원 | MachineID/MAC ≠ 현재 호스트 | 피싱 LNK/복사 | 이미지 복제 |
| 타임스탬프_이상 | Target Created > Source Created, Target 시각 0 | 조작/복사 | 복사 |
출처: csirt.gov.sk LNK_File_Forensics · forensics.wiki/jump_lists · it-connect.tech (jump lists) · MS-SHLLINK

## 5. OS·계정 (SAM/SECURITY/SYSTEM, 프로필, 작업, 서비스, WER)
핵심 열: ts(account_created/last_logon/pwd_last_set/task_created/last_run) · 객체 유형 · 이름 · SID/RID · 상태 · 경로(실행파일/ProfilePath/TaskPath) · RunAs · 트리거/시작 유형 · 출처 하이브/파일.
보조 열 [G]: SAM F/V(LastLogon, LastPasswordChange, FailedLoginCount, LoginCount, RID 500/501/544 멤버십, 힌트), SYSTEM(ComputerName, TimeZoneInformation, 서비스 ImagePath/ServiceDll/FailureActions), ProfileList, 작업 XML(트리거/Actions/Hidden/RunLevel), WER Report.wer(AppPath, EventTime, 모듈), 이벤트 4720/4722/4724/4732/4738/4740/4698–4702/7045/4697 [V].

| 지표 | 규칙 | 의미 | 오탐 |
|---|---|---|---|
| 신규_계정 | 사건 시간대 4720·신규 RID, `$` 끝 숨김 계정 [G] | 백도어 | 프로비저닝 |
| 관리자_추가 | 4732 Administrators | 권한상승 | 정상 관리 |
| 작업_의심 | Actions가 사용자 쓰기 경로/PS/LOLBin, SYSTEM, 숨김, 분 단위 트리거 | 지속성 | 업데이터 |
| 작업_불일치 | Tasks 파일 vs TaskCache 레지스트리 불일치 [G] | 숨김 작업 | 손상 |
| 서비스_의심 | 7045/4697 + 사용자경로·비서명·비표준 ServiceDll | 지속성 | 드라이버 |
| 프로필_이상 | 비표준 ProfileList 경로, 로그인 없는 프로필 활동 | 은닉 계정 | 이전 프로필 |
| WER_이상 | 비정상 앱 충돌(삭제된 exe 흔적) | 실행 보강 [G] | 정상 크래시 |
출처: logpoint event ids · manageengine (4698) · cybertriage registry cheat sheet · sans.org

## 6. NTFS ($MFT/$UsnJrnl/$LogFile, 타임스탬프 조작, ADS, 휴지통)
핵심 열: ts 8종($SI/$FN × Created/Modified/MFTChanged/Accessed, ts_kind 필수) · FullPath · FileRef(MFT#+Seq) · Size · InUse · Flags(Dir/Hidden/System) · ADS 이름 · ParentRef · USN(Reason/Time).
보조 열: $UsnJrnl(USN, Reason, FRN, ParentFRN, 이름, 시각 [V]) · $LogFile 트랜잭션 · $I30 슬랙 [V] · 휴지통 $I/$R(원본 경로·크기·삭제시각, Vista+ [V]) · SecurityId · ObjectId · 압축/암호화 · ResidentData.

| 지표 | 규칙 | 의미 | 오탐 |
|---|---|---|---|
| SI_Created<FN_Created | $SI 생성이 $FN 생성보다 이름 [V] | 사용자모드 timestomp | 이동/복사, 설치기 |
| 나노초_0 | $SI sub-second=0, $FN 비0 [V] | 초 단위 도구(약한 지표) | 일부 정상 SW/FAT 유래 |
| FN_조작 | USN RENAME 이벤트와 $FN 시각 불일치 [V] | 고급 timestomp | 정상 이동 |
| USN_BasicInfoChange | BasicInfoChange 후 $SI 시각이 과거 [V] | 조작 시점 | 속성 변경도 동일 플래그 → 단독 금지 |
| 시각_역전 | Modified<Created 등 비논리 | 복사 vs 조작 | 복사 파일은 정상 |
| 실행파일_ADS | ADS 스트림이 PE(MZ) | 은닉 페이로드 | Zone.Identifier 정상 |
| Zone.Identifier | ZoneId=3 + HostUrl | 다운로드 출처 | — |
| 삭제_흔적 | $I30 슬랙, !InUse, 휴지통 $I 민감 파일 | 삭제 증거 [V] | 정상 삭제 |
| 대량_변경 | USN 단시간 대량 RENAME/DELETE | 랜섬웨어/와이핑 | 백업/AV |
출처: inversecos.com (timestomping) · opus.bibliothek.uni-augsburg.de 117569 · andreafortuna.org (usn-journal) · sans.org ($I30) · andreafortuna.org (recycle bin)

## 7. USB / 이동식 장치
핵심 열: ts(first_install/first_connect/last_connect/last_removal) · VID/PID · Vendor/Model · SerialNumber · 드라이브 문자/볼륨 GUID · VSN · VolumeLabel · 사용자(MountPoints2) · 출처.
소스·ID [V]: DriverFrameworks-UserMode/Operational 2003/2004/2006/2010/2100/2101/2105/2106(연결), 2102(제거), LifetimeId 상관(2100/2101 의미는 출처 간 불일치 → 검증 필요) · Kernel-PnP 400/410/430 · UserPnp 20001/20003 · Partition/Diagnostic 1006(제조사/모델/시리얼/파티션/VSN) · Security 6416/4663 · 레지스트리 USBSTOR/MountedDevices/MountPoints2/WPD · setupapi.dev.log. 이벤트 로그는 복수 연결 보존, 레지스트리는 최신만 [V].
보조 열: ParentIdPrefix, ContainerID, Class/ClassGUID, UASP(Enum\SCSI), 마지막 마운트 드라이브, 파일 복사 증거(LNK/JumpList/ShellBag), MBR/파티션 식별자.

| 지표 | 규칙 | 의미 | 오탐 |
|---|---|---|---|
| 신규_장치 | 사건 시간대 최초 연결 | 신규 이동식 | 정상 USB |
| 시리얼_부재 | 시리얼 없음/Generic/중복 | 신뢰도 낮음/복제 | 저가 USB |
| 대용량_저장소 | Mass Storage + 사건 인근 대량 열람(LNK/ShellBag/JumpList) | 유출 | 백업 |
| 비저장_USB | HID 키보드 신규 → BadUSB [G] | 입력 위장 | 새 키보드 |
| 교차_일치 | USBSTOR VSN↔LNK VSN↔MountedDevices [V] | 사용자-장치-파일 | 재포맷 시 VSN 변경 |
| 로그_비활성 | DriverFrameworks/Partition 로그 비활성 | 이벤트 증거 부재 | 기본 설정 |
출처: docs.nxlog.co (windows usb auditing) · forensics.wiki/usb_history_viewing · it-connect.tech (usb history) · hackmd.io/@M4shl3/USB-Forensics

## 구현 메모
- 시각 열은 `ts_kind`와 함께; $SI/$FN, LNK source/target, 레지스트리 LastWrite vs 값 내부 시각 구분.
- 지표 3단계: A(단독 강함: 1102/104, SI<FN+USN, 외부IP RDP) · B(조합 필요: 4625 폭주+성공, 의심경로 실행) · C(약함: 나노초 0, 업무외 시간).
- 정책 의존 이벤트(4688/4104/6416/DriverFrameworks)는 "부재 ≠ 미발생" 배너.
- [G] 항목은 실제 이미지(bsh-e01)로 확인 후 반영.
