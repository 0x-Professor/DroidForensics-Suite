# DIGITAL FORENSICS INVESTIGATION REPORT

## CLASSIFICATION: OFFICIAL USE ONLY

---

## CASE INFORMATION

| Field | Value |
|-------|-------|
| Case Number | 001 |
| Examiner | FIA Officer |
| Agency | Federal Investigation Agency |
| Investigation Started | 2025-12-23T12:16:45.688052 |
| Report Generated | 2025-12-23T12:21:39.653024 |
| Case Notes |  |

---

## DEVICE INFORMATION

| Property | Value |
|----------|-------|
| Manufacturer | realme |
| Model | RMX3760 |
| Brand | realme |
| Device | RE58C2 |
| Android Version | 14 |
| Sdk Version | 34 |
| Build Id | UP1A.231005.007 |
| Security Patch | 2025-02-01 |
| Serial | 0H73C14I221025B8 |
| Hardware | ums9230_hulk |
| Bootloader | unknown |
| Baseband | O_V1_P16,O_V1_P16 |
| Fingerprint | realme/RMX3760/RE58C2:14/UP1A.231005.007/T.R4T2.1739756167:user/release-keys |
| Device Id | 0H73C14I221025B8 |

---

## ACQUIRED EVIDENCE

### DEVICE INFO

**Type:** device  
**Acquired:** 2025-12-23T12:16:50.689668

```json
{
  "manufacturer": "realme",
  "model": "RMX3760",
  "brand": "realme",
  "device": "RE58C2",
  "android_version": "14",
  "sdk_version": "34",
  "build_id": "UP1A.231005.007",
  "security_patch": "2025-02-01",
  "serial": "0H73C14I221025B8",
  "hardware": "ums9230_hulk",
  "bootloader": "unknown",
  "baseband": "O_V1_P16,O_V1_P16",
  "fingerprint": "realme/RMX3760/RE58C2:14/UP1A.231005.007/T.R4T2.1739756167:user/release-keys",
  "device_id": "0H73C14I221025B8"
}
```

### INSTALLED PACKAGES

**Type:** packages  
**Acquired:** 2025-12-23T12:17:09.570372

*311 items acquired*

### LOGCAT

**Type:** logs  
**Acquired:** 2025-12-23T12:17:49.152382

```
--------- beginning of main
12-23 12:17:40.098  1381 18952 D BLASTBufferQueue: [VRI[StatusBar]#3](f:0,a:2) PendingRelease=1, PendingBuffersToHold=0, SyncedFrameNumbers=0, lacfnr:8690, lapfnr:8690
12-23 12:17:40.356   870  1483 D GNSSMGT : WaitEvent: sem_timedwait ret:-1
12-23 12:17:40.356   870  1483 E GNSSMGT : WaitEvent: wait timeout
12-23 12:17:40.356   870  1483 D GNSSMGT : compute_abs_timeout: enter, ms[500]
--------- beginning of system
12-23 12:17:40.404  1108  1154 V SomeArgsObtain: sPoolSize = 10,spool is:com.android.internal.os.SomeArgs@da563e9
12-23 12:17:40.405  1108  1154 V SomeArgsObtain: sPoolSize = 9,spool is:com.android.internal.os.SomeArgs@a3b7ba1
12-23 12:17:40.406  1108  1224 V SomeArgsRecycle: sPoolSize = 9,spool is:com.android.internal.os.SomeArgs@da563e9
12-23 12:17:40.406  1108  1224 V SomeArgsRecycle: sPoolSize = 10,spool is:com.android.internal.os.SomeArgs@a3b7ba1
12-23 12:17:40.409  1108  1922 D AppStartupManager: error happend in shouldPreventStartService:checkStartupLimit
12-23 12:17:40.415  1108  1154 V SomeArgsObtain: sPoolSize = 10,spool is:com.android.internal.os.SomeArgs@a3b7ba1
12-23 12:17:40.416  1108  1154 V SomeArgsObtain: sPoolSize = 9,spool is:com.android.internal.os.SomeArgs@da563e9
12-23 12:17:40.417  1108  1224 V SomeArgsRecycle: sPoolSize = 9,spool is:com.android.internal.os.SomeArgs@a3b7ba1
12-23 12:17:40.418  1108  1224 V SomeArgsRecycle: sPoolSize = 10,spool is:com.android.internal.os.SomeArgs@da563e9
12-23 12:17:40.423  1108  1271 D WifiStaIfaceHidlImpl: getCachedScanData is not implemented by HIDL
12-23 12:17:40.434  1108  1271 I HalDevMgr: bestIfaceCreationProposal is null, requestIface=STA, existingIface=[name=wlan0 type=STA]
12-23 12:17:40.436  1381  1381 D WifiSignalController: connected:trueinet:1isdefault:true
12-23 12:17:40.439  1381  1381 D Tile.WifiTile: onWifiSignalChanged enabled=true
12-23 12:17:40.439  1381  1637 D Tile.WifiTile: handleUpdateState arg=null
12-23 12:17:40.440  1381  1637 D Tile.WifiTile: h
```

### PROCESSES

**Type:** system  
**Acquired:** 2025-12-23T12:18:06.579686

```
USER           PID  PPID        VSZ    RSS WCHAN            ADDR S NAME                       
root             1     0   11048284   5008 0                   0 S init
root             2     0          0      0 0                   0 S [kthreadd]
root             3     2          0      0 0                   0 I [rcu_gp]
root             4     2          0      0 0                   0 I [rcu_par_gp]
root             8     2          0      0 0                   0 I [mm_percpu_wq]
root            10     2          0      0 0                   0 S [ksoftirqd/0]
root            11     2          0      0 0                   0 I [rcu_preempt]
root            12     2          0      0 0                   0 S [migration/0]
root            14     2          0      0 0                   0 S [cpuhp/0]
root            15     2          0      0 0                   0 S [cpuhp/1]
root            16     2          0      0 0                   0 S [migration/1]
root            17     2          0      0 0                   0 S [ksoftirqd/1]
root            20     2          0      0 0                   0 S [cpuhp/2]
root            21     2          0      0 0                   0 S [migration/2]
root            22     2          0      0 0                   0 S [ksoftirqd/2]
root            25     2          0      0 0                   0 S [cpuhp/3]
root            26     2          0      0 0                   0 S [migration/3]
root            27     2          0      0 0                   0 S [ksoftirqd/3]
root            30     2          0      0 0                   0 S [cpuhp/4]
root            31     2          0      0 0                   0 S [migration/4]
root            32     2          0      0 0                   0 S [ksoftirqd/4]
root            35     2          0      0 0                   0 S [cpuhp/5]
root            36     2          0      0 0                   0 S [migration/5]
root            37     2          0      0 0                   0 S [ksoftirqd/5]
ro
```

### CONTACTS

**Type:** contacts  
**Acquired:** 2025-12-23T12:18:35.894686

```
Row: 0 starred=0, number=+92 300 5695159, person=3121, last_time_contacted=0, number_key=951596500329+, custom_ringtone=NULL, primary_organization=NULL, phonetic_name=, primary_email=NULL, primary_phone=NULL, _id=12636, name=Bilal Lala, type=2, label=NULL, notes=NULL, send_to_voicemail=0, display_name=Bilal Lala, times_contacted=0, isprimary=0
Row: 1 starred=0, number=+92 304 0678292, person=266, last_time_contacted=0, number_key=292876040329+, custom_ringtone=NULL, primary_organization=NULL, phonetic_name=, primary_email=NULL, primary_phone=NULL, _id=949, name=Jawad Akram BBA, type=2, label=NULL, notes=NULL, send_to_voicemail=0, display_name=Jawad Akram BBA, times_contacted=0, isprimary=0
Row: 2 starred=0, number=+92 314 3978077, person=3149, last_time_contacted=0, number_key=770879341329+, custom_ringtone=NULL, primary_organization=NULL, phonetic_name=, primary_email=NULL, primary_phone=NULL, _id=12720, name=Ahmed Hostel, type=2, label=NULL, notes=NULL, send_to_voicemail=0, display_name=Ahmed Hostel, times_contacted=0, isprimary=0
Row: 3 starred=0, number=+92 314 3978077, person=3151, last_time_contacted=0, number_key=770879341329+, custom_ringtone=NULL, primary_organization=NULL, phonetic_name=, primary_email=NULL, primary_phone=NULL, _id=12730, name=Ahmed Hostel, type=2, label=NULL, notes=NULL, send_to_voicemail=0, display_name=Ahmed Hostel, times_contacted=0, isprimary=0
Row: 4 starred=0, number=+92 315 8880444, person=241, last_time_contacted=0, number_key=444088851329+, custom_ringtone=NULL, primary_organization=NULL, phonetic_name=, primary_email=NULL, primary_phone=NULL, _id=822, name=Muhammad Saad New, type=2, label=NULL, notes=NULL, send_to_voicemail=0, display_name=Muhammad Saad New, times_contacted=0, isprimary=0
Row: 5 starred=0, number=+92 315 8880444, person=242, last_time_contacted=0, number_key=444088851329+, custom_ringtone=NULL, primary_organization=NULL, phonetic_name=, primary_email=NULL, primary_phone=NULL, _id=827, name=Saad Kamra, type=2, la
```

### CALL LOG

**Type:** calls  
**Acquired:** 2025-12-23T12:18:56.889879

```
Row: 0 date=1750312804859, phone_account_hidden=0, transcription=NULL, photo_id=0, subscription_component_name=com.android.phone/com.android.services.telephony.TelephonyConnectionService, subject=NULL, call_screening_app_name=NULL, type=1, geocoded_location=Pakistan, presentation=1, duration=30, subscription_id=2, is_read=NULL, suggest_text_1=, number=03189864005, features=0, voicemail_uri=NULL, suggest_text_2=03189864005, normalized_number=+923189864005, composer_photo_uri=NULL, normalized_full_name=NULL, via_number=, matched_number=NULL, last_modified=1750312842076, new=1, numberlabel=, missed_reason=0, suggest_intent_data_id=201, lookup_uri=, photo_uri=, data_usage=NULL, phone_account_address=, formatted_number=0318 9864005, add_for_all_users=1, block_reason=0, priority=0, numbertype=0, call_screening_component_name=NULL, normalized_simple_name=NULL, countryiso=PK, is_call_log_phone_account_migration_pending=0, name=, post_dial_digits=, transcription_state=0, location=NULL, _id=201
Row: 1 date=1750313066471, phone_account_hidden=0, transcription=NULL, photo_id=0, subscription_component_name=com.android.phone/com.android.services.telephony.TelephonyConnectionService, subject=NULL, call_screening_app_name=NULL, type=1, geocoded_location=Pakistan, presentation=1, duration=7, subscription_id=2, is_read=NULL, suggest_text_1=, number=03189864005, features=0, voicemail_uri=NULL, suggest_text_2=03189864005, normalized_number=+923189864005, composer_photo_uri=NULL, normalized_full_name=NULL, via_number=, matched_number=NULL, last_modified=1750313084070, new=1, numberlabel=, missed_reason=0, suggest_intent_data_id=202, lookup_uri=, photo_uri=, data_usage=NULL, phone_account_address=, formatted_number=0318 9864005, add_for_all_users=1, block_reason=0, priority=0, numbertype=0, call_screening_component_name=NULL, normalized_simple_name=NULL, countryiso=PK, is_call_log_phone_account_migration_pending=0, name=, post_dial_digits=, transcription_state=0, location=NULL, _id=202
R
```

### SMS

**Type:** messages  
**Acquired:** 2025-12-23T12:19:21.206885

```
Row: 0 _id=307, thread_id=17, address=Telenor, person=NULL, date=1766389398386, date_sent=1766389398000, protocol=0, read=0, status=-1, type=1, reply_path_present=0, subject=proto:CjoKImNvbS5nb29nbGUuYW5kcm9pZC5hcHBzLm1lc3NhZ2luZy4SFCIAKhDedhORlsdKOaFcZqtJWOVu, body=Rs.600 ka discount. Monthly Prime offer ab 2300 nahi sirf 1700 mein. 300 GB data aur 10 000 All network mins pore 30 din k liye, service_center=+923450000917, locked=0, sub_id=3, error_code=-1, creator=com.google.android.apps.messaging, seen=1
Row: 1 _id=306, thread_id=22, address=14250, person=NULL, date=1766322064303, date_sent=1766322063000, protocol=0, read=0, status=-1, type=1, reply_path_present=0, subject=proto:CjoKImNvbS5nb29nbGUuYW5kcm9pZC5hcHBzLm1lc3NhZ2luZy4SFCIAKhDXcdJqFKhIhapjj2Ikhv/c, body=Your HBL Debit Card has been charged for a Transaction of PKR 191.00 on 21/12/2025 ., service_center=+923450000927, locked=0, sub_id=3, error_code=-1, creator=com.google.android.apps.messaging, seen=1
Row: 2 _id=305, thread_id=22, address=14250, person=NULL, date=1766321798487, date_sent=1766321797000, protocol=0, read=0, status=-1, type=1, reply_path_present=0, subject=proto:CjoKImNvbS5nb29nbGUuYW5kcm9pZC5hcHBzLm1lc3NhZ2luZy4SFCIAKhBrjD/ZGvZHN4eUuUJSpqY2, body=Your HBL Debit Card has been charged for a Transaction of PKR 191.00 on 21/12/2025 ., service_center=+923450000927, locked=0, sub_id=3, error_code=-1, creator=com.google.android.apps.messaging, seen=1
Row: 3 _id=304, thread_id=22, address=14250, person=NULL, date=1766321271129, date_sent=1766321269000, protocol=0, read=0, status=-1, type=1, reply_path_present=0, subject=proto:CjoKImNvbS5nb29nbGUuYW5kcm9pZC5hcHBzLm1lc3NhZ2luZy4SFCIAKhDvWUSvRchM6r1Z659gsYrZ, body=Your HBL Debit Card has been charged for a Transaction of PKR 100.00 on 21/12/2025 ., service_center=+923450000927, locked=0, sub_id=3, error_code=-1, creator=com.google.android.apps.messaging, seen=1
Row: 4 _id=303, thread_id=22, address=14250, person=NULL, date=1766305327711, date_sent=176
```

### STORAGE

**Type:** system  
**Acquired:** 2025-12-23T12:19:45.927843

```
Filesystem            Size Used Avail Use% Mounted on
/dev/block/dm-7       2.8G 2.8G     0 100% /
tmpfs                 2.8G 1.6M  2.8G   1% /dev
tmpfs                 2.8G    0  2.8G   0% /mnt
/dev/block/dm-8       709M 709M     0 100% /system_ext
/dev/block/dm-9       531M 531M     0 100% /vendor
/dev/block/dm-10      320M 320M     0 100% /odm
/dev/block/dm-11      1.5G 1.5G     0 100% /product
/dev/block/dm-12      9.2M 9.2M     0 100% /vendor_dlkm
tmpfs                 2.8G 124K  2.8G   1% /apex
/dev/block/mmcblk0p48  62M  48M   14M  78% /cache
/dev/block/mmcblk0p46 1.6G 435M  1.2G  26% /my_preload
/dev/block/dm-47      106G  52G   54G  50% /data
/dev/block/loop5      232K  96K  132K  43% /apex/com.android.apex.cts.shim@1
/dev/block/loop6       25M  25M     0 100% /apex/com.android.btservices@340090000
/dev/block/dm-44       10M  10M     0 100% /apex/com.android.wifi@361153320
/dev/block/loop10      10M  10M     0 100% /apex/com.android.runtime@1
/dev/block/dm-43       29M  29M     0 100% /apex/com.android.media.swcodec@361153320
/dev/block/loop11     304K 272K   28K  91% /apex/com.android.virt@2
/dev/block/dm-42       11M  11M     0 100% /apex/com.android.adbd@361153600
/dev/block/loop14      38M  38M     0 100% /apex/com.android.i18n@1
/dev/block/dm-39      7.3M 7.3M     0 100% /apex/com.android.conscrypt@361153320
/dev/block/dm-38      740K 712K   16K  98% /apex/com.android.tzdata@343102000
/dev/block/dm-36       15M  15M     0 100% /apex/com.android.healthfitness@361153320
/dev/block/loop17     5.4M 5.3M     0 100% /apex/com.android.devicelock@1
/dev/block/dm-35       22M  22M     0 100% /apex/com.android.adservices@361153320
/dev/block/loop19      41M  41M     0 100% /apex/com.android.vndk.v34@1
/dev/block/dm-33      4.0M 4.0M     0 100% /apex/com.android.appsearch@361153980
/dev/block/dm-27      840K 812K   12K  99% /apex/com.android.ipsec@361153320
/dev/block/dm-28      5.3M 5.3M     0 100% /apex/com.android.configinfrastructure@361153320
/dev/block/loop
```

### IMAGES

**Type:** images  
**Acquired:** 2025-12-23T12:20:43.428592

```
Row: 0 instance_id=NULL, compilation=NULL, disc_number=NULL, duration=NULL, album_artist=NULL, description=NULL, picasa_id=NULL, resolution=976×1600, latitude=NULL, orientation=NULL, artist=NULL, author=NULL, inferred_date=NULL, height=1600, is_drm=0, bucket_display_name=WhatsApp Images, owner_package_name=com.whatsapp, f_number=NULL, volume_name=external_primary, date_modified=1752819426, writer=NULL, date_expires=NULL, composer=NULL, _display_name=IMG-20250718-WA0017.jpg, scene_capture_type=NULL, datetaken=NULL, mime_type=image/jpeg, bitrate=NULL, cd_track_number=NULL, _id=1000001824, iso=NULL, xmp=BLOB, year=NULL, oem_metadata=NULL, _data=/storage/emulated/0/Android/media/com.whatsapp/WhatsApp/Media/WhatsApp Images/IMG-20250718-WA0017.jpg, _size=39873, album=NULL, genre=NULL, title=IMG-20250718-WA0017, width=976, longitude=NULL, is_favorite=0, is_trashed=0, exposure_time=NULL, group_id=NULL, document_id=NULL, generation_added=11645, is_download=0, generation_modified=11656, is_pending=0, date_added=1752819425, mini_thumb_magic=NULL, capture_framerate=NULL, num_tracks=NULL, isprivate=NULL, original_document_id=NULL, bucket_id=-1829889111, relative_path=Android/media/com.whatsapp/WhatsApp/Media/WhatsApp Images/
Row: 1 instance_id=NULL, compilation=NULL, disc_number=NULL, duration=NULL, album_artist=NULL, description=NULL, picasa_id=NULL, resolution=1080×1004, latitude=NULL, orientation=NULL, artist=NULL, author=NULL, inferred_date=NULL, height=1004, is_drm=0, bucket_display_name=WhatsApp Images, owner_package_name=com.whatsapp, f_number=NULL, volume_name=external_primary, date_modified=1752950029, writer=NULL, date_expires=NULL, composer=NULL, _display_name=IMG-20250719-WA0020.jpg, scene_capture_type=NULL, datetaken=NULL, mime_type=image/jpeg, bitrate=NULL, cd_track_number=NULL, _id=1000002121, iso=NULL, xmp=BLOB, year=NULL, oem_metadata=NULL, _data=/storage/emulated/0/Android/media/com.whatsapp/WhatsApp/Media/WhatsApp Images/IMG-20250719-WA0020.jpg, _size=90069, a
```

---

## CHAIN OF CUSTODY - AUDIT LOG

| Timestamp | Level | Action | Details |
|-----------|-------|--------|--------|
| 12:16:45 | INFO | CASE_OPENED | Case initiated: 001 |
| 12:16:49 | INFO | USER_INPUT | Command: device info |
| 12:16:50 | INFO | ARTIFACT | Artifact acquired: device_info |
| 12:17:09 | INFO | USER_INPUT | Command: installed apps |
| 12:17:09 | INFO | ARTIFACT | Artifact acquired: installed_packages |
| 12:17:48 | INFO | USER_INPUT | Command: logcat |
| 12:17:49 | INFO | ARTIFACT | Artifact acquired: logcat |
| 12:18:06 | INFO | USER_INPUT | Command: processes |
| 12:18:06 | INFO | ARTIFACT | Artifact acquired: processes |
| 12:18:34 | INFO | USER_INPUT | Command: contacts |
| 12:18:35 | INFO | ARTIFACT | Artifact acquired: contacts |
| 12:18:55 | INFO | USER_INPUT | Command: call log |
| 12:18:56 | INFO | ARTIFACT | Artifact acquired: call_log |
| 12:19:19 | INFO | USER_INPUT | Command: sms |
| 12:19:21 | INFO | ARTIFACT | Artifact acquired: sms |
| 12:19:45 | INFO | USER_INPUT | Command: storage |
| 12:19:45 | INFO | ARTIFACT | Artifact acquired: storage |
| 12:20:40 | INFO | USER_INPUT | Command: get me the images |
| 12:20:43 | INFO | ARTIFACT | Artifact acquired: images |

---

*Report generated by FIA Digital Forensics Framework v2.3.0*
