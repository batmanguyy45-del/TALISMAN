# TALISMAN Security Report — bounty-q1

**Generated:** 2026-04-21T21:16:19.818119Z  
**Total Findings:** 67  

## Executive Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 23 |
| 🟠 High | 6 |
| 🟡 Medium | 33 |
| 🔵 Low | 3 |
| ⚪ Info | 2 |

**Targets scanned:** 0

---

## Findings

### 1. Command Injection (output_based) — param 'cmd' via GET

**Severity:** 🔴 CRITICAL  
**Target:** `https://etoro.com`  
**Module:** cmdi  
**Confidence:** confirmed  
**CVSS Score:** 10.0  
**CWE:** CWE-78  

**Description:**  
OS command injection confirmed via output_based technique. Parameter 'cmd' is injected into a shell command. Payload: 1; id

**Request:**
```http
GET https://etoro.com?cmd=1%3B%20id HTTP/1.1
```
**Evidence:**
```
<!doctype html>
<html lang="en" class=" home">
<head>
<script type="text/javascript">(window.NREUM||(NREUM={})).init={privacy:{cookies_enabled:true},ajax:{deny_list:[]},session_trace:{sampling_rate:0.0,mode:"FIXED_RATE",enabled:true,error_sampling_rate:0.0},feature_flags:["soft_nav"],distributed_tra
```

**Steps to Reproduce:**  
Send: GET https://etoro.com?cmd=1%3B%20id


**Remediation:**  
1. Avoid passing user input to OS commands entirely.
2. If unavoidable, use allowlists to validate input strictly.
3. Use language-native APIs instead of shell commands (e.g., Python's subprocess with list args).
4. Sanitize and escape all user input before use in shell context.


---

### 2. Command Injection (output_based) — param 'exec' via GET

**Severity:** 🔴 CRITICAL  
**Target:** `https://etoro.com`  
**Module:** cmdi  
**Confidence:** confirmed  
**CVSS Score:** 10.0  
**CWE:** CWE-78  

**Description:**  
OS command injection confirmed via output_based technique. Parameter 'exec' is injected into a shell command. Payload: 1; id

**Request:**
```http
GET https://etoro.com?exec=1%3B%20id HTTP/1.1
```
**Evidence:**
```
<!doctype html>
<html lang="en" class=" home">
<head>
<script type="text/javascript">(window.NREUM||(NREUM={})).init={privacy:{cookies_enabled:true},ajax:{deny_list:[]},session_trace:{sampling_rate:0.0,mode:"FIXED_RATE",enabled:true,error_sampling_rate:0.0},feature_flags:["soft_nav"],distributed_tra
```

**Steps to Reproduce:**  
Send: GET https://etoro.com?exec=1%3B%20id


**Remediation:**  
1. Avoid passing user input to OS commands entirely.
2. If unavoidable, use allowlists to validate input strictly.
3. Use language-native APIs instead of shell commands (e.g., Python's subprocess with list args).
4. Sanitize and escape all user input before use in shell context.


---

### 3. Command Injection (output_based) — param 'command' via GET

**Severity:** 🔴 CRITICAL  
**Target:** `https://etoro.com`  
**Module:** cmdi  
**Confidence:** confirmed  
**CVSS Score:** 10.0  
**CWE:** CWE-78  

**Description:**  
OS command injection confirmed via output_based technique. Parameter 'command' is injected into a shell command. Payload: 1; id

**Request:**
```http
GET https://etoro.com?command=1%3B%20id HTTP/1.1
```
**Evidence:**
```
<!doctype html>
<html lang="en" class=" home">
<head>
<script type="text/javascript">(window.NREUM||(NREUM={})).init={privacy:{cookies_enabled:true},ajax:{deny_list:[]},session_trace:{sampling_rate:0.0,mode:"FIXED_RATE",enabled:true,error_sampling_rate:0.0},feature_flags:["soft_nav"],distributed_tra
```

**Steps to Reproduce:**  
Send: GET https://etoro.com?command=1%3B%20id


**Remediation:**  
1. Avoid passing user input to OS commands entirely.
2. If unavoidable, use allowlists to validate input strictly.
3. Use language-native APIs instead of shell commands (e.g., Python's subprocess with list args).
4. Sanitize and escape all user input before use in shell context.


---

### 4. Command Injection (output_based) — param 'ping' via GET

**Severity:** 🔴 CRITICAL  
**Target:** `https://etoro.com`  
**Module:** cmdi  
**Confidence:** confirmed  
**CVSS Score:** 10.0  
**CWE:** CWE-78  

**Description:**  
OS command injection confirmed via output_based technique. Parameter 'ping' is injected into a shell command. Payload: 1; id

**Request:**
```http
GET https://etoro.com?ping=1%3B%20id HTTP/1.1
```
**Evidence:**
```
<!doctype html>
<html lang="en" class=" home">
<head>
<script type="text/javascript">(window.NREUM||(NREUM={})).init={privacy:{cookies_enabled:true},ajax:{deny_list:[]},session_trace:{sampling_rate:0.0,mode:"FIXED_RATE",enabled:true,error_sampling_rate:0.0},feature_flags:["soft_nav"],distributed_tra
```

**Steps to Reproduce:**  
Send: GET https://etoro.com?ping=1%3B%20id


**Remediation:**  
1. Avoid passing user input to OS commands entirely.
2. If unavoidable, use allowlists to validate input strictly.
3. Use language-native APIs instead of shell commands (e.g., Python's subprocess with list args).
4. Sanitize and escape all user input before use in shell context.


---

### 5. Command Injection (output_based) — param 'host' via GET

**Severity:** 🔴 CRITICAL  
**Target:** `https://etoro.com`  
**Module:** cmdi  
**Confidence:** confirmed  
**CVSS Score:** 10.0  
**CWE:** CWE-78  

**Description:**  
OS command injection confirmed via output_based technique. Parameter 'host' is injected into a shell command. Payload: 1; id

**Request:**
```http
GET https://etoro.com?host=1%3B%20id HTTP/1.1
```
**Evidence:**
```
<!doctype html>
<html lang="en" class=" home">
<head>
<script type="text/javascript">(window.NREUM||(NREUM={})).init={privacy:{cookies_enabled:true},ajax:{deny_list:[]},session_trace:{sampling_rate:0.0,mode:"FIXED_RATE",enabled:true,error_sampling_rate:0.0},feature_flags:["soft_nav"],distributed_tra
```

**Steps to Reproduce:**  
Send: GET https://etoro.com?host=1%3B%20id


**Remediation:**  
1. Avoid passing user input to OS commands entirely.
2. If unavoidable, use allowlists to validate input strictly.
3. Use language-native APIs instead of shell commands (e.g., Python's subprocess with list args).
4. Sanitize and escape all user input before use in shell context.


---

### 6. Command Injection (output_based) — param 'ip' via GET

**Severity:** 🔴 CRITICAL  
**Target:** `https://etoro.com`  
**Module:** cmdi  
**Confidence:** confirmed  
**CVSS Score:** 10.0  
**CWE:** CWE-78  

**Description:**  
OS command injection confirmed via output_based technique. Parameter 'ip' is injected into a shell command. Payload: 1; id

**Request:**
```http
GET https://etoro.com?ip=1%3B%20id HTTP/1.1
```
**Evidence:**
```
<!doctype html>
<html lang="en" class=" home">
<head>
<script type="text/javascript">(window.NREUM||(NREUM={})).init={privacy:{cookies_enabled:true},ajax:{deny_list:[]},session_trace:{sampling_rate:0.0,mode:"FIXED_RATE",enabled:true,error_sampling_rate:0.0},feature_flags:["soft_nav"],distributed_tra
```

**Steps to Reproduce:**  
Send: GET https://etoro.com?ip=1%3B%20id


**Remediation:**  
1. Avoid passing user input to OS commands entirely.
2. If unavoidable, use allowlists to validate input strictly.
3. Use language-native APIs instead of shell commands (e.g., Python's subprocess with list args).
4. Sanitize and escape all user input before use in shell context.


---

### 7. Command Injection (output_based) — param 'dir' via GET

**Severity:** 🔴 CRITICAL  
**Target:** `https://etoro.com`  
**Module:** cmdi  
**Confidence:** confirmed  
**CVSS Score:** 10.0  
**CWE:** CWE-78  

**Description:**  
OS command injection confirmed via output_based technique. Parameter 'dir' is injected into a shell command. Payload: 1; id

**Request:**
```http
GET https://etoro.com?dir=1%3B%20id HTTP/1.1
```
**Evidence:**
```
<!doctype html>
<html lang="en" class=" home">
<head>
<script type="text/javascript">(window.NREUM||(NREUM={})).init={privacy:{cookies_enabled:true},ajax:{deny_list:[]},session_trace:{sampling_rate:0.0,mode:"FIXED_RATE",enabled:true,error_sampling_rate:0.0},feature_flags:["soft_nav"],distributed_tra
```

**Steps to Reproduce:**  
Send: GET https://etoro.com?dir=1%3B%20id


**Remediation:**  
1. Avoid passing user input to OS commands entirely.
2. If unavoidable, use allowlists to validate input strictly.
3. Use language-native APIs instead of shell commands (e.g., Python's subprocess with list args).
4. Sanitize and escape all user input before use in shell context.


---

### 8. Command Injection (output_based) — param 'query' via GET

**Severity:** 🔴 CRITICAL  
**Target:** `https://etoro.com`  
**Module:** cmdi  
**Confidence:** confirmed  
**CVSS Score:** 10.0  
**CWE:** CWE-78  

**Description:**  
OS command injection confirmed via output_based technique. Parameter 'query' is injected into a shell command. Payload: 1; id

**Request:**
```http
GET https://etoro.com?query=1%3B%20id HTTP/1.1
```
**Evidence:**
```
<!doctype html>
<html lang="en" class=" home">
<head>
<script type="text/javascript">(window.NREUM||(NREUM={})).init={privacy:{cookies_enabled:true},ajax:{deny_list:[]},session_trace:{sampling_rate:0.0,mode:"FIXED_RATE",enabled:true,error_sampling_rate:0.0},feature_flags:["soft_nav"],distributed_tra
```

**Steps to Reproduce:**  
Send: GET https://etoro.com?query=1%3B%20id


**Remediation:**  
1. Avoid passing user input to OS commands entirely.
2. If unavoidable, use allowlists to validate input strictly.
3. Use language-native APIs instead of shell commands (e.g., Python's subprocess with list args).
4. Sanitize and escape all user input before use in shell context.


---

### 9. Command Injection (output_based) — param 'name' via GET

**Severity:** 🔴 CRITICAL  
**Target:** `https://etoro.com`  
**Module:** cmdi  
**Confidence:** confirmed  
**CVSS Score:** 10.0  
**CWE:** CWE-78  

**Description:**  
OS command injection confirmed via output_based technique. Parameter 'name' is injected into a shell command. Payload: 1; id

**Request:**
```http
GET https://etoro.com?name=1%3B%20id HTTP/1.1
```
**Evidence:**
```
<!doctype html>
<html lang="en" class=" home">
<head>
<script type="text/javascript">(window.NREUM||(NREUM={})).init={privacy:{cookies_enabled:true},ajax:{deny_list:[]},session_trace:{sampling_rate:0.0,mode:"FIXED_RATE",enabled:true,error_sampling_rate:0.0},feature_flags:["soft_nav"],distributed_tra
```

**Steps to Reproduce:**  
Send: GET https://etoro.com?name=1%3B%20id


**Remediation:**  
1. Avoid passing user input to OS commands entirely.
2. If unavoidable, use allowlists to validate input strictly.
3. Use language-native APIs instead of shell commands (e.g., Python's subprocess with list args).
4. Sanitize and escape all user input before use in shell context.


---

### 10. Command Injection (output_based) — param 'path' via GET

**Severity:** 🔴 CRITICAL  
**Target:** `https://etoro.com`  
**Module:** cmdi  
**Confidence:** confirmed  
**CVSS Score:** 10.0  
**CWE:** CWE-78  

**Description:**  
OS command injection confirmed via output_based technique. Parameter 'path' is injected into a shell command. Payload: 1; id

**Request:**
```http
GET https://etoro.com?path=1%3B%20id HTTP/1.1
```
**Evidence:**
```
<!doctype html>
<html lang="en" class=" home">
<head>
<script type="text/javascript">(window.NREUM||(NREUM={})).init={privacy:{cookies_enabled:true},ajax:{deny_list:[]},session_trace:{sampling_rate:0.0,mode:"FIXED_RATE",enabled:true,error_sampling_rate:0.0},feature_flags:["soft_nav"],distributed_tra
```

**Steps to Reproduce:**  
Send: GET https://etoro.com?path=1%3B%20id


**Remediation:**  
1. Avoid passing user input to OS commands entirely.
2. If unavoidable, use allowlists to validate input strictly.
3. Use language-native APIs instead of shell commands (e.g., Python's subprocess with list args).
4. Sanitize and escape all user input before use in shell context.


---

### 11. Command Injection (output_based) — param 'id' via GET

**Severity:** 🔴 CRITICAL  
**Target:** `https://etoro.com`  
**Module:** cmdi  
**Confidence:** confirmed  
**CVSS Score:** 10.0  
**CWE:** CWE-78  

**Description:**  
OS command injection confirmed via output_based technique. Parameter 'id' is injected into a shell command. Payload: 1; id

**Request:**
```http
GET https://etoro.com?id=1%3B%20id HTTP/1.1
```
**Evidence:**
```
<!doctype html>
<html lang="en" class=" home">
<head>
<script type="text/javascript">(window.NREUM||(NREUM={})).init={privacy:{cookies_enabled:true},ajax:{deny_list:[]},session_trace:{sampling_rate:0.0,mode:"FIXED_RATE",enabled:true,error_sampling_rate:0.0},feature_flags:["soft_nav"],distributed_tra
```

**Steps to Reproduce:**  
Send: GET https://etoro.com?id=1%3B%20id


**Remediation:**  
1. Avoid passing user input to OS commands entirely.
2. If unavoidable, use allowlists to validate input strictly.
3. Use language-native APIs instead of shell commands (e.g., Python's subprocess with list args).
4. Sanitize and escape all user input before use in shell context.


---

### 12. Command Injection (output_based) — param 'file' via GET

**Severity:** 🔴 CRITICAL  
**Target:** `https://etoro.com`  
**Module:** cmdi  
**Confidence:** confirmed  
**CVSS Score:** 10.0  
**CWE:** CWE-78  

**Description:**  
OS command injection confirmed via output_based technique. Parameter 'file' is injected into a shell command. Payload: 1; id

**Request:**
```http
GET https://etoro.com?file=1%3B%20id HTTP/1.1
```
**Evidence:**
```
<!doctype html>
<html lang="en" class=" home">
<head>
<script type="text/javascript">(window.NREUM||(NREUM={})).init={privacy:{cookies_enabled:true},ajax:{deny_list:[]},session_trace:{sampling_rate:0.0,mode:"FIXED_RATE",enabled:true,error_sampling_rate:0.0},feature_flags:["soft_nav"],distributed_tra
```

**Steps to Reproduce:**  
Send: GET https://etoro.com?file=1%3B%20id


**Remediation:**  
1. Avoid passing user input to OS commands entirely.
2. If unavoidable, use allowlists to validate input strictly.
3. Use language-native APIs instead of shell commands (e.g., Python's subprocess with list args).
4. Sanitize and escape all user input before use in shell context.


---

### 13. SSTI (unknown) — param 'name'

**Severity:** 🔴 CRITICAL  
**Target:** `https://etoro.com`  
**Module:** ssti  
**Confidence:** confirmed  
**CVSS Score:** 10.0  
**CWE:** CWE-94  

**Description:**  
Server-Side Template Injection in 'name'. Engine: unknown. Expression '{{7*7}}' evaluated server-side to '49'.

**Request:**
```http
GET https://etoro.com?name=%7B%7B7%2A7%7D%7D HTTP/1.1
```
**Evidence:**
```
Expression '{{7*7}}' evaluated to '49'
```

**Steps to Reproduce:**  
Send: GET with name={{7*7}}


**Remediation:**  
1. Never pass user input directly to template engines.
2. Use sandboxed template evaluation with no access to builtins.
3. Escape all user-supplied data before rendering.
4. Consider logic-less templates (Mustache/Handlebars) for user content.


---

### 14. SSTI (unknown) — param 'template'

**Severity:** 🔴 CRITICAL  
**Target:** `https://etoro.com`  
**Module:** ssti  
**Confidence:** confirmed  
**CVSS Score:** 10.0  
**CWE:** CWE-94  

**Description:**  
Server-Side Template Injection in 'template'. Engine: unknown. Expression '{{7*7}}' evaluated server-side to '49'.

**Request:**
```http
GET https://etoro.com?template=%7B%7B7%2A7%7D%7D HTTP/1.1
```
**Evidence:**
```
Expression '{{7*7}}' evaluated to '49'
```

**Steps to Reproduce:**  
Send: GET with template={{7*7}}


**Remediation:**  
1. Never pass user input directly to template engines.
2. Use sandboxed template evaluation with no access to builtins.
3. Escape all user-supplied data before rendering.
4. Consider logic-less templates (Mustache/Handlebars) for user content.


---

### 15. SSTI (unknown) — param 'message'

**Severity:** 🔴 CRITICAL  
**Target:** `https://etoro.com`  
**Module:** ssti  
**Confidence:** confirmed  
**CVSS Score:** 10.0  
**CWE:** CWE-94  

**Description:**  
Server-Side Template Injection in 'message'. Engine: unknown. Expression '{{7*7}}' evaluated server-side to '49'.

**Request:**
```http
GET https://etoro.com?message=%7B%7B7%2A7%7D%7D HTTP/1.1
```
**Evidence:**
```
Expression '{{7*7}}' evaluated to '49'
```

**Steps to Reproduce:**  
Send: GET with message={{7*7}}


**Remediation:**  
1. Never pass user input directly to template engines.
2. Use sandboxed template evaluation with no access to builtins.
3. Escape all user-supplied data before rendering.
4. Consider logic-less templates (Mustache/Handlebars) for user content.


---

### 16. SSTI (unknown) — param 'subject'

**Severity:** 🔴 CRITICAL  
**Target:** `https://etoro.com`  
**Module:** ssti  
**Confidence:** confirmed  
**CVSS Score:** 10.0  
**CWE:** CWE-94  

**Description:**  
Server-Side Template Injection in 'subject'. Engine: unknown. Expression '{{7*7}}' evaluated server-side to '49'.

**Request:**
```http
GET https://etoro.com?subject=%7B%7B7%2A7%7D%7D HTTP/1.1
```
**Evidence:**
```
Expression '{{7*7}}' evaluated to '49'
```

**Steps to Reproduce:**  
Send: GET with subject={{7*7}}


**Remediation:**  
1. Never pass user input directly to template engines.
2. Use sandboxed template evaluation with no access to builtins.
3. Escape all user-supplied data before rendering.
4. Consider logic-less templates (Mustache/Handlebars) for user content.


---

### 17. SSTI (unknown) — param 'greeting'

**Severity:** 🔴 CRITICAL  
**Target:** `https://etoro.com`  
**Module:** ssti  
**Confidence:** confirmed  
**CVSS Score:** 10.0  
**CWE:** CWE-94  

**Description:**  
Server-Side Template Injection in 'greeting'. Engine: unknown. Expression '{{7*7}}' evaluated server-side to '49'.

**Request:**
```http
GET https://etoro.com?greeting=%7B%7B7%2A7%7D%7D HTTP/1.1
```
**Evidence:**
```
Expression '{{7*7}}' evaluated to '49'
```

**Steps to Reproduce:**  
Send: GET with greeting={{7*7}}


**Remediation:**  
1. Never pass user input directly to template engines.
2. Use sandboxed template evaluation with no access to builtins.
3. Escape all user-supplied data before rendering.
4. Consider logic-less templates (Mustache/Handlebars) for user content.


---

### 18. SSTI (unknown) — param 'text'

**Severity:** 🔴 CRITICAL  
**Target:** `https://etoro.com`  
**Module:** ssti  
**Confidence:** confirmed  
**CVSS Score:** 10.0  
**CWE:** CWE-94  

**Description:**  
Server-Side Template Injection in 'text'. Engine: unknown. Expression '{{7*7}}' evaluated server-side to '49'.

**Request:**
```http
GET https://etoro.com?text=%7B%7B7%2A7%7D%7D HTTP/1.1
```
**Evidence:**
```
Expression '{{7*7}}' evaluated to '49'
```

**Steps to Reproduce:**  
Send: GET with text={{7*7}}


**Remediation:**  
1. Never pass user input directly to template engines.
2. Use sandboxed template evaluation with no access to builtins.
3. Escape all user-supplied data before rendering.
4. Consider logic-less templates (Mustache/Handlebars) for user content.


---

### 19. SSTI (unknown) — param 'content'

**Severity:** 🔴 CRITICAL  
**Target:** `https://etoro.com`  
**Module:** ssti  
**Confidence:** confirmed  
**CVSS Score:** 10.0  
**CWE:** CWE-94  

**Description:**  
Server-Side Template Injection in 'content'. Engine: unknown. Expression '{{7*7}}' evaluated server-side to '49'.

**Request:**
```http
GET https://etoro.com?content=%7B%7B7%2A7%7D%7D HTTP/1.1
```
**Evidence:**
```
Expression '{{7*7}}' evaluated to '49'
```

**Steps to Reproduce:**  
Send: GET with content={{7*7}}


**Remediation:**  
1. Never pass user input directly to template engines.
2. Use sandboxed template evaluation with no access to builtins.
3. Escape all user-supplied data before rendering.
4. Consider logic-less templates (Mustache/Handlebars) for user content.


---

### 20. SSTI (unknown) — param 'body'

**Severity:** 🔴 CRITICAL  
**Target:** `https://etoro.com`  
**Module:** ssti  
**Confidence:** confirmed  
**CVSS Score:** 10.0  
**CWE:** CWE-94  

**Description:**  
Server-Side Template Injection in 'body'. Engine: unknown. Expression '{{7*7}}' evaluated server-side to '49'.

**Request:**
```http
GET https://etoro.com?body=%7B%7B7%2A7%7D%7D HTTP/1.1
```
**Evidence:**
```
Expression '{{7*7}}' evaluated to '49'
```

**Steps to Reproduce:**  
Send: GET with body={{7*7}}


**Remediation:**  
1. Never pass user input directly to template engines.
2. Use sandboxed template evaluation with no access to builtins.
3. Escape all user-supplied data before rendering.
4. Consider logic-less templates (Mustache/Handlebars) for user content.


---

### 21. SSTI (unknown) — param 'page'

**Severity:** 🔴 CRITICAL  
**Target:** `https://etoro.com`  
**Module:** ssti  
**Confidence:** confirmed  
**CVSS Score:** 10.0  
**CWE:** CWE-94  

**Description:**  
Server-Side Template Injection in 'page'. Engine: unknown. Expression '{{7*7}}' evaluated server-side to '49'.

**Request:**
```http
GET https://etoro.com?page=%7B%7B7%2A7%7D%7D HTTP/1.1
```
**Evidence:**
```
Expression '{{7*7}}' evaluated to '49'
```

**Steps to Reproduce:**  
Send: GET with page={{7*7}}


**Remediation:**  
1. Never pass user input directly to template engines.
2. Use sandboxed template evaluation with no access to builtins.
3. Escape all user-supplied data before rendering.
4. Consider logic-less templates (Mustache/Handlebars) for user content.


---

### 22. SSTI (unknown) — param 'page'

**Severity:** 🔴 CRITICAL  
**Target:** `https://etoro.com`  
**Module:** ssti  
**Confidence:** confirmed  
**CVSS Score:** 10.0  
**CWE:** CWE-94  

**Description:**  
Server-Side Template Injection in 'page'. Engine: unknown. Expression '${7*7}' evaluated server-side to '49'.

**Request:**
```http
POST https://etoro.com?page=%24%7B7%2A7%7D HTTP/1.1
```
**Evidence:**
```
Expression '${7*7}' evaluated to '49'
```

**Steps to Reproduce:**  
Send: POST with page=${7*7}


**Remediation:**  
1. Never pass user input directly to template engines.
2. Use sandboxed template evaluation with no access to builtins.
3. Escape all user-supplied data before rendering.
4. Consider logic-less templates (Mustache/Handlebars) for user content.


---

### 23. SSTI (unknown) — param 'title'

**Severity:** 🔴 CRITICAL  
**Target:** `https://etoro.com`  
**Module:** ssti  
**Confidence:** confirmed  
**CVSS Score:** 10.0  
**CWE:** CWE-94  

**Description:**  
Server-Side Template Injection in 'title'. Engine: unknown. Expression '{{7*7}}' evaluated server-side to '49'.

**Request:**
```http
GET https://etoro.com?title=%7B%7B7%2A7%7D%7D HTTP/1.1
```
**Evidence:**
```
Expression '{{7*7}}' evaluated to '49'
```

**Steps to Reproduce:**  
Send: GET with title={{7*7}}


**Remediation:**  
1. Never pass user input directly to template engines.
2. Use sandboxed template evaluation with no access to builtins.
3. Escape all user-supplied data before rendering.
4. Consider logic-less templates (Mustache/Handlebars) for user content.


---

### 24. IDOR — parameter 'id' allows access to ID 2

**Severity:** 🟠 HIGH  
**Target:** `https://etoro.com`  
**Module:** idor  
**Confidence:** likely  
**CVSS Score:** 8.1  
**CWE:** CWE-639  

**Description:**  
Insecure Direct Object Reference in parameter 'id'. Changing ID from '1' to '2' returned a different but valid resource (status 200).

**Request:**
```http
GET https://etoro.com?id=2 HTTP/1.1
```
**Evidence:**
```
<!doctype html>
<html lang="en" class=" home">
<head>
<script type="text/javascript">(window.NREUM||(NREUM={})).init={privacy:{cookies_enabled:true},ajax:{deny_list:[]},session_trace:{sampling_rate:0.0,mode:"FIXED_RATE",enabled:true,error_sampling_rate:0.0},feature_flags:["soft_nav"],distributed_tra
```

**Steps to Reproduce:**  
Change id=1 to id=2


**Remediation:**  
1. Implement object-level authorization checks on every resource access.
2. Use indirect references (UUIDs or opaque tokens) instead of sequential IDs.
3. Validate that the authenticated user owns or has permission for the requested resource.


---

### 25. IDOR — parameter 'user_id' allows access to ID 2

**Severity:** 🟠 HIGH  
**Target:** `https://etoro.com`  
**Module:** idor  
**Confidence:** likely  
**CVSS Score:** 8.1  
**CWE:** CWE-639  

**Description:**  
Insecure Direct Object Reference in parameter 'user_id'. Changing ID from '1' to '2' returned a different but valid resource (status 200).

**Request:**
```http
GET https://etoro.com?user_id=2 HTTP/1.1
```
**Evidence:**
```
<!doctype html>
<html lang="en" class=" home">
<head>
<script type="text/javascript">(window.NREUM||(NREUM={})).init={privacy:{cookies_enabled:true},ajax:{deny_list:[]},session_trace:{sampling_rate:0.0,mode:"FIXED_RATE",enabled:true,error_sampling_rate:0.0},feature_flags:["soft_nav"],distributed_tra
```

**Steps to Reproduce:**  
Change user_id=1 to user_id=2


**Remediation:**  
1. Implement object-level authorization checks on every resource access.
2. Use indirect references (UUIDs or opaque tokens) instead of sequential IDs.
3. Validate that the authenticated user owns or has permission for the requested resource.


---

### 26. IDOR — parameter 'account_id' allows access to ID 2

**Severity:** 🟠 HIGH  
**Target:** `https://etoro.com`  
**Module:** idor  
**Confidence:** likely  
**CVSS Score:** 8.1  
**CWE:** CWE-639  

**Description:**  
Insecure Direct Object Reference in parameter 'account_id'. Changing ID from '1' to '2' returned a different but valid resource (status 200).

**Request:**
```http
GET https://etoro.com?account_id=2 HTTP/1.1
```
**Evidence:**
```
<!doctype html>
<html lang="en" class=" home">
<head>
<script type="text/javascript">(window.NREUM||(NREUM={})).init={privacy:{cookies_enabled:true},ajax:{deny_list:[]},session_trace:{sampling_rate:0.0,mode:"FIXED_RATE",enabled:true,error_sampling_rate:0.0},feature_flags:["soft_nav"],distributed_tra
```

**Steps to Reproduce:**  
Change account_id=1 to account_id=2


**Remediation:**  
1. Implement object-level authorization checks on every resource access.
2. Use indirect references (UUIDs or opaque tokens) instead of sequential IDs.
3. Validate that the authenticated user owns or has permission for the requested resource.


---

### 27. IDOR — parameter 'order_id' allows access to ID 2

**Severity:** 🟠 HIGH  
**Target:** `https://etoro.com`  
**Module:** idor  
**Confidence:** likely  
**CVSS Score:** 8.1  
**CWE:** CWE-639  

**Description:**  
Insecure Direct Object Reference in parameter 'order_id'. Changing ID from '1' to '2' returned a different but valid resource (status 200).

**Request:**
```http
GET https://etoro.com?order_id=2 HTTP/1.1
```
**Evidence:**
```
<!doctype html>
<html lang="en" class=" home">
<head>
<script type="text/javascript">(window.NREUM||(NREUM={})).init={privacy:{cookies_enabled:true},ajax:{deny_list:[]},session_trace:{sampling_rate:0.0,mode:"FIXED_RATE",enabled:true,error_sampling_rate:0.0},feature_flags:["soft_nav"],distributed_tra
```

**Steps to Reproduce:**  
Change order_id=1 to order_id=2


**Remediation:**  
1. Implement object-level authorization checks on every resource access.
2. Use indirect references (UUIDs or opaque tokens) instead of sequential IDs.
3. Validate that the authenticated user owns or has permission for the requested resource.


---

### 28. IDOR — parameter 'invoice_id' allows access to ID 2

**Severity:** 🟠 HIGH  
**Target:** `https://etoro.com`  
**Module:** idor  
**Confidence:** likely  
**CVSS Score:** 8.1  
**CWE:** CWE-639  

**Description:**  
Insecure Direct Object Reference in parameter 'invoice_id'. Changing ID from '1' to '2' returned a different but valid resource (status 200).

**Request:**
```http
GET https://etoro.com?invoice_id=2 HTTP/1.1
```
**Evidence:**
```
<!doctype html>
<html lang="en" class=" home">
<head>
<script type="text/javascript">(window.NREUM||(NREUM={})).init={privacy:{cookies_enabled:true},ajax:{deny_list:[]},session_trace:{sampling_rate:0.0,mode:"FIXED_RATE",enabled:true,error_sampling_rate:0.0},feature_flags:["soft_nav"],distributed_tra
```

**Steps to Reproduce:**  
Change invoice_id=1 to invoice_id=2


**Remediation:**  
1. Implement object-level authorization checks on every resource access.
2. Use indirect references (UUIDs or opaque tokens) instead of sequential IDs.
3. Validate that the authenticated user owns or has permission for the requested resource.


---

### 29. CRLF injection — HTTP response splitting

**Severity:** 🟠 HIGH  
**Target:** `https://etoro.com`  
**Module:** server_misconfig  
**Confidence:** confirmed  
**CVSS Score:** 6.1  
**CWE:** CWE-93  

**Description:**  
URL parameters or headers allow injection of CRLF sequences, enabling response splitting, header injection, and potentially XSS.


**Remediation:**  
Validate and sanitize all user input. Encode CRLF characters before including in HTTP headers.


---

### 30. Missing Strict-Transport-Security header

**Severity:** 🟡 MEDIUM  
**Target:** `https://example.com`  
**Module:** headers  
**Confidence:** confirmed  
**CWE:** CWE-319  

**Description:**  
Enforces HTTPS connections

**Request:**
```http
GET https://example.com HTTP/1.1
```

**Remediation:**  
Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload


---

### 31. Missing X-Frame-Options header

**Severity:** 🟡 MEDIUM  
**Target:** `https://example.com`  
**Module:** headers  
**Confidence:** confirmed  
**CWE:** CWE-1021  

**Description:**  
Prevents clickjacking attacks

**Request:**
```http
GET https://example.com HTTP/1.1
```

**Remediation:**  
Add: X-Frame-Options: DENY


---

### 32. Missing Content-Security-Policy header

**Severity:** 🟡 MEDIUM  
**Target:** `https://example.com`  
**Module:** headers  
**Confidence:** confirmed  
**CWE:** CWE-79  

**Description:**  
Restricts resource loading to prevent XSS

**Request:**
```http
GET https://example.com HTTP/1.1
```

**Remediation:**  
Implement a strict CSP. Start with: Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'


---

### 33. Missing Content-Security-Policy header

**Severity:** 🟡 MEDIUM  
**Target:** `https://etoro.com`  
**Module:** headers  
**Confidence:** confirmed  
**CWE:** CWE-79  

**Description:**  
Restricts resource loading to prevent XSS

**Request:**
```http
GET https://etoro.com HTTP/1.1
```

**Remediation:**  
Implement a strict CSP. Start with: Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'


---

### 34. Open Redirect — param 'next'

**Severity:** 🟡 MEDIUM  
**Target:** `https://etoro.com`  
**Module:** open_redirect  
**Confidence:** confirmed  
**CVSS Score:** 6.1  
**CWE:** CWE-601  

**Description:**  
Open redirect via 'next' parameter. Redirects to attacker-controlled domain: https://www.etoro.com/?next=https%3A%2F%2Fevil.com

**Request:**
```http
GET https://etoro.com?next=https%3A%2F%2Fevil.com HTTP/1.1
```
**Evidence:**
```
Location: https://www.etoro.com/?next=https%3A%2F%2Fevil.com
```

**Steps to Reproduce:**  
Navigate to: https://etoro.com?next=https%3A%2F%2Fevil.com


**Remediation:**  
1. Validate redirect URLs against an allowlist of trusted domains.
2. Use relative paths instead of absolute URLs for internal redirects.
3. Display an interstitial warning page before external redirects.


---

### 35. Open Redirect — param 'jump'

**Severity:** 🟡 MEDIUM  
**Target:** `https://etoro.com`  
**Module:** open_redirect  
**Confidence:** confirmed  
**CVSS Score:** 6.1  
**CWE:** CWE-601  

**Description:**  
Open redirect via 'jump' parameter. Redirects to attacker-controlled domain: https://www.etoro.com/?jump=https%3A%2F%2Fevil.com

**Request:**
```http
GET https://etoro.com?jump=https%3A%2F%2Fevil.com HTTP/1.1
```
**Evidence:**
```
Location: https://www.etoro.com/?jump=https%3A%2F%2Fevil.com
```

**Steps to Reproduce:**  
Navigate to: https://etoro.com?jump=https%3A%2F%2Fevil.com


**Remediation:**  
1. Validate redirect URLs against an allowlist of trusted domains.
2. Use relative paths instead of absolute URLs for internal redirects.
3. Display an interstitial warning page before external redirects.


---

### 36. Open Redirect — param 'login_url'

**Severity:** 🟡 MEDIUM  
**Target:** `https://etoro.com`  
**Module:** open_redirect  
**Confidence:** confirmed  
**CVSS Score:** 6.1  
**CWE:** CWE-601  

**Description:**  
Open redirect via 'login_url' parameter. Redirects to attacker-controlled domain: https://www.etoro.com/?login_url=https%3A%2F%2Fevil.com

**Request:**
```http
GET https://etoro.com?login_url=https%3A%2F%2Fevil.com HTTP/1.1
```
**Evidence:**
```
Location: https://www.etoro.com/?login_url=https%3A%2F%2Fevil.com
```

**Steps to Reproduce:**  
Navigate to: https://etoro.com?login_url=https%3A%2F%2Fevil.com


**Remediation:**  
1. Validate redirect URLs against an allowlist of trusted domains.
2. Use relative paths instead of absolute URLs for internal redirects.
3. Display an interstitial warning page before external redirects.


---

### 37. Open Redirect — param 'go'

**Severity:** 🟡 MEDIUM  
**Target:** `https://etoro.com`  
**Module:** open_redirect  
**Confidence:** confirmed  
**CVSS Score:** 6.1  
**CWE:** CWE-601  

**Description:**  
Open redirect via 'go' parameter. Redirects to attacker-controlled domain: https://www.etoro.com/?go=https%3A%2F%2Fevil.com

**Request:**
```http
GET https://etoro.com?go=https%3A%2F%2Fevil.com HTTP/1.1
```
**Evidence:**
```
Location: https://www.etoro.com/?go=https%3A%2F%2Fevil.com
```

**Steps to Reproduce:**  
Navigate to: https://etoro.com?go=https%3A%2F%2Fevil.com


**Remediation:**  
1. Validate redirect URLs against an allowlist of trusted domains.
2. Use relative paths instead of absolute URLs for internal redirects.
3. Display an interstitial warning page before external redirects.


---

### 38. Open Redirect — param 'ref'

**Severity:** 🟡 MEDIUM  
**Target:** `https://etoro.com`  
**Module:** open_redirect  
**Confidence:** confirmed  
**CVSS Score:** 6.1  
**CWE:** CWE-601  

**Description:**  
Open redirect via 'ref' parameter. Redirects to attacker-controlled domain: https://www.etoro.com/?ref=https%3A%2F%2Fevil.com

**Request:**
```http
GET https://etoro.com?ref=https%3A%2F%2Fevil.com HTTP/1.1
```
**Evidence:**
```
Location: https://www.etoro.com/?ref=https%3A%2F%2Fevil.com
```

**Steps to Reproduce:**  
Navigate to: https://etoro.com?ref=https%3A%2F%2Fevil.com


**Remediation:**  
1. Validate redirect URLs against an allowlist of trusted domains.
2. Use relative paths instead of absolute URLs for internal redirects.
3. Display an interstitial warning page before external redirects.


---

### 39. Open Redirect — param 'out'

**Severity:** 🟡 MEDIUM  
**Target:** `https://etoro.com`  
**Module:** open_redirect  
**Confidence:** confirmed  
**CVSS Score:** 6.1  
**CWE:** CWE-601  

**Description:**  
Open redirect via 'out' parameter. Redirects to attacker-controlled domain: https://www.etoro.com/?out=https%3A%2F%2Fevil.com

**Request:**
```http
GET https://etoro.com?out=https%3A%2F%2Fevil.com HTTP/1.1
```
**Evidence:**
```
Location: https://www.etoro.com/?out=https%3A%2F%2Fevil.com
```

**Steps to Reproduce:**  
Navigate to: https://etoro.com?out=https%3A%2F%2Fevil.com


**Remediation:**  
1. Validate redirect URLs against an allowlist of trusted domains.
2. Use relative paths instead of absolute URLs for internal redirects.
3. Display an interstitial warning page before external redirects.


---

### 40. Open Redirect — param 'returnTo'

**Severity:** 🟡 MEDIUM  
**Target:** `https://etoro.com`  
**Module:** open_redirect  
**Confidence:** confirmed  
**CVSS Score:** 6.1  
**CWE:** CWE-601  

**Description:**  
Open redirect via 'returnTo' parameter. Redirects to attacker-controlled domain: https://www.etoro.com/?returnTo=https%3A%2F%2Fevil.com

**Request:**
```http
GET https://etoro.com?returnTo=https%3A%2F%2Fevil.com HTTP/1.1
```
**Evidence:**
```
Location: https://www.etoro.com/?returnTo=https%3A%2F%2Fevil.com
```

**Steps to Reproduce:**  
Navigate to: https://etoro.com?returnTo=https%3A%2F%2Fevil.com


**Remediation:**  
1. Validate redirect URLs against an allowlist of trusted domains.
2. Use relative paths instead of absolute URLs for internal redirects.
3. Display an interstitial warning page before external redirects.


---

### 41. Open Redirect — param 'redir'

**Severity:** 🟡 MEDIUM  
**Target:** `https://etoro.com`  
**Module:** open_redirect  
**Confidence:** confirmed  
**CVSS Score:** 6.1  
**CWE:** CWE-601  

**Description:**  
Open redirect via 'redir' parameter. Redirects to attacker-controlled domain: https://www.etoro.com/?redir=https%3A%2F%2Fevil.com

**Request:**
```http
GET https://etoro.com?redir=https%3A%2F%2Fevil.com HTTP/1.1
```
**Evidence:**
```
Location: https://www.etoro.com/?redir=https%3A%2F%2Fevil.com
```

**Steps to Reproduce:**  
Navigate to: https://etoro.com?redir=https%3A%2F%2Fevil.com


**Remediation:**  
1. Validate redirect URLs against an allowlist of trusted domains.
2. Use relative paths instead of absolute URLs for internal redirects.
3. Display an interstitial warning page before external redirects.


---

### 42. Open Redirect — param 'dest'

**Severity:** 🟡 MEDIUM  
**Target:** `https://etoro.com`  
**Module:** open_redirect  
**Confidence:** confirmed  
**CVSS Score:** 6.1  
**CWE:** CWE-601  

**Description:**  
Open redirect via 'dest' parameter. Redirects to attacker-controlled domain: https://www.etoro.com/?dest=https%3A%2F%2Fevil.com

**Request:**
```http
GET https://etoro.com?dest=https%3A%2F%2Fevil.com HTTP/1.1
```
**Evidence:**
```
Location: https://www.etoro.com/?dest=https%3A%2F%2Fevil.com
```

**Steps to Reproduce:**  
Navigate to: https://etoro.com?dest=https%3A%2F%2Fevil.com


**Remediation:**  
1. Validate redirect URLs against an allowlist of trusted domains.
2. Use relative paths instead of absolute URLs for internal redirects.
3. Display an interstitial warning page before external redirects.


---

### 43. Open Redirect — param 'link'

**Severity:** 🟡 MEDIUM  
**Target:** `https://etoro.com`  
**Module:** open_redirect  
**Confidence:** confirmed  
**CVSS Score:** 6.1  
**CWE:** CWE-601  

**Description:**  
Open redirect via 'link' parameter. Redirects to attacker-controlled domain: https://www.etoro.com/?link=https%3A%2F%2Fevil.com

**Request:**
```http
GET https://etoro.com?link=https%3A%2F%2Fevil.com HTTP/1.1
```
**Evidence:**
```
Location: https://www.etoro.com/?link=https%3A%2F%2Fevil.com
```

**Steps to Reproduce:**  
Navigate to: https://etoro.com?link=https%3A%2F%2Fevil.com


**Remediation:**  
1. Validate redirect URLs against an allowlist of trusted domains.
2. Use relative paths instead of absolute URLs for internal redirects.
3. Display an interstitial warning page before external redirects.


---

### 44. Open Redirect — param 'return'

**Severity:** 🟡 MEDIUM  
**Target:** `https://etoro.com`  
**Module:** open_redirect  
**Confidence:** confirmed  
**CVSS Score:** 6.1  
**CWE:** CWE-601  

**Description:**  
Open redirect via 'return' parameter. Redirects to attacker-controlled domain: https://www.etoro.com/?return=https%3A%2F%2Fevil.com

**Request:**
```http
GET https://etoro.com?return=https%3A%2F%2Fevil.com HTTP/1.1
```
**Evidence:**
```
Location: https://www.etoro.com/?return=https%3A%2F%2Fevil.com
```

**Steps to Reproduce:**  
Navigate to: https://etoro.com?return=https%3A%2F%2Fevil.com


**Remediation:**  
1. Validate redirect URLs against an allowlist of trusted domains.
2. Use relative paths instead of absolute URLs for internal redirects.
3. Display an interstitial warning page before external redirects.


---

### 45. Open Redirect — param 'u'

**Severity:** 🟡 MEDIUM  
**Target:** `https://etoro.com`  
**Module:** open_redirect  
**Confidence:** confirmed  
**CVSS Score:** 6.1  
**CWE:** CWE-601  

**Description:**  
Open redirect via 'u' parameter. Redirects to attacker-controlled domain: https://www.etoro.com/?u=https%3A%2F%2Fevil.com

**Request:**
```http
GET https://etoro.com?u=https%3A%2F%2Fevil.com HTTP/1.1
```
**Evidence:**
```
Location: https://www.etoro.com/?u=https%3A%2F%2Fevil.com
```

**Steps to Reproduce:**  
Navigate to: https://etoro.com?u=https%3A%2F%2Fevil.com


**Remediation:**  
1. Validate redirect URLs against an allowlist of trusted domains.
2. Use relative paths instead of absolute URLs for internal redirects.
3. Display an interstitial warning page before external redirects.


---

### 46. Open Redirect — param 'referrer'

**Severity:** 🟡 MEDIUM  
**Target:** `https://etoro.com`  
**Module:** open_redirect  
**Confidence:** confirmed  
**CVSS Score:** 6.1  
**CWE:** CWE-601  

**Description:**  
Open redirect via 'referrer' parameter. Redirects to attacker-controlled domain: https://www.etoro.com/?referrer=https%3A%2F%2Fevil.com

**Request:**
```http
GET https://etoro.com?referrer=https%3A%2F%2Fevil.com HTTP/1.1
```
**Evidence:**
```
Location: https://www.etoro.com/?referrer=https%3A%2F%2Fevil.com
```

**Steps to Reproduce:**  
Navigate to: https://etoro.com?referrer=https%3A%2F%2Fevil.com


**Remediation:**  
1. Validate redirect URLs against an allowlist of trusted domains.
2. Use relative paths instead of absolute URLs for internal redirects.
3. Display an interstitial warning page before external redirects.


---

### 47. Open Redirect — param 'redirect_uri'

**Severity:** 🟡 MEDIUM  
**Target:** `https://etoro.com`  
**Module:** open_redirect  
**Confidence:** confirmed  
**CVSS Score:** 6.1  
**CWE:** CWE-601  

**Description:**  
Open redirect via 'redirect_uri' parameter. Redirects to attacker-controlled domain: https://www.etoro.com/?redirect_uri=https%3A%2F%2Fevil.com

**Request:**
```http
GET https://etoro.com?redirect_uri=https%3A%2F%2Fevil.com HTTP/1.1
```
**Evidence:**
```
Location: https://www.etoro.com/?redirect_uri=https%3A%2F%2Fevil.com
```

**Steps to Reproduce:**  
Navigate to: https://etoro.com?redirect_uri=https%3A%2F%2Fevil.com


**Remediation:**  
1. Validate redirect URLs against an allowlist of trusted domains.
2. Use relative paths instead of absolute URLs for internal redirects.
3. Display an interstitial warning page before external redirects.


---

### 48. Open Redirect — param 'view'

**Severity:** 🟡 MEDIUM  
**Target:** `https://etoro.com`  
**Module:** open_redirect  
**Confidence:** confirmed  
**CVSS Score:** 6.1  
**CWE:** CWE-601  

**Description:**  
Open redirect via 'view' parameter. Redirects to attacker-controlled domain: https://www.etoro.com/?view=https%3A%2F%2Fevil.com

**Request:**
```http
GET https://etoro.com?view=https%3A%2F%2Fevil.com HTTP/1.1
```
**Evidence:**
```
Location: https://www.etoro.com/?view=https%3A%2F%2Fevil.com
```

**Steps to Reproduce:**  
Navigate to: https://etoro.com?view=https%3A%2F%2Fevil.com


**Remediation:**  
1. Validate redirect URLs against an allowlist of trusted domains.
2. Use relative paths instead of absolute URLs for internal redirects.
3. Display an interstitial warning page before external redirects.


---

### 49. Open Redirect — param 'url'

**Severity:** 🟡 MEDIUM  
**Target:** `https://etoro.com`  
**Module:** open_redirect  
**Confidence:** confirmed  
**CVSS Score:** 6.1  
**CWE:** CWE-601  

**Description:**  
Open redirect via 'url' parameter. Redirects to attacker-controlled domain: https://www.etoro.com/?url=https%3A%2F%2Fevil.com

**Request:**
```http
GET https://etoro.com?url=https%3A%2F%2Fevil.com HTTP/1.1
```
**Evidence:**
```
Location: https://www.etoro.com/?url=https%3A%2F%2Fevil.com
```

**Steps to Reproduce:**  
Navigate to: https://etoro.com?url=https%3A%2F%2Fevil.com


**Remediation:**  
1. Validate redirect URLs against an allowlist of trusted domains.
2. Use relative paths instead of absolute URLs for internal redirects.
3. Display an interstitial warning page before external redirects.


---

### 50. Open Redirect — param 'goto'

**Severity:** 🟡 MEDIUM  
**Target:** `https://etoro.com`  
**Module:** open_redirect  
**Confidence:** confirmed  
**CVSS Score:** 6.1  
**CWE:** CWE-601  

**Description:**  
Open redirect via 'goto' parameter. Redirects to attacker-controlled domain: https://www.etoro.com/?goto=https%3A%2F%2Fevil.com

**Request:**
```http
GET https://etoro.com?goto=https%3A%2F%2Fevil.com HTTP/1.1
```
**Evidence:**
```
Location: https://www.etoro.com/?goto=https%3A%2F%2Fevil.com
```

**Steps to Reproduce:**  
Navigate to: https://etoro.com?goto=https%3A%2F%2Fevil.com


**Remediation:**  
1. Validate redirect URLs against an allowlist of trusted domains.
2. Use relative paths instead of absolute URLs for internal redirects.
3. Display an interstitial warning page before external redirects.


---

### 51. Open Redirect — param 'forward'

**Severity:** 🟡 MEDIUM  
**Target:** `https://etoro.com`  
**Module:** open_redirect  
**Confidence:** confirmed  
**CVSS Score:** 6.1  
**CWE:** CWE-601  

**Description:**  
Open redirect via 'forward' parameter. Redirects to attacker-controlled domain: https://www.etoro.com/?forward=https%3A%2F%2Fevil.com

**Request:**
```http
GET https://etoro.com?forward=https%3A%2F%2Fevil.com HTTP/1.1
```
**Evidence:**
```
Location: https://www.etoro.com/?forward=https%3A%2F%2Fevil.com
```

**Steps to Reproduce:**  
Navigate to: https://etoro.com?forward=https%3A%2F%2Fevil.com


**Remediation:**  
1. Validate redirect URLs against an allowlist of trusted domains.
2. Use relative paths instead of absolute URLs for internal redirects.
3. Display an interstitial warning page before external redirects.


---

### 52. Open Redirect — param 'callback'

**Severity:** 🟡 MEDIUM  
**Target:** `https://etoro.com`  
**Module:** open_redirect  
**Confidence:** confirmed  
**CVSS Score:** 6.1  
**CWE:** CWE-601  

**Description:**  
Open redirect via 'callback' parameter. Redirects to attacker-controlled domain: https://www.etoro.com/?callback=https%3A%2F%2Fevil.com

**Request:**
```http
GET https://etoro.com?callback=https%3A%2F%2Fevil.com HTTP/1.1
```
**Evidence:**
```
Location: https://www.etoro.com/?callback=https%3A%2F%2Fevil.com
```

**Steps to Reproduce:**  
Navigate to: https://etoro.com?callback=https%3A%2F%2Fevil.com


**Remediation:**  
1. Validate redirect URLs against an allowlist of trusted domains.
2. Use relative paths instead of absolute URLs for internal redirects.
3. Display an interstitial warning page before external redirects.


---

### 53. Open Redirect — param 'redirect'

**Severity:** 🟡 MEDIUM  
**Target:** `https://etoro.com`  
**Module:** open_redirect  
**Confidence:** confirmed  
**CVSS Score:** 6.1  
**CWE:** CWE-601  

**Description:**  
Open redirect via 'redirect' parameter. Redirects to attacker-controlled domain: https://www.etoro.com/?redirect=https%3A%2F%2Fevil.com

**Request:**
```http
GET https://etoro.com?redirect=https%3A%2F%2Fevil.com HTTP/1.1
```
**Evidence:**
```
Location: https://www.etoro.com/?redirect=https%3A%2F%2Fevil.com
```

**Steps to Reproduce:**  
Navigate to: https://etoro.com?redirect=https%3A%2F%2Fevil.com


**Remediation:**  
1. Validate redirect URLs against an allowlist of trusted domains.
2. Use relative paths instead of absolute URLs for internal redirects.
3. Display an interstitial warning page before external redirects.


---

### 54. Open Redirect — param 'target'

**Severity:** 🟡 MEDIUM  
**Target:** `https://etoro.com`  
**Module:** open_redirect  
**Confidence:** confirmed  
**CVSS Score:** 6.1  
**CWE:** CWE-601  

**Description:**  
Open redirect via 'target' parameter. Redirects to attacker-controlled domain: https://www.etoro.com/?target=https%3A%2F%2Fevil.com

**Request:**
```http
GET https://etoro.com?target=https%3A%2F%2Fevil.com HTTP/1.1
```
**Evidence:**
```
Location: https://www.etoro.com/?target=https%3A%2F%2Fevil.com
```

**Steps to Reproduce:**  
Navigate to: https://etoro.com?target=https%3A%2F%2Fevil.com


**Remediation:**  
1. Validate redirect URLs against an allowlist of trusted domains.
2. Use relative paths instead of absolute URLs for internal redirects.
3. Display an interstitial warning page before external redirects.


---

### 55. Open Redirect — param 'continue'

**Severity:** 🟡 MEDIUM  
**Target:** `https://etoro.com`  
**Module:** open_redirect  
**Confidence:** confirmed  
**CVSS Score:** 6.1  
**CWE:** CWE-601  

**Description:**  
Open redirect via 'continue' parameter. Redirects to attacker-controlled domain: https://www.etoro.com/?continue=https%3A%2F%2Fevil.com

**Request:**
```http
GET https://etoro.com?continue=https%3A%2F%2Fevil.com HTTP/1.1
```
**Evidence:**
```
Location: https://www.etoro.com/?continue=https%3A%2F%2Fevil.com
```

**Steps to Reproduce:**  
Navigate to: https://etoro.com?continue=https%3A%2F%2Fevil.com


**Remediation:**  
1. Validate redirect URLs against an allowlist of trusted domains.
2. Use relative paths instead of absolute URLs for internal redirects.
3. Display an interstitial warning page before external redirects.


---

### 56. Open Redirect — param 'success_url'

**Severity:** 🟡 MEDIUM  
**Target:** `https://etoro.com`  
**Module:** open_redirect  
**Confidence:** confirmed  
**CVSS Score:** 6.1  
**CWE:** CWE-601  

**Description:**  
Open redirect via 'success_url' parameter. Redirects to attacker-controlled domain: https://www.etoro.com/?success_url=https%3A%2F%2Fevil.com

**Request:**
```http
GET https://etoro.com?success_url=https%3A%2F%2Fevil.com HTTP/1.1
```
**Evidence:**
```
Location: https://www.etoro.com/?success_url=https%3A%2F%2Fevil.com
```

**Steps to Reproduce:**  
Navigate to: https://etoro.com?success_url=https%3A%2F%2Fevil.com


**Remediation:**  
1. Validate redirect URLs against an allowlist of trusted domains.
2. Use relative paths instead of absolute URLs for internal redirects.
3. Display an interstitial warning page before external redirects.


---

### 57. Open Redirect — param 'path'

**Severity:** 🟡 MEDIUM  
**Target:** `https://etoro.com`  
**Module:** open_redirect  
**Confidence:** confirmed  
**CVSS Score:** 6.1  
**CWE:** CWE-601  

**Description:**  
Open redirect via 'path' parameter. Redirects to attacker-controlled domain: https://www.etoro.com/?path=https%3A%2F%2Fevil.com

**Request:**
```http
GET https://etoro.com?path=https%3A%2F%2Fevil.com HTTP/1.1
```
**Evidence:**
```
Location: https://www.etoro.com/?path=https%3A%2F%2Fevil.com
```

**Steps to Reproduce:**  
Navigate to: https://etoro.com?path=https%3A%2F%2Fevil.com


**Remediation:**  
1. Validate redirect URLs against an allowlist of trusted domains.
2. Use relative paths instead of absolute URLs for internal redirects.
3. Display an interstitial warning page before external redirects.


---

### 58. Open Redirect — param 'cancel_url'

**Severity:** 🟡 MEDIUM  
**Target:** `https://etoro.com`  
**Module:** open_redirect  
**Confidence:** confirmed  
**CVSS Score:** 6.1  
**CWE:** CWE-601  

**Description:**  
Open redirect via 'cancel_url' parameter. Redirects to attacker-controlled domain: https://www.etoro.com/?cancel_url=https%3A%2F%2Fevil.com

**Request:**
```http
GET https://etoro.com?cancel_url=https%3A%2F%2Fevil.com HTTP/1.1
```
**Evidence:**
```
Location: https://www.etoro.com/?cancel_url=https%3A%2F%2Fevil.com
```

**Steps to Reproduce:**  
Navigate to: https://etoro.com?cancel_url=https%3A%2F%2Fevil.com


**Remediation:**  
1. Validate redirect URLs against an allowlist of trusted domains.
2. Use relative paths instead of absolute URLs for internal redirects.
3. Display an interstitial warning page before external redirects.


---

### 59. Open Redirect — param 'r'

**Severity:** 🟡 MEDIUM  
**Target:** `https://etoro.com`  
**Module:** open_redirect  
**Confidence:** confirmed  
**CVSS Score:** 6.1  
**CWE:** CWE-601  

**Description:**  
Open redirect via 'r' parameter. Redirects to attacker-controlled domain: https://www.etoro.com/?r=https%3A%2F%2Fevil.com

**Request:**
```http
GET https://etoro.com?r=https%3A%2F%2Fevil.com HTTP/1.1
```
**Evidence:**
```
Location: https://www.etoro.com/?r=https%3A%2F%2Fevil.com
```

**Steps to Reproduce:**  
Navigate to: https://etoro.com?r=https%3A%2F%2Fevil.com


**Remediation:**  
1. Validate redirect URLs against an allowlist of trusted domains.
2. Use relative paths instead of absolute URLs for internal redirects.
3. Display an interstitial warning page before external redirects.


---

### 60. Open Redirect — param 'return_to'

**Severity:** 🟡 MEDIUM  
**Target:** `https://etoro.com`  
**Module:** open_redirect  
**Confidence:** confirmed  
**CVSS Score:** 6.1  
**CWE:** CWE-601  

**Description:**  
Open redirect via 'return_to' parameter. Redirects to attacker-controlled domain: https://www.etoro.com/?return_to=https%3A%2F%2Fevil.com

**Request:**
```http
GET https://etoro.com?return_to=https%3A%2F%2Fevil.com HTTP/1.1
```
**Evidence:**
```
Location: https://www.etoro.com/?return_to=https%3A%2F%2Fevil.com
```

**Steps to Reproduce:**  
Navigate to: https://etoro.com?return_to=https%3A%2F%2Fevil.com


**Remediation:**  
1. Validate redirect URLs against an allowlist of trusted domains.
2. Use relative paths instead of absolute URLs for internal redirects.
3. Display an interstitial warning page before external redirects.


---

### 61. Open Redirect — param 'redirect_url'

**Severity:** 🟡 MEDIUM  
**Target:** `https://etoro.com`  
**Module:** open_redirect  
**Confidence:** confirmed  
**CVSS Score:** 6.1  
**CWE:** CWE-601  

**Description:**  
Open redirect via 'redirect_url' parameter. Redirects to attacker-controlled domain: https://www.etoro.com/?redirect_url=https%3A%2F%2Fevil.com

**Request:**
```http
GET https://etoro.com?redirect_url=https%3A%2F%2Fevil.com HTTP/1.1
```
**Evidence:**
```
Location: https://www.etoro.com/?redirect_url=https%3A%2F%2Fevil.com
```

**Steps to Reproduce:**  
Navigate to: https://etoro.com?redirect_url=https%3A%2F%2Fevil.com


**Remediation:**  
1. Validate redirect URLs against an allowlist of trusted domains.
2. Use relative paths instead of absolute URLs for internal redirects.
3. Display an interstitial warning page before external redirects.


---

### 62. Open Redirect — param 'destination'

**Severity:** 🟡 MEDIUM  
**Target:** `https://etoro.com`  
**Module:** open_redirect  
**Confidence:** confirmed  
**CVSS Score:** 6.1  
**CWE:** CWE-601  

**Description:**  
Open redirect via 'destination' parameter. Redirects to attacker-controlled domain: https://www.etoro.com/?destination=https%3A%2F%2Fevil.com

**Request:**
```http
GET https://etoro.com?destination=https%3A%2F%2Fevil.com HTTP/1.1
```
**Evidence:**
```
Location: https://www.etoro.com/?destination=https%3A%2F%2Fevil.com
```

**Steps to Reproduce:**  
Navigate to: https://etoro.com?destination=https%3A%2F%2Fevil.com


**Remediation:**  
1. Validate redirect URLs against an allowlist of trusted domains.
2. Use relative paths instead of absolute URLs for internal redirects.
3. Display an interstitial warning page before external redirects.


---

### 63. Missing X-Content-Type-Options header

**Severity:** 🔵 LOW  
**Target:** `https://example.com`  
**Module:** headers  
**Confidence:** confirmed  
**CWE:** CWE-693  

**Description:**  
Prevents MIME-type sniffing

**Request:**
```http
GET https://example.com HTTP/1.1
```

**Remediation:**  
Add: X-Content-Type-Options: nosniff


---

### 64. Missing Referrer-Policy header

**Severity:** 🔵 LOW  
**Target:** `https://example.com`  
**Module:** headers  
**Confidence:** confirmed  
**CWE:** CWE-200  

**Description:**  
Controls referrer information sent with requests

**Request:**
```http
GET https://example.com HTTP/1.1
```

**Remediation:**  
Add: Referrer-Policy: strict-origin-when-cross-origin


---

### 65. Missing Referrer-Policy header

**Severity:** 🔵 LOW  
**Target:** `https://etoro.com`  
**Module:** headers  
**Confidence:** confirmed  
**CWE:** CWE-200  

**Description:**  
Controls referrer information sent with requests

**Request:**
```http
GET https://etoro.com HTTP/1.1
```

**Remediation:**  
Add: Referrer-Policy: strict-origin-when-cross-origin


---

### 66. Information disclosure via Server

**Severity:** ⚪ INFO  
**Target:** `https://example.com`  
**Module:** headers  
**Confidence:** confirmed  

**Description:**  
Reveals server version (information leakage): cloudflare

**Evidence:**
```
Server: cloudflare
```

---

### 67. Information disclosure via Server

**Severity:** ⚪ INFO  
**Target:** `https://etoro.com`  
**Module:** headers  
**Confidence:** confirmed  

**Description:**  
Reveals server version (information leakage): cloudflare

**Evidence:**
```
Server: cloudflare
```

---
