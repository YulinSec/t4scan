# 🔥 T4scan
A burp plugin for text4shell passive scan

## 免责声明
该工具仅用于安全自查检测

由于传播、利用此工具所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。

本人拥有对此工具的修改和解释权。未经网络安全部门及相关部门允许，不得善自使用本工具进行任何攻击活动，不得以任何方式将其用于商业目的。

## 📦How to install
### ⏬Download
You can download complied jar from release or build from source.
### 🔨Build from source
First clone the project
```
git clone https://github.com/YulinSec/t4scan
```
Then open it by IDEA, run task fatJar in build.gradle
![images](images/fatjar.png)
You can find compiled jar in build/libs/t4scan-all-1.0-SNAPSHOT.jar
![images](images/output.png)
### 🚀Install to burp
Install this plugin as a java plugin in extender panel.

## 🔮Images
After t4scan installed, it will automatically get http request sent by burp, and inject payloads to find text4shell, including echo and dns.
You can find urls scanned in stdout of t4scan. 
![images](images/stdout.png)
When it found a text4shell, it  will alert an issue.
![images](images/issue.png)
For more details, please go and look at source code.

## Thanks
- https://github.com/pmiaowu/BurpShiroPassiveScan
- https://github.com/Maskhe/FastjsonScan