# Cryptographic Accountability Protocol for Service-Oriented Architecture Systems
Provides client/server architecture for four proposed CAPs

## 如何開始
1. 使用 [GitHub Desktop](https://desktop.github.com) Clone 本專案
2. 開啟 [NetBeans IDE](https://netbeans.org) 上方選單選擇 `File` > `Open Project` > `本專案路徑`
3. 上方選單選擇 `Run` > `Run Project` 啟動伺服器 (快捷鍵為 F6)
4. 等待 console 出現 `Ready to go!` 字樣
5. 開啟 `client.Experiments.java`，上方選單選擇 `Run` > `Run File` 模擬使用者行為 (快捷鍵為 shift+f6)
6. 待 `client.Experiments.java` 結束之後，記得也要關閉伺服器

**請使用 JDK 8 以上版本**

## 介紹

包含五種 CAP 的實作：

* Non-CAP
* Two-Step-SN
* Two-Step-CH
* Four-Step-C&L
* Four-Step-DH

系統主要有三大部分：

* 服務提供者（service provider）
* 使用者（client）
* 中間傳遞的訊息（message）

### 服務提供者（service provider）

簡單來說就是伺服器，啟動的時候會開啟五個 `SocketServer` 監聽不同的 port 並各自對應到不同的 CAP。

每個請求抵達之後，會產生一個 `Thread` 並配合不同 CAP 自己的 handler 去執行請求。你可以在 `service.handler` 找到五個 CAP 的 handler，並且透過裡頭的 `void handle(DataOutputStream out, DataInputStream in)` 觀察其行為。

### 使用者（client）

使用者的實作都在 `client` 中，其中的 `Experiments.java` 統整了各 CAP 使用者的呼叫，執行他就可以直接比較五者的差異。

使用者主要透過 `void run(final List<Operation> operations, final int runTimes)` 執行，會輪流呼叫所有動作：

```
for (int i = 0; i < runTimes; i++) {
  execute(operations.get(i % operations.size()));
}
```

`execute(Operation op)` 會先去與伺服器建立連接，然後再執行 `handle(Operation op, Socket socket, DataOutputStream out, DataInputStream in)`。你可以去觀察每個使用者裡面的此方法，並與對應到的 handler 搭配著看，就可以得知每個 CAP 的運作模式。

### 中間傳遞的訊息（message）

以 [SOAP](https://en.wikipedia.org/wiki/SOAP) 格式為主，使用 `javax.xml.soap.MessageFactory` 產生，另外還附有電子簽章，全部實作可以在 `message` 找到。

`Non CAP`, `Two-Step-SN`, `Two-Step-CH` 提供：

* Request
* Acknowledgement

`Four-Step-C&L`, `Four-Step-DH` 提供：

* Request
* Response
* ReplyResponse
* Acknowledgement

## 如何新增自己的 CAP

1. 在 `handler` 中適當位置新增 `xxxxxHandler.java`
  1. 繼承 `ConnectionHandler`
  2. 實作 `void handle(DataOutputStream out, DataInputStream in)`
2. 在 `client` 中新增 `xxxxxClient.java`
  1. 繼承 `Client`
  2. 實作 `handle(Operation op, Socket socket, DataOutputStream out, DataInputStream in)`
3. 在 `message` 中適當位置新增你的 package
  1. 在你的 package 底下新增需要用到的訊息，比如說 `Request.java` 跟 `Acknowledgement.java`
  2. 每個都必須繼承 `SOAPMessage`
4. 在 `service.SocketServer.java` 的主程式裡面，新增你的 `SocketServer`
5. 看是想要在 `xxxxxClient.java` 寫一個主程式還是寫在 `Experiments.java` 中，新增操作 `xxxxxClient` 的程式碼
6. 執行
  1. 執行 `service.SocketServer.java`
  2. 等待畫面中出現 `Ready to go!` 字樣
  3. 執行操作 `xxxxxClient` 的程式碼

**P.S. 有不會的部分就直接參考現有的是怎麼做**

## License

   Copyright (c) 2016 Cloud Computing Laboratory

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
