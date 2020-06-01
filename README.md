### HelloCotrun v0.0.1
---

### 目标
- 验证TURN基础流程
- 掌握TURN编码实现


### TODOs
- [ ] 发送 Allocation 请求
- [ ] 接收 Allocation 响应
- [ ] 更新 Allocation
- [ ] 发送 CreatePermission 请求
- [ ] 接收 CreatePermission 响应
- [ ] Long-Term Credential Mechanism实验
- [ ] 通过中继发送数据
- [ ] 通过中继接收数据
- [ ] 通过中继完成 echo 实验
- [ ] 通过中继完成RTP数据单向传输
- [ ] 通过中继完成RTP数据双向传输




### Message

#### STUN header 
```
       0                   1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |0 0|     STUN Message Type     |         Message Length        |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                         Magic Cookie                          |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                                                               |
      |                     Transaction ID (96 bits)                  |
      |                                                               |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

                  Figure 2: Format of STUN Message Header
```

#### STUN Message Type
```
                        0                 1
                        2  3  4 5 6 7 8 9 0 1 2 3 4 5

                       +--+--+-+-+-+-+-+-+-+-+-+-+-+-+
                       |M |M |M|M|M|C|M|M|M|C|M|M|M|M|
                       |11|10|9|8|7|1|6|5|4|0|3|2|1|0|
                       +--+--+-+-+-+-+-+-+-+-+-+-+-+-+

                Figure 3: Format of STUN Message Type Field
```
- M11 through M0 represent a 12-bit encoding of the method.
  - Binding method = 0b000000000001
- C1 and C0 represent a 2-bit encoding of the class.
  - A class of 0b00 is a request
  - a class of 0b01 is an indication
  - a class of 0b10 is a success response
  - a class of 0b11 is an error response


#### magic cookie
The magic cookie field MUST contain the fixed value 0x2112A442 in network byte order.

#### transaction ID
The transaction ID is a 96-bit identifier, used to uniquely identify STUN transactions.
For request/response transactions, the transaction ID is chosen by the STUN client for 
the request and echoed by the server in the response.  For indications, it is chosen by
the agent sending the indication.


#### RFC 5766.13. New STUN Methods
   This section lists the codepoints for the new STUN methods defined in
   this specification.  See elsewhere in this document for the semantics
   of these new methods.
```
   0x003  :  Allocate          (only request/response semantics defined)
   0x004  :  Refresh           (only request/response semantics defined)
   0x006  :  Send              (only indication semantics defined)
   0x007  :  Data              (only indication semantics defined)
   0x008  :  CreatePermission  (only request/response semantics defined
   0x009  :  ChannelBind       (only request/response semantics defined)
```


#### RFC 5766.14. New STUN Attributes

   This STUN extension defines the following new attributes:
```
     0x000C: CHANNEL-NUMBER
     0x000D: LIFETIME
     0x0010: Reserved (was BANDWIDTH)
     0x0012: XOR-PEER-ADDRESS
     0x0013: DATA
     0x0016: XOR-RELAYED-ADDRESS
     0x0018: EVEN-PORT
     0x0019: REQUESTED-TRANSPORT
     0x001A: DONT-FRAGMENT
     0x0021: Reserved (was TIMER-VAL)
     0x0022: RESERVATION-TOKEN
```
   Some of these attributes have lengths that are not multiples of 4.
   By the rules of STUN, any attribute whose length is not a multiple of
   4 bytes MUST be immediately followed by 1 to 3 padding bytes to
   ensure the next attribute (if any) would start on a 4-byte boundary
   (see [RFC5389]).

#### Allocation
- REQUESTED-TRANSPORT: In this specification, the REQUESTED-TRANSPORT type is always UDP.
- LIFETIME: initialize the time-to-expiry field of the allocation to some value other than the default lifetime.
- DONT-FRAGMENT: 
- EVEN-PORT: 
- RESERVATION-TOKEN:
- long-term credential mechanism



