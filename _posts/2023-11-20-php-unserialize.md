---
layout: post
title: PHP-unserialize
date: 2023-11-20 10:54 +0800
categories:
- Web_security
tags:
- PHP
- 反序列化
---
## 0x00 序列化/反序列化：
把对象转换为字节序列的过程称为对象的**序列化**

将字节序列恢复为对象的过程称为对象的**反序列化**

对象的序列化主要用途：

- [x] *将对象的字节序列化保存在硬盘上*
- [x] *在网络上传输对象的字节序列（Session的使用）*


```php
PHP魔术方法总览:
__construct() 当创建对象时触发,一般用于初始化对象,对变量赋初值
__sleep() 使用serialize()时自动触发 
__wakeup() 使用unserialize()时自动触发  (注:当php版本低时可以绕过)
__destruct() 当一个对象被销毁时触发
__toString() 当一个类被当成字符串使用时触发
__invoke() 当尝试以调用函数的方式调用一个对象时触发
__call() 在对象上下文中调用不可访问的方法时触发 
__callStatic() 在静态上下文中调用不可访问的方法时触发 
__get() 用于从不可访问的属性读取数据
__set() 用于将数据写入不可访问的属性
__isset() 在不可访问的属性上调用isset()或empty()触发
__unset() 在不可访问的属性上使用unset()时触发
```

## 0x01 进阶难度之POP链
待补充~

## 0x02 终极难度之字符逃逸

### 前置知识：
- ​     在PHP反序列化过程中，底层代码以 `;`作为字段的分割，以 `}`作为结尾（字符串除外），并且是根据长度判断内容

- ​     字符逃逸的标志： 

  1. 序列化的对象可以控制  
  2. 过滤函数在序列化之后，反序列化之前 

### 从一个简单的例子开始吧：

```php
<?php

	$username = $_GET['username'];
	$sign = "hi guys";
	$user = array($username, $sign);

	$seri = bad_str(serialize($user));

	echo $seri;

	$user=unserialize($seri);
    echo "<br>";
	echo $user[0];
	echo "<br>";
	echo $user[1];

	//过滤方法：
	function bad_str($string){
		return preg_replace('/\'/', 'no', $string);
	}
?>
```

在这段代码中，先序列化$user 对象再利用bad_str()方法进行过滤，最后反序列化输出结果。bad_str()方法将匹配到的 `/\'/` 全部转换为no，相当于多一个字符（这是实现字符逃逸的一个标志）

接下来看看输入`username = admin` 的结果：

![image-20231116144454178](/images/PHP-反序列化.assets/image-20231116144454178.png){: w="800" h="400" }

如果此时，想要让它显示 `hi girls`呢？这就用的上字符串逃逸了，其核心思路是 **利用bad_str()方法构造显示 `hi girls`的字段**，先看看要构造的部分：

![image-20231116155727268](/images/PHP-反序列化.assets/image-20231116155727268.png){: w="800" h="400" }

观察后得到我们需要构造的一部分内容： `";i:1;s:8:"hi girls";}` （长度22）

看看输入 `username = ";i:1;s:8:"hi girls";}`的效果：

![image-20231116161701372](/images/PHP-反序列化.assets/image-20231116161701372.png){: w="800" h="400" }

可以看到，输入的 ` username `值被当作了字符串，利用bad_str()方法构造一部分内容x，使它能够拼接在这个<u>位置1</u>，把后面这部分内容 `";i:1;s:7:"hi guys";}` 溢出

![image-20231116162730151](/images/PHP-反序列化.assets/image-20231116162730151.png){: w="800" h="400" }

点子来了，bad_str()方法正好可以在反序列化之前多一个字符，那么我输入22个` ' `  填充进 `username  `就可以了，即`username=''''''''''''''''''''''";i:1;s:8:"hi girls";}`（长度为44），这次再看看结果：

![image-20231116163815050](/images/PHP-反序列化.assets/image-20231116163815050.png){: w="800" h="400" }

可以看到输出变成了 `hi girls`,完成了我们的目标~


### 如何判断添加/减少多少字符？

**字符数=目标字符串数/字符差数** (注：不满整数时需要自行添加字符凑整)

> 参考文章：1.[从一道ctf看php反序列化漏洞的应用场景](https://www.cnblogs.com/litlife/p/11690918.html)

